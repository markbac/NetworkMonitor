#!/usr/bin/env python3
"""
advanced_network_monitor.py -- Windows Network Observability Monitor

Continuously probes internet connectivity and local network health,
displaying live metrics in a curses TUI and persisting all samples and
events to SQLite.

Architecture
------------
Three threads run concurrently:

  monitor_loop  -- polls on poll_interval_seconds. Each iteration runs all
                   probes, analyses results, persists to SQLite, and fires
                   events. Probe duration is measured; a warning event fires
                   if it exceeds the configured interval.

  tui (main)    -- curses UI, redraws at ~10 fps. Skipped in --headless mode.

  retention     -- runs once per hour, deleting rows older than
                   general.retention_days from all tables.

Probes per cycle
----------------
  internet ping     round-robin across internet_ping_hosts
  gateway ping      cached gateway IP; refreshed every 60 s or on IP change
  DNS hostname      round-robin across dns_hosts (system resolver)
  DNS server direct UDP probe to the DNS server IP on port 53
  HTTP GET          round-robin across http_targets
  Wi-Fi             netsh wlan show interfaces
  NIC rates         psutil.net_io_counters() per-second deltas
  TCP states        psutil.net_connections() counts by state
  IP / DNS server   ipconfig /all, change-detected
  CPU / RAM         psutil.cpu_percent() / psutil.virtual_memory()

On fault (packet_loss / high_latency / severe_latency)
-------------------------------------------------------
  All internet_ping_hosts probed concurrently, results logged.
  tracert run and saved to data/incidents/ if traceroute_on_fault is true.

Usage
-----
  python advanced_network_monitor.py            # TUI mode
  python advanced_network_monitor.py --headless # background / server mode

Windows-only. Requires: requests psutil pyyaml windows-curses
"""

from __future__ import annotations

import argparse
import curses
import logging
import platform
import re
import signal
import socket
import sqlite3
import statistics
import struct
import subprocess
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from logging.handlers import RotatingFileHandler
import logging.handlers
from pathlib import Path
from typing import Optional

import psutil
import requests
import yaml


CONFIG_FILE = "config/default.yaml"
SCHEMA_FILE = "config/schema.sql"
GATEWAY_CACHE_TTL  = 60   # seconds between ipconfig gateway re-reads
NETSH_IFACE_TTL    = 10   # seconds between netsh wlan show interfaces re-reads
IPCONFIG_ALL_TTL   = 10   # seconds between ipconfig /all re-reads

# Separate logger for debug command tracing. Only activated with --debug.
# Using a named logger keeps it independent of the root logger so it can
# be enabled/disabled without affecting normal event logging.
debug_log = logging.getLogger("netmon.debug")
debug_log.setLevel(logging.DEBUG)
debug_log.propagate = False  # don't send to root handler


class CommandLogger:
    """Wraps subprocess calls and logs every command, response, and timing.

    When debug mode is active, each call to run() or check_output() logs:
      - The full command as a list
      - Elapsed time in milliseconds
      - Return code
      - First 500 chars of stdout and stderr (to avoid flooding the log)

    When debug mode is inactive, the wrappers are transparent pass-throughs
    with no overhead beyond the function call.
    """

    def __init__(self, enabled: bool):
        self.enabled = enabled

    def run(self, cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
        """subprocess.run() with debug logging."""
        start = time.perf_counter()
        try:
            result = subprocess.run(cmd, **kwargs)
            elapsed = (time.perf_counter() - start) * 1000
            if self.enabled:
                debug_log.debug(
                    "RUN cmd=%s elapsed=%.1fms rc=%d stdout=%r stderr=%r",
                    cmd,
                    elapsed,
                    result.returncode,
                    (result.stdout or b"")[:500],
                    (result.stderr or b"")[:500],
                )
            return result
        except Exception as exc:
            elapsed = (time.perf_counter() - start) * 1000
            if self.enabled:
                debug_log.debug(
                    "RUN EXCEPTION cmd=%s elapsed=%.1fms exc=%r",
                    cmd, elapsed, exc,
                )
            raise

    def check_output(self, cmd: list[str], **kwargs) -> str:
        """subprocess.check_output() with debug logging."""
        start = time.perf_counter()
        try:
            result = subprocess.check_output(cmd, **kwargs)
            elapsed = (time.perf_counter() - start) * 1000
            if self.enabled:
                preview = result[:500] if isinstance(result, bytes) else result[:500]
                debug_log.debug(
                    "CHECK_OUTPUT cmd=%s elapsed=%.1fms output=%r",
                    cmd, elapsed, preview,
                )
            return result
        except Exception as exc:
            elapsed = (time.perf_counter() - start) * 1000
            if self.enabled:
                debug_log.debug(
                    "CHECK_OUTPUT EXCEPTION cmd=%s elapsed=%.1fms exc=%r",
                    cmd, elapsed, exc,
                )
            raise


# Module-level command logger. Replaced with a debug-enabled instance in
# main() when --debug is passed. All classes use this singleton so the flag
# only needs to be set once.
cmd_logger = CommandLogger(enabled=False)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class Sample:
    """One complete measurement cycle.

    All timing fields are milliseconds. None means the probe failed.
    probe_duration_ms is the wall-clock time the probe block took;
    if it exceeds poll_interval_seconds a slow_probe warning is fired.
    cpu_pct and ram_pct are system-wide utilisation percentages (0-100).
    """
    timestamp: str
    probed_host: str
    internet_ping: Optional[float]
    gateway_ping: Optional[float]
    dns_ms: Optional[float]
    dns_server_ms: Optional[float]
    http_ms: Optional[float]
    packet_loss_rate: float
    ip_address: Optional[str]
    dns_server: Optional[str]
    cpu_pct: Optional[float]
    ram_pct: Optional[float]
    probe_duration_ms: float
    notes: str


@dataclass
class WifiSample:
    timestamp: str
    ssid: Optional[str]
    bssid: Optional[str]
    signal_pct: Optional[int]
    channel: Optional[int]
    band: Optional[str]
    rx_rate_mbps: Optional[float]
    tx_rate_mbps: Optional[float]
    auth: Optional[str]


@dataclass
class NicSample:
    timestamp: str
    interface: str
    bytes_sent_ps: float
    bytes_recv_ps: float
    errin_ps: float
    errout_ps: float
    dropin_ps: float
    dropout_ps: float


@dataclass
class TcpStateSample:
    timestamp: str
    established: int = 0
    time_wait: int = 0
    close_wait: int = 0
    syn_sent: int = 0
    syn_recv: int = 0
    fin_wait1: int = 0
    fin_wait2: int = 0
    closing: int = 0
    last_ack: int = 0
    listen: int = 0
    other: int = 0


@dataclass
class BufferbloatSample:
    """Result of one bufferbloat scan.

    baseline_ms is the rolling average ping at scan time.
    loaded_ms is the mean RTT of pings fired while a download saturates the link.
    delta_ms = loaded_ms - baseline_ms; this is the bufferbloat score.
    rating: good <30 ms / moderate 30-100 / bad 100-300 / severe >300.
    download_mbps is the throughput achieved during the test window.
    """
    timestamp: str
    baseline_ms: Optional[float]
    loaded_ms: Optional[float]
    delta_ms: Optional[float]
    rating: str
    download_mbps: Optional[float]
    ping_host: str
    download_url: str


@dataclass
class SpeedTestSample:
    """Result of one speed test (download + upload).

    Both directions use the same test duration. Throughput is Mbps.
    None in either direction means the transfer failed entirely.
    download_bytes and upload_bytes are the raw byte counts transferred
    during each window, useful for verifying the result makes sense.
    """
    timestamp: str
    download_mbps: Optional[float]
    upload_mbps: Optional[float]
    download_bytes: int
    upload_bytes: int
    duration_seconds: float
    download_url: str
    upload_url: str


# ---------------------------------------------------------------------------
# Rolling statistics
# ---------------------------------------------------------------------------

class RollingStats:
    """Fixed-size window of Optional[float] ping samples.

    None entries represent failed probes and are counted in packet_loss_rate
    but excluded from average and jitter calculations.
    """

    def __init__(self, size: int = 120):
        self.window: deque[Optional[float]] = deque(maxlen=size)

    def add(self, value: Optional[float]):
        self.window.append(value)

    def _good(self) -> list[float]:
        return [v for v in self.window if v is not None]

    def average(self) -> float:
        good = self._good()
        return statistics.mean(good) if good else 0.0

    def jitter(self) -> float:
        """Mean absolute difference between consecutive successful samples."""
        good = self._good()
        if len(good) < 2:
            return 0.0
        return statistics.mean(
            abs(good[i] - good[i - 1]) for i in range(1, len(good))
        )

    def packet_loss_rate(self) -> float:
        """Percentage of window entries that are None (0-100)."""
        if not self.window:
            return 0.0
        failed = sum(1 for v in self.window if v is None)
        return round(failed / len(self.window) * 100, 1)


# ---------------------------------------------------------------------------
# Host cycler
# ---------------------------------------------------------------------------

class HostCycler:
    """Round-robin iterator over a list of hosts.

    next() returns the current host and advances the index.
    all() returns every host -- used for fault-time multi-host probing.
    """

    def __init__(self, hosts: list[str]):
        if not hosts:
            raise ValueError("HostCycler requires at least one host")
        self._hosts = hosts
        self._index = 0

    def next(self) -> str:
        host = self._hosts[self._index]
        self._index = (self._index + 1) % len(self._hosts)
        return host

    def all(self) -> list[str]:
        return list(self._hosts)


# ---------------------------------------------------------------------------
# Gateway cache
# ---------------------------------------------------------------------------

class GatewayCache:
    """Caches the default gateway IP to avoid running ipconfig every cycle.

    The cache is considered stale after GATEWAY_CACHE_TTL seconds, or
    immediately when force_refresh() is called (e.g. on an IP change event).
    ipconfig is expensive (~50 ms) at 1 s poll intervals.
    """

    def __init__(self):
        self._ip: Optional[str] = None
        self._fetched_at: float = 0.0

    def get(self) -> Optional[str]:
        """Return cached gateway IP, refreshing if the TTL has expired."""
        if time.monotonic() - self._fetched_at > GATEWAY_CACHE_TTL:
            self._ip = self._fetch()
            self._fetched_at = time.monotonic()
        return self._ip

    def force_refresh(self):
        """Invalidate the cache; next call to get() will re-run ipconfig."""
        self._fetched_at = 0.0

    @staticmethod
    def _fetch() -> Optional[str]:
        try:
            out = cmd_logger.check_output(
                ["ipconfig"], text=True, encoding="utf-8",
                errors="ignore", timeout=5,
            )
            for line in out.splitlines():
                if "Default Gateway" in line:
                    val = line.split(":")[-1].strip()
                    if val:
                        return val
        except Exception:
            pass
        return None


# ---------------------------------------------------------------------------
# Wi-Fi probe
# ---------------------------------------------------------------------------

class WifiProbe:
    """Reads Wi-Fi metrics from 'netsh wlan show interfaces'.

    Works regardless of whether Wi-Fi is the default route. On a machine
    where Ethernet is the primary route but Wi-Fi is also associated to an
    SSID, this probe still returns signal strength, BSSID, channel, and
    link rates for the Wi-Fi adapter. The only condition for data to be
    returned is that the Wi-Fi adapter is associated to a network -- it
    does not need to be carrying any traffic.

    Set wifi.enabled: true even on wired-primary machines if a Wi-Fi
    adapter is present; you will still get signal history and roaming
    detection without any impact on routing.

    Detects BSSID changes (roaming) and band changes between cycles,
    returning event strings for each. All parsing targets English-locale
    netsh output; non-English locales will silently return None fields.
    """

    _PATTERNS = {
        "ssid":         re.compile(r"^\s+SSID\s*:\s*(.+)$",               re.I),
        "bssid":        re.compile(r"^\s+BSSID\s*:\s*(.+)$",              re.I),
        "signal_pct":   re.compile(r"^\s+Signal\s*:\s*(\d+)%",            re.I),
        "channel":      re.compile(r"^\s+Channel\s*:\s*(\d+)",            re.I),
        "band":         re.compile(r"^\s+Radio type\s*:\s*(.+)$",         re.I),
        "rx_rate_mbps": re.compile(r"^\s+Receive rate.*?:\s*([\d.]+)",    re.I),
        "tx_rate_mbps": re.compile(r"^\s+Transmit rate.*?:\s*([\d.]+)",   re.I),
        "auth":         re.compile(r"^\s+Authentication\s*:\s*(.+)$",     re.I),
    }

    _BAND_MAP = {
        "802.11b": "2.4GHz", "802.11g": "2.4GHz", "802.11n": "2.4GHz",
        "802.11a": "5GHz",   "802.11ac": "5GHz",   "802.11ax": "6GHz",
    }

    def __init__(self, enabled: bool):
        self.enabled = enabled
        self._last_bssid: Optional[str] = None
        self._last_band:  Optional[str] = None
        self._cached_sample: Optional[WifiSample] = None
        self._cache_ts: float = 0.0

    def read(self) -> tuple[Optional[WifiSample], list[str]]:
        """Return cached Wi-Fi sample if within TTL, else re-run netsh.

        netsh wlan show interfaces takes 300--800 ms per call. Running it
        every cycle at a 1 s poll interval consumes most of the probe budget.
        TTL cache means it runs at most every NETSH_IFACE_TTL seconds while
        still detecting roaming and band changes within that window.
        """
        if not self.enabled:
            return None, []

        if time.monotonic() - self._cache_ts < NETSH_IFACE_TTL:
            return self._cached_sample, []

        # TTL expired -- re-run netsh.
        try:
            output = cmd_logger.check_output(
                ["netsh", "wlan", "show", "interfaces"],
                text=True, encoding="utf-8", errors="ignore", timeout=5,
            )
        except Exception:
            return None, []

        parsed: dict = {}
        for line in output.splitlines():
            for key, pat in self._PATTERNS.items():
                if key not in parsed:
                    m = pat.match(line)
                    if m:
                        parsed[key] = m.group(1).strip()

        if "ssid" not in parsed:
            # Adapter is disconnected -- cache the None result so we don't
            # hammer netsh every cycle while Wi-Fi is off.
            self._cached_sample = None
            self._cache_ts = time.monotonic()
            return None, []

        raw_band = parsed.get("band", "")
        band = next(
            (label for prefix, label in self._BAND_MAP.items()
             if raw_band.lower().startswith(prefix)),
            None,
        )

        sample = WifiSample(
            timestamp=datetime.now().isoformat(),
            ssid=parsed.get("ssid"),
            bssid=parsed.get("bssid"),
            signal_pct=int(parsed["signal_pct"]) if "signal_pct" in parsed else None,
            channel=int(parsed["channel"]) if "channel" in parsed else None,
            band=band,
            rx_rate_mbps=float(parsed["rx_rate_mbps"]) if "rx_rate_mbps" in parsed else None,
            tx_rate_mbps=float(parsed["tx_rate_mbps"]) if "tx_rate_mbps" in parsed else None,
            auth=parsed.get("auth"),
        )

        events = []
        if self._last_bssid is not None and sample.bssid != self._last_bssid:
            events.append(
                f"wifi_roam: {self._last_bssid} -> {sample.bssid} "
                f"(SSID: {sample.ssid}, signal: {sample.signal_pct}%)"
            )
        if self._last_band is not None and sample.band != self._last_band:
            events.append(f"wifi_band_change: {self._last_band} -> {sample.band}")

        self._last_bssid = sample.bssid
        self._last_band = sample.band
        self._cached_sample = sample
        self._cache_ts = time.monotonic()
        return sample, events


# ---------------------------------------------------------------------------
# Wi-Fi environment scanner
# ---------------------------------------------------------------------------

@dataclass
class WifiScanEntry:
    """One visible network from a 'netsh wlan show networks mode=bssid' scan."""
    scan_timestamp: str
    ssid: str
    bssid: str
    signal_pct: Optional[int]
    channel: Optional[int]
    band: Optional[str]       # derived from channel number
    authentication: Optional[str]
    cipher: Optional[str]


class WifiScanner:
    """Scans all visible Wi-Fi networks using 'netsh wlan show networks mode=bssid'.

    Runs regardless of whether the Wi-Fi adapter is connected -- netsh returns
    visible networks even when the adapter is not associated to any SSID.

    Band is read directly from the 'Band :' line in netsh output (which
    reports '2.4 GHz', '5 GHz', or '6 GHz' explicitly). Channel-based
    inference is used only as a fallback when the Band line is absent.
    """

    @staticmethod
    def _band_from_channel(ch: Optional[int]) -> Optional[str]:
        """Fallback: infer band from channel number."""
        if ch is None:
            return None
        if 1 <= ch <= 14:
            return "2.4GHz"
        if 36 <= ch <= 177:
            return "5GHz"
        return "6GHz"

    @staticmethod
    def _normalise_band(raw: str) -> str:
        """Convert netsh band string to canonical label."""
        r = raw.strip()
        if "6" in r:
            return "6GHz"
        if "5" in r:
            return "5GHz"
        return "2.4GHz"

    def scan(self) -> list[WifiScanEntry]:
        """Return one WifiScanEntry per visible BSSID, or [] on any failure."""
        try:
            output = cmd_logger.check_output(
                ["netsh", "wlan", "show", "networks", "mode=bssid"],
                text=True, encoding="utf-8", errors="ignore", timeout=15,
            )
        except Exception:
            return []

        ts = datetime.now().isoformat()
        results: list[WifiScanEntry] = []

        current_ssid    = ""
        current_bssid:  Optional[str] = None
        current_auth:   Optional[str] = None
        current_cipher: Optional[str] = None
        bssid_signal:   Optional[int] = None
        bssid_channel:  Optional[int] = None
        bssid_band:     Optional[str] = None

        def _flush():
            if current_bssid:
                band = bssid_band or self._band_from_channel(bssid_channel)
                results.append(WifiScanEntry(
                    scan_timestamp=ts,
                    ssid=current_ssid,
                    bssid=current_bssid,
                    signal_pct=bssid_signal,
                    channel=bssid_channel,
                    band=band,
                    authentication=current_auth,
                    cipher=current_cipher,
                ))

        for line in output.splitlines():
            s = line.strip()

            m = re.match(r"^SSID\s+\d+\s*:\s*(.*)$", s, re.IGNORECASE)
            if m and "BSSID" not in s:
                _flush()
                current_ssid = m.group(1).strip(); current_bssid = None
                bssid_signal = bssid_channel = bssid_band = None
                current_auth = current_cipher = None
                continue

            m = re.match(r"^BSSID\s+\d+\s*:\s*(.+)$", s, re.IGNORECASE)
            if m:
                _flush()
                current_bssid = m.group(1).strip()
                bssid_signal = bssid_channel = bssid_band = None
                continue

            m = re.match(r"^Signal\s*:\s*(\d+)%", s, re.IGNORECASE)
            if m: bssid_signal = int(m.group(1)); continue

            m = re.match(r"^Channel\s*:\s*(\d+)", s, re.IGNORECASE)
            if m: bssid_channel = int(m.group(1)); continue

            # Band line -- use this in preference to channel inference
            m = re.match(r"^Band\s*:\s*(.+)$", s, re.IGNORECASE)
            if m: bssid_band = self._normalise_band(m.group(1)); continue

            m = re.match(r"^Authentication\s*:\s*(.+)$", s, re.IGNORECASE)
            if m: current_auth = m.group(1).strip(); continue

            m = re.match(r"^Cipher\s*:\s*(.+)$", s, re.IGNORECASE)
            if m: current_cipher = m.group(1).strip(); continue

        _flush()
        return results


# ---------------------------------------------------------------------------
# NIC probe
# ---------------------------------------------------------------------------

class NicProbe:
    """Per-second NIC I/O rates from psutil counter deltas.

    When interface is 'auto' (the default), every non-loopback NIC that has
    seen any traffic is recorded each cycle. This means both Ethernet and
    Wi-Fi appear in nic_samples simultaneously when both are active, even if
    Ethernet is the primary route. A wired-primary machine will therefore
    show Wi-Fi throughput and error rates alongside Ethernet without any
    extra configuration.

    Set interface to an exact NIC name (e.g. 'Ethernet', 'Wi-Fi') to record
    only that adapter. The name must match psutil's short name exactly
    (visible in Task Manager > Performance or 'netsh interface show interface').

    First call stores the baseline; subsequent calls return one NicSample
    per monitored interface.
    """

    # Loopback adapter names to skip regardless of traffic.
    _LOOPBACK = {"loopback pseudo-interface 1", "loopback"}

    def __init__(self, interface: str):
        self._interface = interface
        self._last_counters: Optional[dict] = None

    def read(self, elapsed: float) -> list[NicSample]:
        now = psutil.net_io_counters(pernic=True)

        if self._last_counters is None or elapsed <= 0:
            self._last_counters = now
            return []

        interfaces = self._select(now)
        ts = datetime.now().isoformat()
        samples = []

        for iface in interfaces:
            if iface not in self._last_counters:
                continue
            cur, prev = now[iface], self._last_counters[iface]
            samples.append(NicSample(
                timestamp=ts, interface=iface,
                bytes_sent_ps=max(0, (cur.bytes_sent - prev.bytes_sent) / elapsed),
                bytes_recv_ps=max(0, (cur.bytes_recv - prev.bytes_recv) / elapsed),
                errin_ps=max(0,  (cur.errin  - prev.errin)  / elapsed),
                errout_ps=max(0, (cur.errout - prev.errout) / elapsed),
                dropin_ps=max(0, (cur.dropin - prev.dropin) / elapsed),
                dropout_ps=max(0, (cur.dropout - prev.dropout) / elapsed),
            ))

        self._last_counters = now
        return samples

    def _select(self, counters: dict) -> list[str]:
        """Return the list of interface names to sample this cycle."""
        if self._interface != "auto":
            # Pinned to a specific interface; return it if present.
            return [self._interface] if self._interface in counters else []

        # Auto mode: all non-loopback NICs that have seen any traffic.
        # This naturally includes both Ethernet and Wi-Fi when both are
        # active, without needing explicit configuration.
        selected = []
        for name, stats in counters.items():
            if name.lower() in self._LOOPBACK:
                continue
            if stats.bytes_sent + stats.bytes_recv > 0:
                selected.append(name)
        return selected


# ---------------------------------------------------------------------------
# Network state tracker
# ---------------------------------------------------------------------------

class NetworkState:
    """Tracks IP addresses and DNS server across all network adapters.

    Parses 'ipconfig /all' once per cycle. Each named adapter block is
    parsed independently so changes on any adapter fire an event -- useful
    when Ethernet is the primary route but Wi-Fi is also associated and
    its IP changes due to roaming or DHCP renewal.

    Returns:
      primary_ip   -- IPv4 of the adapter with the highest psutil byte count
                      (matches NicProbe's concept of the active interface)
      dns_server   -- first DNS server found in the output (usually the same
                      across adapters on a home/office network)
      events       -- one string per changed adapter IP or DNS server
    """

    def __init__(self):
        self._last_ips: dict[str, str] = {}
        self._last_dns: Optional[str] = None
        self._cache_ts: float = 0.0
        self._cached_ip:  Optional[str] = None
        self._cached_dns: Optional[str] = None

    def read(self) -> tuple[Optional[str], Optional[str], list[str]]:
        """Return (primary_ip, dns_server, [event_strings]).

        ipconfig /all takes 80--210 ms per call. Running it every cycle
        at a 1 s poll interval wastes ~15% of the probe budget. TTL cache
        means it runs at most every IPCONFIG_ALL_TTL seconds; change events
        still fire as soon as the TTL expires and the values differ.
        """
        if time.monotonic() - self._cache_ts < IPCONFIG_ALL_TTL:
            return self._cached_ip, self._cached_dns, []

        # TTL expired -- re-run ipconfig /all.
        try:
            out = cmd_logger.check_output(
                ["ipconfig", "/all"], text=True,
                encoding="utf-8", errors="ignore", timeout=5,
            )
        except Exception:
            self._cache_ts = time.monotonic()  # back off on failure
            return None, None, []

        # Parse into adapter blocks. Each block starts with a non-indented
        # line (the adapter name) and contains indented key: value lines.
        adapters = self._parse_adapters(out)
        dns = self._extract(out, r"DNS Servers.*?:\s*([\d.]+)")

        events = []

        # Detect per-adapter IP changes.
        current_ips: dict[str, str] = {}
        for name, fields in adapters.items():
            ip = fields.get("ip")
            if ip:
                current_ips[name] = ip
                prev = self._last_ips.get(name)
                if prev is not None and prev != ip:
                    events.append(f"ip_change [{name}]: {prev} -> {ip}")

        # Detect adapters that have gained or lost an IP.
        for name in set(self._last_ips) - set(current_ips):
            events.append(f"ip_lost [{name}]: {self._last_ips[name]} -> (none)")
        for name in set(current_ips) - set(self._last_ips):
            if self._last_ips:  # suppress on first run
                events.append(f"ip_gained [{name}]: {current_ips[name]}")

        if self._last_dns is not None and dns != self._last_dns:
            events.append(f"dns_server_change: {self._last_dns} -> {dns}")

        self._last_ips  = current_ips
        self._last_dns  = dns
        primary_ip = self._primary_ip(current_ips)
        self._cached_ip  = primary_ip
        self._cached_dns = dns
        self._cache_ts   = time.monotonic()
        return primary_ip, dns, events

    @staticmethod
    def _parse_adapters(text: str) -> dict[str, dict[str, str]]:
        """Return {adapter_name: {'ip': ..., 'gateway': ...}} from ipconfig /all.

        Adapter header lines are non-indented and end with a colon.
        IPv4 address and default gateway are extracted from the indented
        lines that follow each header.
        """
        adapters: dict[str, dict[str, str]] = {}
        current: Optional[str] = None

        ip_pat  = re.compile(r"IPv4 Address.*?:\s*([\d.]+)")
        gw_pat  = re.compile(r"Default Gateway.*?:\s*([\d.]+)")

        for line in text.splitlines():
            # Adapter header: non-indented, ends with ':'
            if line and not line[0].isspace() and line.rstrip().endswith(":"):
                current = line.strip().rstrip(":")
                adapters[current] = {}
                continue

            if current is None:
                continue

            m = ip_pat.search(line)
            if m and "ip" not in adapters[current]:
                adapters[current]["ip"] = m.group(1)

            m = gw_pat.search(line)
            if m and "gateway" not in adapters[current]:
                adapters[current]["gateway"] = m.group(1)

        return adapters

    @staticmethod
    def _primary_ip(current_ips: dict[str, str]) -> Optional[str]:
        """Return the IP belonging to the NIC with the highest psutil byte count."""
        if not current_ips:
            return None
        try:
            counters = psutil.net_io_counters(pernic=True)
            # Find the psutil NIC name that best matches an adapter name.
            # ipconfig names are verbose ("Ethernet adapter Local Area Connection");
            # psutil names are short ("Ethernet"). Match on containment.
            best_nic = max(
                counters,
                key=lambda n: counters[n].bytes_sent + counters[n].bytes_recv,
            )
            for adapter_name, ip in current_ips.items():
                if best_nic.lower() in adapter_name.lower() or \
                   adapter_name.lower().startswith(best_nic.lower()):
                    return ip
        except Exception:
            pass
        # Fallback: return first IP found.
        return next(iter(current_ips.values()), None)

    @staticmethod
    def _extract(text: str, pattern: str) -> Optional[str]:
        m = re.search(pattern, text)
        return m.group(1).strip() if m else None


# ---------------------------------------------------------------------------
# DNS server direct probe
# ---------------------------------------------------------------------------

def dns_server_latency(server_ip: str, timeout: float = 2.0) -> Optional[float]:
    """Measure RTT of a raw DNS query directly to server_ip:53 (UDP).

    Sends a minimal A-record query for 'a.root-servers.net' and waits for
    any response. This isolates DNS server reachability and latency from the
    OS resolver path (which may cache or redirect through a stub resolver).

    Returns elapsed milliseconds, or None on timeout / error.
    """
    if not server_ip:
        return None

    # Minimal DNS query: transaction ID 0x1234, standard query for 'a.root-servers.net' A
    # Built manually to avoid needing dnspython.
    # Header: ID=0x1234, QR=0, Opcode=0, AA=0, TC=0, RD=1, RA=0, Z=0, RCODE=0
    # QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
    header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)

    # QNAME: encode 'a.root-servers.net'
    def encode_name(name: str) -> bytes:
        parts = name.rstrip(".").split(".")
        encoded = b""
        for part in parts:
            encoded += bytes([len(part)]) + part.encode()
        return encoded + b"\x00"

    qname = encode_name("a.root-servers.net")
    # QTYPE=A (1), QCLASS=IN (1)
    question = qname + struct.pack(">HH", 1, 1)
    packet = header + question

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        start = time.perf_counter()
        sock.sendto(packet, (server_ip, 53))
        sock.recv(512)  # any valid DNS response is sufficient
        elapsed = (time.perf_counter() - start) * 1000
        return round(elapsed, 1)
    except Exception:
        return None
    finally:
        sock.close()


# ---------------------------------------------------------------------------
# TCP state probe
# ---------------------------------------------------------------------------

def read_tcp_states() -> TcpStateSample:
    """Count TCP connections by state. Returns zeroed sample on psutil error."""
    ts = datetime.now().isoformat()
    sample = TcpStateSample(timestamp=ts)
    known = {
        "ESTABLISHED": "established", "TIME_WAIT": "time_wait",
        "CLOSE_WAIT": "close_wait",   "SYN_SENT":  "syn_sent",
        "SYN_RECV":   "syn_recv",     "FIN_WAIT1": "fin_wait1",
        "FIN_WAIT2":  "fin_wait2",    "CLOSING":   "closing",
        "LAST_ACK":   "last_ack",     "LISTEN":    "listen",
    }
    try:
        for conn in psutil.net_connections(kind="tcp"):
            attr = known.get(conn.status, "other")
            setattr(sample, attr, getattr(sample, attr) + 1)
    except Exception:
        pass
    return sample


# ---------------------------------------------------------------------------
# Bufferbloat probe
# ---------------------------------------------------------------------------

class BufferbloatProbe:
    """Measures bufferbloat by comparing ping RTT at idle vs under download load.

    Method
    ------
    1. Record the current rolling average ping as the baseline.
    2. Start a background thread that downloads a large file from
       bufferbloat.download_url, consuming bandwidth for the test window.
    3. Fire ping_count pings to the configured ping host during the download.
    4. Compute mean loaded RTT and delta vs baseline.
    5. Rate the result and return a BufferbloatSample.

    The download thread uses a streaming requests.get with a small chunk size
    so it stays active for the full test window regardless of line speed.
    It is abandoned (daemon thread) after test_duration_seconds.

    This runs in the monitor_loop thread so it blocks for approximately
    test_duration_seconds. This is intentional -- probe_duration_ms will
    reflect the scan cost and may trigger slow_probe warnings, which is the
    correct signal to the operator.
    """

    # Delta thresholds in milliseconds for the four rating bands.
    _RATINGS = [
        (30,  "good"),
        (100, "moderate"),
        (300, "bad"),
    ]

    def __init__(self, config: dict):
        bb_cfg = config.get("bufferbloat", {})
        self.enabled          = bb_cfg.get("enabled", True)
        self.download_url     = bb_cfg.get("download_url",
            "https://speed.cloudflare.com/__down?bytes=104857600")  # 100 MB
        self.test_duration    = bb_cfg.get("test_duration_seconds", 10)
        self.ping_count       = bb_cfg.get("ping_count", 10)
        self.interval_cycles  = bb_cfg.get("interval_cycles", 300)  # every 5 min

    def run(
        self,
        ping_host: str,
        baseline_ms: float,
        ping_fn,   # callable: (host: str) -> Optional[float]
    ) -> BufferbloatSample:
        """Execute the bufferbloat test and return a result sample.

        ping_fn is Monitor._ping so we reuse the existing ping implementation
        without coupling BufferbloatProbe to Monitor directly.
        """
        ts = datetime.now().isoformat()

        # Start background download to saturate the uplink queue.
        download_done = threading.Event()
        bytes_downloaded = [0]

        def _download():
            try:
                with requests.get(
                    self.download_url,
                    stream=True,
                    timeout=self.test_duration + 5,
                ) as resp:
                    resp.raise_for_status()
                    deadline = time.monotonic() + self.test_duration
                    for chunk in resp.iter_content(chunk_size=65536):
                        bytes_downloaded[0] += len(chunk)
                        if time.monotonic() >= deadline:
                            break
            except Exception:
                pass
            finally:
                download_done.set()

        dl_thread = threading.Thread(target=_download, daemon=True)
        dl_thread.start()

        # Give the download a moment to ramp up before firing pings.
        time.sleep(0.5)

        # Fire ping_count pings spread across the test window.
        ping_interval = max(0.1, (self.test_duration - 0.5) / self.ping_count)
        loaded_rtts: list[float] = []

        for _ in range(self.ping_count):
            rtt = ping_fn(ping_host)
            if rtt is not None:
                loaded_rtts.append(rtt)
            time.sleep(ping_interval)

        # Wait for download to finish (it should already be done).
        dl_thread.join(timeout=2)

        # Compute results.
        loaded_ms   = round(statistics.mean(loaded_rtts), 1) if loaded_rtts else None
        delta_ms    = round(loaded_ms - baseline_ms, 1) if (loaded_ms and baseline_ms) else None
        dl_mbps     = round(bytes_downloaded[0] * 8 / 1_000_000 / self.test_duration, 2)

        rating = "unknown"
        if delta_ms is not None:
            rating = "severe"
            for threshold, label in self._RATINGS:
                if delta_ms < threshold:
                    rating = label
                    break

        return BufferbloatSample(
            timestamp=ts,
            baseline_ms=baseline_ms,
            loaded_ms=loaded_ms,
            delta_ms=delta_ms,
            rating=rating,
            download_mbps=dl_mbps if dl_mbps > 0 else None,
            ping_host=ping_host,
            download_url=self.download_url,
        )


# ---------------------------------------------------------------------------
# Speed test probe
# ---------------------------------------------------------------------------

class SpeedTestProbe:
    """Measures download and upload throughput against a configurable endpoint.

    Both directions use the same test duration. The download streams a large
    file from download_url, counting bytes received until the deadline.
    The upload POSTs a pre-allocated buffer to upload_url, counting bytes
    sent until the deadline.

    Cloudflare speed test endpoints used by default:
      Download: https://speed.cloudflare.com/__down?bytes=N
      Upload:   https://speed.cloudflare.com/__up

    No account or API key required. Client-side elapsed time is used for
    throughput calculation since the Cloudflare __up endpoint does not
    return throughput JSON.

    The test runs in the monitor_loop thread and blocks for approximately
    2 * test_duration_seconds. probe_duration_ms will reflect this cost on
    test cycles and may trigger slow_probe warnings, which is the intended
    signal to the operator.
    """

    def __init__(self, config: dict):
        st_cfg = config.get("speedtest", {})
        self.enabled          = st_cfg.get("enabled", True)
        self.download_url     = st_cfg.get(
            "download_url",
            "https://speed.cloudflare.com/__down?bytes=104857600",  # 100 MB
        )
        self.upload_url       = st_cfg.get(
            "upload_url",
            "https://speed.cloudflare.com/__up",
        )
        self.test_duration    = st_cfg.get("test_duration_seconds", 10)
        self.interval_cycles  = st_cfg.get("interval_cycles", 900)  # 15 min

    def run(self) -> SpeedTestSample:
        """Run download then upload test; return SpeedTestSample."""
        ts = datetime.now().isoformat()
        dl_bytes, dl_mbps = self._download()
        ul_bytes, ul_mbps = self._upload()
        return SpeedTestSample(
            timestamp=ts,
            download_mbps=dl_mbps,
            upload_mbps=ul_mbps,
            download_bytes=dl_bytes,
            upload_bytes=ul_bytes,
            duration_seconds=self.test_duration,
            download_url=self.download_url,
            upload_url=self.upload_url,
        )

    def _download(self) -> tuple[int, Optional[float]]:
        """Stream download_url for test_duration seconds; return (bytes, Mbps)."""
        total_bytes = 0
        start = time.perf_counter()
        deadline = time.monotonic() + self.test_duration
        try:
            with requests.get(
                self.download_url, stream=True,
                timeout=self.test_duration + 5,
            ) as resp:
                resp.raise_for_status()
                for chunk in resp.iter_content(chunk_size=65536):
                    total_bytes += len(chunk)
                    if time.monotonic() >= deadline:
                        break
        except Exception:
            return total_bytes, None
        elapsed = time.perf_counter() - start
        if elapsed <= 0 or total_bytes == 0:
            return total_bytes, None
        mbps = round(total_bytes * 8 / 1_000_000 / elapsed, 2)
        return total_bytes, mbps

    def _upload(self) -> tuple[int, Optional[float]]:
        """POST a buffer to upload_url for test_duration seconds; return (bytes, Mbps).

        Sends the buffer in a chunked generator so the request stays alive for
        the full test window rather than sending in a single burst.
        A 10 MB buffer is allocated once and yielded in 64 KB chunks until the
        deadline, giving the server a continuous stream to measure.
        """
        # Pre-allocate a 10 MB buffer of zero bytes.
        buf = bytes(10 * 1024 * 1024)
        total_bytes = [0]
        deadline = time.monotonic() + self.test_duration
        start = time.perf_counter()

        def _gen():
            """Yield buf in 64 KB chunks until the deadline."""
            chunk_size = 65536
            offset = 0
            while time.monotonic() < deadline:
                chunk = buf[offset:offset + chunk_size]
                if not chunk:
                    offset = 0
                    chunk = buf[offset:offset + chunk_size]
                total_bytes[0] += len(chunk)
                yield chunk
                offset += chunk_size

        try:
            requests.post(
                self.upload_url,
                data=_gen(),
                headers={"Content-Type": "application/octet-stream"},
                timeout=self.test_duration + 5,
            )
        except Exception:
            # Timeout or connection error after partial upload is expected --
            # the generator exhausts before the server closes the connection.
            pass

        elapsed = time.perf_counter() - start
        if elapsed <= 0 or total_bytes[0] == 0:
            return total_bytes[0], None
        mbps = round(total_bytes[0] * 8 / 1_000_000 / elapsed, 2)
        return total_bytes[0], mbps


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------

class Storage:
    """SQLite persistence for all tables.

    _apply_schema() runs schema.sql via executescript() on construction.
    check_same_thread=False allows the web dashboard to open a second
    read-only connection to the same file concurrently.
    """

    def __init__(self, db_path: str):
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._path = db_path
        self.connection = sqlite3.connect(db_path, check_same_thread=False)
        self._apply_schema()

    def _apply_schema(self):
        with open(SCHEMA_FILE, "r", encoding="utf-8") as fh:
            self.connection.executescript(fh.read())

    def db_size_bytes(self) -> int:
        """Return the current size of the SQLite file in bytes."""
        try:
            return Path(self._path).stat().st_size
        except OSError:
            return 0

    def purge_old_rows(self, retention_days: int):
        """Delete rows older than retention_days from all tables.

        Uses a single cutoff timestamp computed once and applied to every
        table. Commits once after all deletes to keep the operation atomic.
        Called from the retention thread once per hour.
        """
        cutoff = (datetime.now() - timedelta(days=retention_days)).isoformat()
        tables = [
            ("samples",             "timestamp"),
            ("events",              "timestamp"),
            ("wifi_samples",        "timestamp"),
            ("nic_samples",         "timestamp"),
            ("tcp_states",          "timestamp"),
            ("wifi_scan_results",   "scan_timestamp"),
            ("bufferbloat_samples", "timestamp"),
            ("speed_test_results",  "timestamp"),
        ]
        for table, col in tables:
            self.connection.execute(
                f"DELETE FROM {table} WHERE {col} < ?", (cutoff,)
            )
        self.connection.commit()

    def insert_sample(self, s: Sample):
        self.connection.execute("""
            INSERT INTO samples
                (timestamp, probed_host, internet_ping, gateway_ping,
                 dns_ms, dns_server_ms, http_ms, packet_loss_rate,
                 ip_address, dns_server, cpu_pct, ram_pct,
                 probe_duration_ms, notes)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (s.timestamp, s.probed_host, s.internet_ping, s.gateway_ping,
              s.dns_ms, s.dns_server_ms, s.http_ms, s.packet_loss_rate,
              s.ip_address, s.dns_server, s.cpu_pct, s.ram_pct,
              s.probe_duration_ms, s.notes))
        self.connection.commit()

    def insert_event(self, timestamp: str, category: str, message: str):
        self.connection.execute(
            "INSERT INTO events (timestamp, category, message) VALUES (?,?,?)",
            (timestamp, category, message),
        )
        self.connection.commit()

    def insert_wifi(self, w: WifiSample):
        self.connection.execute("""
            INSERT INTO wifi_samples
                (timestamp, ssid, bssid, signal_pct, channel, band,
                 rx_rate_mbps, tx_rate_mbps, auth)
            VALUES (?,?,?,?,?,?,?,?,?)
        """, (w.timestamp, w.ssid, w.bssid, w.signal_pct, w.channel,
              w.band, w.rx_rate_mbps, w.tx_rate_mbps, w.auth))
        self.connection.commit()

    def insert_nic(self, n: NicSample):
        self.connection.execute("""
            INSERT INTO nic_samples
                (timestamp, interface, bytes_sent_ps, bytes_recv_ps,
                 errin_ps, errout_ps, dropin_ps, dropout_ps)
            VALUES (?,?,?,?,?,?,?,?)
        """, (n.timestamp, n.interface, n.bytes_sent_ps, n.bytes_recv_ps,
              n.errin_ps, n.errout_ps, n.dropin_ps, n.dropout_ps))
        self.connection.commit()

    def insert_tcp(self, t: TcpStateSample):
        self.connection.execute("""
            INSERT INTO tcp_states
                (timestamp, established, time_wait, close_wait, syn_sent,
                 syn_recv, fin_wait1, fin_wait2, closing, last_ack, listen, other)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
        """, (t.timestamp, t.established, t.time_wait, t.close_wait,
              t.syn_sent, t.syn_recv, t.fin_wait1, t.fin_wait2,
              t.closing, t.last_ack, t.listen, t.other))
        self.connection.commit()

    def insert_wifi_scan(self, entries: list[WifiScanEntry]):
        """Persist all entries from one scan batch. Single commit for the batch."""
        self.connection.executemany("""
            INSERT INTO wifi_scan_results
                (scan_timestamp, ssid, bssid, signal_pct, channel, band,
                 authentication, cipher)
            VALUES (?,?,?,?,?,?,?,?)
        """, [
            (e.scan_timestamp, e.ssid, e.bssid, e.signal_pct, e.channel,
             e.band, e.authentication, e.cipher)
            for e in entries
        ])
        self.connection.commit()

    def insert_bufferbloat(self, b: BufferbloatSample):
        self.connection.execute("""
            INSERT INTO bufferbloat_samples
                (timestamp, baseline_ms, loaded_ms, delta_ms, rating,
                 download_mbps, ping_host, download_url)
            VALUES (?,?,?,?,?,?,?,?)
        """, (b.timestamp, b.baseline_ms, b.loaded_ms, b.delta_ms,
              b.rating, b.download_mbps, b.ping_host, b.download_url))
        self.connection.commit()

    def insert_speed_test(self, s: SpeedTestSample):
        self.connection.execute("""
            INSERT INTO speed_test_results
                (timestamp, download_mbps, upload_mbps, download_bytes,
                 upload_bytes, duration_seconds, download_url, upload_url)
            VALUES (?,?,?,?,?,?,?,?)
        """, (s.timestamp, s.download_mbps, s.upload_mbps,
              s.download_bytes, s.upload_bytes, s.duration_seconds,
              s.download_url, s.upload_url))
        self.connection.commit()


# ---------------------------------------------------------------------------
# Monitor
# ---------------------------------------------------------------------------

class Monitor:
    """Central controller. Owns config, all probes, storage, and the TUI.

    Lifecycle events (monitor_start / monitor_stop) are written to the events
    table so the dashboard can display them alongside connectivity events.
    """

    def __init__(self):
        self.config   = self._load_config()
        self.interval = self.config["general"]["poll_interval_seconds"]

        self.ping_cycler = HostCycler(self.config["network"]["internet_ping_hosts"])
        self.dns_cycler  = HostCycler(self.config["network"]["dns_hosts"])
        self.http_cycler = HostCycler(self.config["network"]["http_targets"])

        wifi_cfg         = self.config.get("wifi", {})
        self.wifi_probe  = WifiProbe(enabled=wifi_cfg.get("enabled", False))
        self.wifi_scanner = WifiScanner()
        self._scan_enabled = wifi_cfg.get("enabled", False)
        self._scan_interval = wifi_cfg.get("scan_interval_cycles", 60)
        self._cycle_count = 0
        self.bloat_probe     = BufferbloatProbe(self.config)
        self._bloat_interval = self.bloat_probe.interval_cycles
        self.speed_probe     = SpeedTestProbe(self.config)
        self._speed_interval = self.speed_probe.interval_cycles
        self.nic_probe   = NicProbe(self.config.get("nic", {}).get("interface", "auto"))
        self.net_state   = NetworkState()
        self.gw_cache    = GatewayCache()

        self.stats   = RollingStats(size=120)
        self.current: Optional[Sample]     = None
        self.current_wifi: Optional[WifiSample] = None
        self.current_nic: Optional[NicSample]   = None
        self.running = True

        self.events: deque[str] = deque(maxlen=self.config["tui"]["max_events"])

        self.storage = Storage(self.config["storage"]["sqlite_db"])
        self._setup_logging()
        self._last_loop_time: Optional[float] = None

        # Write startup event after storage is ready.
        self._add_event("system", "monitor_start")

    def shutdown(self):
        """Graceful shutdown -- write stop event before exiting."""
        if self.running:
            self.running = False
            self._add_event("system", "monitor_stop")

    def _load_config(self) -> dict:
        with open(CONFIG_FILE, "r", encoding="utf-8") as fh:
            return yaml.safe_load(fh)

    def _setup_logging(self):
        log_cfg = self.config["storage"]["event_log"]
        Path(log_cfg["path"]).parent.mkdir(parents=True, exist_ok=True)
        handler = RotatingFileHandler(
            log_cfg["path"],
            maxBytes=log_cfg["max_size_mb"] * 1024 * 1024,
            backupCount=log_cfg["backup_count"],
        )
        logging.basicConfig(
            level=logging.INFO,
            handlers=[handler],
            format="%(asctime)s %(levelname)s %(message)s",
        )

    def _add_event(self, category: str, message: str):
        """Log, prepend to TUI deque, and persist an event."""
        ts = datetime.now().isoformat()
        display = f"{datetime.now().strftime('%H:%M:%S')} [{category}] {message}"
        self.events.appendleft(display)
        logging.info("[%s] %s", category, message)
        self.storage.insert_event(ts, category, message)

    # -----------------------------------------------------------------------
    # Probes
    # -----------------------------------------------------------------------

    def _ping(self, host: str) -> Optional[float]:
        """Ping host once (Windows -n 1 -w 1000); return RTT ms or None."""
        start = time.perf_counter()
        try:
            result = cmd_logger.run(
                ["ping", "-n", "1", "-w", "1000", host],
                capture_output=True, timeout=3,
            )
            if result.returncode != 0:
                return None
            return round((time.perf_counter() - start) * 1000, 1)
        except Exception:
            return None

    def _ping_all(self, hosts: list[str]) -> dict[str, Optional[float]]:
        """Ping all hosts concurrently; return {host: ms | None}."""
        results: dict[str, Optional[float]] = {}

        def probe(h: str):
            results[h] = self._ping(h)

        threads = [threading.Thread(target=probe, args=(h,), daemon=True) for h in hosts]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)
        return results

    def _dns_timing(self, host: str) -> Optional[float]:
        """Resolve host via system resolver; return elapsed ms or None."""
        start = time.perf_counter()
        try:
            socket.gethostbyname(host)
            return round((time.perf_counter() - start) * 1000, 1)
        except Exception:
            return None

    def _http_timing(self, url: str) -> Optional[float]:
        """Full HTTP GET including TLS; return elapsed ms or None."""
        start = time.perf_counter()
        try:
            r = requests.get(url, timeout=5)
            r.raise_for_status()
            return round((time.perf_counter() - start) * 1000, 1)
        except Exception:
            return None

    # -----------------------------------------------------------------------
    # Analysis
    # -----------------------------------------------------------------------

    def _analyse(
        self,
        ping_ms: Optional[float],
        gateway_ms: Optional[float],
        dns_ms: Optional[float],
        loss_rate: float,
        nic_samples: list[NicSample],
    ) -> str:
        """Return comma-separated fault label string, or '' if healthy.

        Labels
        ------
        packet_loss       ping returned None
        severe_latency    ping > severe_latency_ms  (supersedes high_latency)
        high_latency      ping > high_latency_ms
        high_packet_loss  rolling loss % > packet_loss_rate_pct
        high_jitter       rolling jitter > high_jitter_ms
        slow_dns          dns_ms > slow_dns_ms
        isp_issue_likely  gateway < 10 ms but ping > high_latency_ms
        nic_errors        sustained NIC error or drop rate > nic_error_rate_ps
        """
        t = self.config["thresholds"]
        notes = []

        if ping_ms is None:
            notes.append("packet_loss")
        elif ping_ms > t["severe_latency_ms"]:
            notes.append("severe_latency")
        elif ping_ms > t["high_latency_ms"]:
            notes.append("high_latency")

        if loss_rate > t.get("packet_loss_rate_pct", 5):
            notes.append("high_packet_loss")

        if self.stats.jitter() > t["high_jitter_ms"]:
            notes.append("high_jitter")

        if dns_ms is not None and dns_ms > t["slow_dns_ms"]:
            notes.append("slow_dns")

        if gateway_ms and ping_ms and gateway_ms < 10 and ping_ms > t["high_latency_ms"]:
            notes.append("isp_issue_likely")

        # NIC error/drop threshold check.
        nic_err_threshold = t.get("nic_error_rate_ps", 1.0)
        for ns in nic_samples:
            total_err = ns.errin_ps + ns.errout_ps + ns.dropin_ps + ns.dropout_ps
            if total_err > nic_err_threshold:
                notes.append(f"nic_errors({ns.interface}:{total_err:.1f}/s)")
                break  # one label per cycle is sufficient

        return ", ".join(notes)

    # -----------------------------------------------------------------------
    # Fault diagnostics
    # -----------------------------------------------------------------------

    def _fault_diagnostics(self):
        """Probe all hosts concurrently and run tracert on fault."""
        if not self.config["diagnostics"]["traceroute_on_fault"]:
            return

        all_results = self._ping_all(self.ping_cycler.all())
        summary = ", ".join(
            f"{h}={'OK' if ms is not None else 'FAIL'}"
            for h, ms in all_results.items()
        )
        self._add_event("fault", f"multi-host probe: {summary}")

        primary = self.ping_cycler.all()[0]
        self._add_event("info", f"Running tracert to {primary}")
        try:
            out = cmd_logger.check_output(
                ["tracert", primary],
                text=True, encoding="utf-8", errors="ignore", timeout=60,
            )
            inc_dir = Path(self.config["storage"]["incidents_path"])
            inc_dir.mkdir(parents=True, exist_ok=True)
            fname = inc_dir / f"incident_{int(time.time())}.txt"
            with open(fname, "w", encoding="utf-8") as fh:
                fh.write(f"Multi-host probe: {summary}\n\n{out}")
        except Exception as exc:
            self._add_event("info", f"tracert failed: {exc}")

    # -----------------------------------------------------------------------
    # Retention thread
    # -----------------------------------------------------------------------

    def retention_loop(self):
        """Runs every hour; deletes rows older than retention_days."""
        days = self.config["general"]["retention_days"]
        while self.running:
            # Sleep first so the first purge happens after one full hour,
            # not immediately on startup.
            time.sleep(3600)
            if not self.running:
                break
            try:
                self.storage.purge_old_rows(days)
                self._add_event("system", f"retention_purge: removed rows older than {days} days")
            except Exception as exc:
                self._add_event("system", f"retention_purge failed: {exc}")

    # -----------------------------------------------------------------------
    # Monitor loop
    # -----------------------------------------------------------------------

    def monitor_loop(self):
        """Background polling loop. Runs until self.running is False.

        The probe block is timed; if its duration exceeds poll_interval_seconds
        a slow_probe warning event is fired. Sleep time is adjusted to
        compensate so the cycle period stays close to the configured interval.
        """
        while self.running:
            loop_start = time.monotonic()
            elapsed_since_last = (
                (loop_start - self._last_loop_time) if self._last_loop_time else 1.0
            )
            self._last_loop_time = loop_start

            ts = datetime.now().isoformat()

            # --- Probe block start ---
            probe_start = time.perf_counter()

            self._cycle_count += 1
            ping_host = self.ping_cycler.next()
            dns_host  = self.dns_cycler.next()
            http_url  = self.http_cycler.next()

            gateway   = self.gw_cache.get()
            ping_ms   = self._ping(ping_host)
            gw_ms     = self._ping(gateway) if gateway else None
            dns_ms    = self._dns_timing(dns_host)

            # Direct UDP probe to the DNS server (not the hostname being resolved).
            ip_addr, dns_srv, state_events = self.net_state.read()
            dns_server_ms = dns_server_latency(dns_srv) if dns_srv else None

            http_ms   = self._http_timing(http_url)

            wifi_sample, wifi_events = self.wifi_probe.read()

            # Run the full environment scan on the first cycle and then every
            # scan_interval_cycles cycles after that. Running on cycle 1 means
            # the dashboard shows Wi-Fi scan data immediately on startup rather
            # than waiting up to a minute.
            scan_entries: list[WifiScanEntry] = []
            if self._cycle_count == 1 or self._cycle_count % self._scan_interval == 0:
                scan_entries = self.wifi_scanner.scan()

            # Run bufferbloat test on its own interval. Skipped on cycle 0
            # so the rolling baseline has time to populate first. Runs inside
            # the probe block so probe_duration_ms reflects the ~10 s test cost.
            # Also skipped if a speed test fires this cycle -- they would
            # interfere by saturating the link simultaneously.
            speed_test_this_cycle = (
                self.speed_probe.enabled
                and self._cycle_count > 0
                and self._cycle_count % self._speed_interval == 0
            )

            bloat_sample: Optional[BufferbloatSample] = None
            if (self.bloat_probe.enabled
                    and self._cycle_count > 0
                    and self._cycle_count % self._bloat_interval == 0
                    and not speed_test_this_cycle):
                bloat_sample = self.bloat_probe.run(
                    ping_host=self.ping_cycler.all()[0],
                    baseline_ms=self.stats.average(),
                    ping_fn=self._ping,
                )

            # Run speed test -- download then upload, each for test_duration_seconds.
            # Total blocking time is ~2 * test_duration_seconds; probe_duration_ms
            # will show this cost. Runs after bufferbloat to avoid link contention.
            speed_sample: Optional[SpeedTestSample] = None
            if speed_test_this_cycle:
                speed_sample = self.speed_probe.run()

            nic_samples = self.nic_probe.read(elapsed_since_last)
            tcp = read_tcp_states()

            cpu_pct = psutil.cpu_percent(interval=None)
            ram_pct = psutil.virtual_memory().percent

            probe_duration_ms = (time.perf_counter() - probe_start) * 1000
            # --- Probe block end ---

            # Refresh gateway cache if any adapter's IP changed.
            for ev in state_events:
                if ev.startswith("ip_change") or ev.startswith("ip_gained"):
                    self.gw_cache.force_refresh()
                    break

            # Rolling stats.
            self.stats.add(ping_ms)
            loss_rate = self.stats.packet_loss_rate()

            # Analysis.
            notes = self._analyse(ping_ms, gw_ms, dns_ms, loss_rate, nic_samples)

            # Persist.
            sample = Sample(
                timestamp=ts,
                probed_host=ping_host,
                internet_ping=ping_ms,
                gateway_ping=gw_ms,
                dns_ms=dns_ms,
                dns_server_ms=dns_server_ms,
                http_ms=http_ms,
                packet_loss_rate=loss_rate,
                ip_address=ip_addr,
                dns_server=dns_srv,
                cpu_pct=cpu_pct,
                ram_pct=ram_pct,
                probe_duration_ms=round(probe_duration_ms, 1),
                notes=notes,
            )
            self.current = sample
            self.current_wifi = wifi_sample
            self.storage.insert_sample(sample)

            if wifi_sample:
                self.storage.insert_wifi(wifi_sample)
                self.current_nic = nic_samples[0] if nic_samples else None
            for ns in nic_samples:
                self.storage.insert_nic(ns)
            self.storage.insert_tcp(tcp)
            if scan_entries:
                self.storage.insert_wifi_scan(scan_entries)
            if bloat_sample:
                self.storage.insert_bufferbloat(bloat_sample)
                self._add_event(
                    "system",
                    f"bufferbloat: {bloat_sample.rating} "
                    f"(baseline={bloat_sample.baseline_ms} ms, "
                    f"loaded={bloat_sample.loaded_ms} ms, "
                    f"delta={bloat_sample.delta_ms} ms, "
                    f"dl={bloat_sample.download_mbps} Mbps)",
                )
            if speed_sample:
                self.storage.insert_speed_test(speed_sample)
                self._add_event(
                    "system",
                    f"speedtest: "
                    f"dl={speed_sample.download_mbps} Mbps, "
                    f"ul={speed_sample.upload_mbps} Mbps",
                )

            # Events.
            for ev in wifi_events:
                self._add_event("wifi", ev)
            for ev in state_events:
                self._add_event("network", ev)
            if notes:
                self._add_event("fault", notes)

            # Probe timing warning. Uses a configurable multiplier so a
            # machine where probes reliably take 1.1 s on a 1 s interval
            # doesn't fire constant noise. Default multiplier is 1.5.
            slow_threshold = (
                self.interval * 1000
                * self.config.get("diagnostics", {}).get("slow_probe_multiplier", 1.5)
            )
            if probe_duration_ms > slow_threshold:
                self._add_event(
                    "system",
                    f"slow_probe: {probe_duration_ms:.0f} ms "
                    f"(interval={self.interval * 1000:.0f} ms)",
                )

            # Fault diagnostics.
            if any(lbl in notes for lbl in ("packet_loss", "high_latency", "severe_latency")):
                self._fault_diagnostics()

            # Compensate sleep for probe duration so cycle period is stable.
            elapsed_total = time.monotonic() - loop_start
            sleep_for = max(0.0, self.interval - elapsed_total)
            time.sleep(sleep_for)

    # -----------------------------------------------------------------------
    # TUI
    # -----------------------------------------------------------------------

    def _graph(self, width: int) -> str:
        """Unicode bar chart of rolling ping window. Spaces for lost packets."""
        if not self.stats.window:
            return ""
        blocks  = "▁▂▃▄▅▆▇█"
        values  = list(self.stats.window)[-width:]
        good    = [v for v in values if v is not None]
        maximum = max(good) if good else 1
        if maximum <= 0:
            maximum = 1
        graph = ""
        for v in values:
            if v is None:
                graph += " "
            else:
                graph += blocks[int((v / maximum) * (len(blocks) - 1))]
        return graph

    def tui(self, stdscr):
        """Curses TUI. Redraws at ~10 fps until Q is pressed.

        The render body is wrapped in try/except(curses.error) so that a
        drawing error (terminal too small, string overflows window) is logged
        and skipped rather than crashing the monitor silently. stdscr.timeout()
        replaces time.sleep so getch() is non-blocking with a 100 ms wait.
        """
        curses.curs_set(0)
        stdscr.timeout(100)  # non-blocking getch; replaces time.sleep(0.1)

        while self.running:
            try:
                stdscr.erase()
                height, width = stdscr.getmaxyx()
                stdscr.addstr(0, 2, "Network Observability Monitor", curses.A_BOLD)

                row = 2
                if self.current:
                    s = self.current
                    lines = [
                        f"Time              : {datetime.now().strftime('%H:%M:%S')}",
                        f"Host (this cycle) : {s.probed_host}",
                        f"Internet Ping     : {s.internet_ping} ms",
                        f"Gateway Ping      : {s.gateway_ping} ms",
                        f"DNS (resolver)    : {s.dns_ms} ms",
                        f"DNS (server UDP)  : {s.dns_server_ms} ms  [{s.dns_server or '?'}]",
                        f"HTTP Response     : {s.http_ms} ms",
                        f"Avg Ping          : {self.stats.average():.1f} ms",
                        f"Jitter            : {self.stats.jitter():.1f} ms",
                        f"Packet Loss       : {s.packet_loss_rate:.1f}%",
                        f"CPU / RAM         : {s.cpu_pct:.1f}% / {s.ram_pct:.1f}%",
                        f"Probe Duration    : {s.probe_duration_ms:.0f} ms",
                        f"IP Address        : {s.ip_address or '?'}",
                        "",
                        f"Analysis          : {s.notes or 'healthy'}",
                    ]
                    if self.current_wifi:
                        w = self.current_wifi
                        lines += [
                            "",
                            f"Wi-Fi SSID        : {w.ssid}",
                            f"BSSID             : {w.bssid}",
                            f"Signal            : {w.signal_pct}%  "
                            f"Band: {w.band or '?'}  Ch: {w.channel or '?'}",
                            f"Rx / Tx           : {w.rx_rate_mbps} / {w.tx_rate_mbps} Mbps",
                        ]

                    for line in lines:
                        if row >= height - 7:
                            break
                        stdscr.addstr(row, 2, line[:width - 4])
                        row += 1

                    if row + 3 < height:
                        stdscr.addstr(row + 1, 2, "Latency Graph")
                        stdscr.addstr(row + 2, 2, self._graph(width - 4))
                    if row + 5 < height:
                        stdscr.addstr(row + 4, 2, "Recent Events", curses.A_BOLD)
                        er = row + 5
                        for event in self.events:
                            if er >= height - 2:
                                break
                            stdscr.addstr(er, 4, event[:width - 6])
                            er += 1
                else:
                    if height > 4:
                        stdscr.addstr(2, 2, "Waiting for first sample...")

                if height > 1:
                    stdscr.addstr(height - 1, 2, "Press Q to quit")
                stdscr.refresh()

            except curses.error as exc:
                # Almost always "addstr() returned ERR" when the terminal is
                # too small. Log at DEBUG and continue; the next cycle will
                # try again after the user resizes.
                logging.debug("TUI render error: %s", exc)

            key = stdscr.getch()
            if key in (ord("q"), ord("Q")):
                self.shutdown()
                break


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    if platform.system().lower() != "windows":
        print("Error: advanced_network_monitor.py requires Windows.")
        print(f"Detected platform: {platform.system()}")
        sys.exit(1)

    parser = argparse.ArgumentParser(description="Network Observability Monitor")
    parser.add_argument(
        "--headless", action="store_true",
        help="Run without the curses TUI (pair with web_dashboard.py)",
    )
    parser.add_argument(
        "--debug", action="store_true",
        help=(
            "Log every subprocess command and its response to "
            "logs/network_monitor_debug.log. Useful for diagnosing "
            "why netsh, ping, or ipconfig return unexpected results."
        ),
    )
    args = parser.parse_args()

    # Enable the module-level command logger if --debug is set.
    # Done before Monitor() is constructed so the first probe cycle is logged.
    if args.debug:
        global cmd_logger
        cmd_logger = CommandLogger(enabled=True)

        # Write debug log to a separate file so it doesn't flood the main log.
        debug_path = Path("logs/network_monitor_debug.log")
        debug_path.parent.mkdir(parents=True, exist_ok=True)
        dh = logging.handlers.RotatingFileHandler(
            debug_path, maxBytes=50 * 1024 * 1024, backupCount=3
        )
        dh.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
        debug_log.addHandler(dh)
        print(f"Debug logging enabled -> {debug_path}")

    monitor = Monitor()

    # Register shutdown handler for Ctrl+C and SIGTERM so monitor_stop
    # is always written even when running headless or under a process manager.
    def _handle_signal(sig, frame):
        monitor.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGINT,  _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    collector = threading.Thread(target=monitor.monitor_loop, daemon=True)
    collector.start()

    retention = threading.Thread(target=monitor.retention_loop, daemon=True)
    retention.start()

    if args.headless:
        print("Running in headless mode. Press Ctrl+C to stop.")
        # signal handler above will call monitor.shutdown() and sys.exit().
        while True:
            time.sleep(1)
    else:
        curses.wrapper(monitor.tui)
        monitor.shutdown()


if __name__ == "__main__":
    main()