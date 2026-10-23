"""
web_dashboard.py - Real-Time Browser Dashboard for Windows Network Monitor
==========================================================================
A lightweight, self-contained Flask dashboard that visualises telemetry from
the SQLite database maintained by advanced_network_monitor.py.

Includes:
- Multi-tab navigation (Telemetry, LAN & Devices, Wi-Fi & RF, Diagnostics, Events & Export, All Panels)
- Historical time-range filtering (5m, 15m, 1h, 6h, 24h)
- LAN ARP Neighbor Device discovery with OUI hardware vendor identification
- mDNS / Bonjour / ZeroConf smart device discovery
- Path MTU & gateway port health diagnostics
- Real-time latency, DNS, HTTP, packet loss, CPU/RAM, TCP states
- Wi-Fi signal, 2.4/5 GHz channel congestion & RF spectrum overlap
- Network Hog process bandwidth attribution
- Multi-DNS resolver latency benchmark
- Bufferbloat & automated/on-demand speed testing
- Data export (CSV/JSON) and expandable incident diagnostic reports
"""

import argparse
import os
import sqlite3
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from flask import Flask, Response, jsonify, render_template_string, request

# ---------------------------------------------------------------------------
# Configuration & Globals
# ---------------------------------------------------------------------------

CONFIG_FILE = Path(__file__).parent / "config" / "monitor_config.yaml"

DB_PATH: str = ""
INCIDENTS_PATH: str = ""

app = Flask(__name__)

# Mutex to guard SQLite write access in multi-threaded Flask server
_db_write_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Database Helpers
# ---------------------------------------------------------------------------

def get_read_db() -> sqlite3.Connection:
    conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True, timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 5000;")
    return conn


def get_write_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA busy_timeout = 5000;")
    return conn


def query(sql: str, params: tuple = ()) -> List[Dict[str, Any]]:
    if not DB_PATH or not Path(DB_PATH).exists():
        return []
    try:
        conn = get_read_db()
        try:
            cur = conn.execute(sql, params)
            return [dict(row) for row in cur.fetchall()]
        finally:
            conn.close()
    except sqlite3.OperationalError:
        return []


def n_param(default: int = 300, cap: int = 10000) -> int:
    try:
        val = int(request.args.get("n", default))
        return max(1, min(val, cap))
    except (ValueError, TypeError):
        return default


# ---------------------------------------------------------------------------
# API Routes
# ---------------------------------------------------------------------------

@app.route("/api/latest")
def api_latest():
    """Most recent telemetry sample."""
    rows = query("SELECT * FROM samples ORDER BY timestamp DESC LIMIT 1")
    return jsonify(rows[0] if rows else {})


@app.route("/api/history")
def api_history():
    """Last n telemetry samples, oldest-first for chart rendering."""
    rows = query(
        "SELECT * FROM samples ORDER BY timestamp DESC LIMIT ?",
        (n_param(),),
    )
    return jsonify(list(reversed(rows)))


@app.route("/api/events")
def api_events():
    """Last n events, newest-first."""
    rows = query(
        "SELECT * FROM events ORDER BY timestamp DESC LIMIT ?",
        (n_param(default=100, cap=1000),),
    )
    return jsonify(rows)


@app.route("/api/wifi")
def api_wifi():
    """Last n Wi-Fi connection samples, oldest-first for chart rendering."""
    rows = query(
        "SELECT * FROM wifi_samples ORDER BY timestamp DESC LIMIT ?",
        (n_param(),),
    )
    return jsonify(list(reversed(rows)))


@app.route("/api/nic")
def api_nic():
    """Last n NIC throughput samples, oldest-first for chart rendering."""
    rows = query(
        "SELECT * FROM nic_samples ORDER BY timestamp DESC LIMIT ?",
        (n_param(),),
    )
    return jsonify(list(reversed(rows)))


@app.route("/api/nic/active")
def api_nic_active():
    """Determine the currently active physical network adapter based on recent throughput."""
    latest_ts = query("SELECT MAX(timestamp) AS ts FROM nic_samples")
    if not latest_ts or not latest_ts[0]["ts"]:
        return jsonify({"active": None, "interfaces": []})

    ts = latest_ts[0]["ts"]
    rows = query(
        "SELECT interface, bytes_sent_ps, bytes_recv_ps, "
        "(bytes_sent_ps + bytes_recv_ps) AS total_bps "
        "FROM nic_samples WHERE timestamp = ? "
        "ORDER BY total_bps DESC",
        (ts,),
    )
    active = rows[0]["interface"] if rows and rows[0]["total_bps"] > 1024 else None
    return jsonify({"active": active, "interfaces": rows})


@app.route("/api/nic/timeline")
def api_nic_timeline():
    """Throughput timeline per interface for multi-NIC stacked/line visualization."""
    n = n_param(default=300, cap=2000)
    rows = query(
        "SELECT timestamp, interface, (bytes_sent_ps + bytes_recv_ps) AS total_bps "
        "FROM nic_samples "
        "WHERE timestamp IN (SELECT DISTINCT timestamp FROM nic_samples ORDER BY timestamp DESC LIMIT ?) "
        "ORDER BY timestamp ASC",
        (n,),
    )
    data: Dict[str, List[Dict[str, Any]]] = {}
    for r in rows:
        data.setdefault(r["interface"], []).append({
            "timestamp": r["timestamp"],
            "total_bps": r["total_bps"],
        })
    return jsonify(data)


@app.route("/api/tcp")
def api_tcp():
    """Last n TCP connection state breakdown samples, oldest-first."""
    rows = query(
        "SELECT * FROM tcp_states ORDER BY timestamp DESC LIMIT ?",
        (n_param(default=60),),
    )
    return jsonify(list(reversed(rows)))


@app.route("/api/wifi_scan")
def api_wifi_scan():
    """Most recent Wi-Fi environment scan results (all visible BSSIDs)."""
    latest = query("SELECT MAX(scan_timestamp) AS ts FROM wifi_scan_results")
    if not latest or not latest[0]["ts"]:
        return jsonify([])
    rows = query(
        "SELECT * FROM wifi_scan_results WHERE scan_timestamp = ? ORDER BY signal_pct DESC",
        (latest[0]["ts"],),
    )
    return jsonify(rows)


@app.route("/api/wifi_scan/history")
def api_wifi_scan_history():
    """Signal strength history for a specific BSSID or SSID over time."""
    bssid = request.args.get("bssid")
    ssid  = request.args.get("ssid")
    n     = n_param(default=100, cap=1000)

    if bssid:
        rows = query(
            "SELECT scan_timestamp, ssid, bssid, signal_pct, channel, band "
            "FROM wifi_scan_results WHERE bssid = ? "
            "ORDER BY scan_timestamp DESC LIMIT ?",
            (bssid, n),
        )
    elif ssid:
        rows = query(
            "SELECT scan_timestamp, ssid, bssid, signal_pct, channel, band "
            "FROM wifi_scan_results WHERE ssid = ? "
            "ORDER BY scan_timestamp DESC LIMIT ?",
            (ssid, n),
        )
    else:
        return jsonify({"error": "bssid or ssid parameter required"}), 400

    return jsonify(list(reversed(rows)))


@app.route("/api/incidents")
def api_incidents():
    """List diagnostic incident files, newest-first."""
    inc_dir = Path(INCIDENTS_PATH)
    if not inc_dir.exists():
        return jsonify([])

    files = []
    for f in inc_dir.glob("incident_*.txt"):
        try:
            stat = f.stat()
            files.append({
                "filename":   f.name,
                "size_bytes": stat.st_size,
                "modified":   datetime.fromtimestamp(stat.st_mtime).isoformat(),
            })
        except OSError:
            pass

    files.sort(key=lambda x: x["modified"], reverse=True)
    return jsonify(files)


@app.route("/api/bufferbloat")
def api_bufferbloat():
    """Last n bufferbloat measurements, newest-first."""
    rows = query(
        "SELECT * FROM bufferbloat_samples ORDER BY timestamp DESC LIMIT ?",
        (n_param(default=20, cap=200),),
    )
    return jsonify(rows)


@app.route("/api/speed_test")
def api_speed_test():
    """Last n speed test results, newest-first."""
    rows = query(
        "SELECT * FROM speed_test_results ORDER BY timestamp DESC LIMIT ?",
        (n_param(default=50, cap=500),),
    )
    return jsonify(rows)


@app.route("/api/export")
def api_export():
    """Export a time-windowed slice of any table as CSV or JSON."""
    import csv
    import io
    import json as json_mod

    VALID_TABLES = {
        "samples":             "timestamp",
        "events":              "timestamp",
        "wifi_samples":        "timestamp",
        "nic_samples":         "timestamp",
        "tcp_states":          "timestamp",
        "wifi_scan_results":   "scan_timestamp",
        "bufferbloat_samples": "timestamp",
        "speed_test_results":  "timestamp",
        "action_queue":        "timestamp",
        "process_samples":     "timestamp",
        "dns_benchmarks":      "timestamp",
        "mdns_devices":        "last_seen",
        "lan_devices":         "last_seen",
        "mtu_samples":         "timestamp",
    }

    table   = request.args.get("table", "samples")
    fmt     = request.args.get("format", "csv").lower()
    from_ts = request.args.get(
        "from", (datetime.now() - timedelta(hours=24)).isoformat()
    )
    to_ts   = request.args.get("to", datetime.now().isoformat())

    if table not in VALID_TABLES:
        return jsonify({"error": f"Unknown table '{table}'. "
                        f"Valid: {', '.join(VALID_TABLES)}"}), 400
    if fmt not in ("csv", "json"):
        return jsonify({"error": "format must be csv or json"}), 400

    ts_col = VALID_TABLES[table]
    rows = query(
        f"SELECT * FROM {table} "
        f"WHERE {ts_col} >= ? AND {ts_col} <= ? "
        f"ORDER BY {ts_col} ASC",
        (from_ts, to_ts),
    )

    stem = f"{table}_{from_ts[:10]}_{to_ts[:10]}"

    if fmt == "json":
        return Response(
            json_mod.dumps(rows, indent=2),
            mimetype="application/json",
            headers={"Content-Disposition": f"attachment; filename={stem}.json"},
        )

    if not rows:
        return Response(
            "",
            mimetype="text/csv",
            headers={"Content-Disposition": f"attachment; filename={stem}.csv"},
        )

    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=rows[0].keys())
    writer.writeheader()
    writer.writerows(rows)
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={stem}.csv"},
    )


@app.route("/api/mdns")
def api_mdns():
    """Return all discovered mDNS / Bonjour / ZeroConf devices."""
    rows = query("""
        SELECT ip_address, hostname, services, MAX(last_seen) as last_seen
        FROM mdns_devices
        GROUP BY ip_address
        ORDER BY last_seen DESC
        LIMIT ?
    """, (n_param(default=50, cap=200),))
    return jsonify(rows)


@app.route("/api/lan_devices")
def api_lan_devices():
    """Return all active LAN ARP neighbor devices with MAC vendors."""
    rows = query("""
        SELECT ip_address, mac_address, vendor, interface_ip, device_type, MAX(last_seen) as last_seen
        FROM lan_devices
        GROUP BY ip_address
        ORDER BY ip_address ASC
        LIMIT ?
    """, (n_param(default=100, cap=500),))
    return jsonify(rows)


@app.route("/api/mtu")
def api_mtu():
    """Return latest Path MTU diagnostics."""
    rows = query("SELECT * FROM mtu_samples ORDER BY timestamp DESC LIMIT 5")
    return jsonify(rows)


@app.route("/api/processes")
def api_processes():
    """Return top active network processes from the latest sample."""
    latest_ts = query("SELECT MAX(timestamp) AS ts FROM process_samples")
    if not latest_ts or not latest_ts[0]["ts"]:
        return jsonify([])
    ts = latest_ts[0]["ts"]
    rows = query("""
        SELECT * FROM process_samples
        WHERE timestamp = ?
        ORDER BY (read_bytes_ps + write_bytes_ps) DESC, conn_count DESC
        LIMIT 10
    """, (ts,))
    return jsonify(rows)


@app.route("/api/dns_benchmark")
def api_dns_benchmark():
    """Return latest DNS benchmark result and history."""
    rows = query(
        "SELECT * FROM dns_benchmarks ORDER BY timestamp DESC LIMIT ?",
        (n_param(default=20, cap=100),),
    )
    return jsonify(rows)


@app.route("/api/wifi_channels")
def api_wifi_channels():
    """Compute channel congestion distribution from the latest Wi-Fi environment scan."""
    latest = query("SELECT MAX(scan_timestamp) AS ts FROM wifi_scan_results")
    if not latest or not latest[0]["ts"]:
        return jsonify({"channels_24": {}, "channels_5": {}, "recommendation_24": None})
    rows = query(
        "SELECT * FROM wifi_scan_results WHERE scan_timestamp = ?",
        (latest[0]["ts"],),
    )
    channels_24 = {}
    channels_5 = {}
    for r in rows:
        ch = r.get("channel")
        if ch is None:
            continue
        band = r.get("band") or ("2.4GHz" if ch <= 14 else "5GHz")
        target_dict = channels_24 if "2.4" in band else channels_5
        if ch not in target_dict:
            target_dict[ch] = {"count": 0, "ssids": []}
        target_dict[ch]["count"] += 1
        if r.get("ssid"):
            target_dict[ch]["ssids"].append(r["ssid"])

    # Recommend 2.4 GHz channel among non-overlapping 1, 6, 11
    best_ch = 1
    min_score = float("inf")
    for ch in (1, 6, 11):
        score = sum(
            channels_24.get(c, {}).get("count", 0) * max(0, 1 - abs(c - ch) / 5.0)
            for c in range(1, 14)
        )
        if score < min_score:
            min_score = score
            best_ch = ch

    rec = f"Channel {best_ch} has the lowest interference among standard channels (1, 6, 11)" if best_ch else None
    return jsonify({
        "scan_timestamp": latest[0]["ts"],
        "channels_24": channels_24,
        "channels_5": channels_5,
        "recommendation_24": rec,
        "best_channel_24": best_ch,
    })


@app.route("/api/actions", methods=["POST"])
def api_queue_action():
    """Queue an on-demand diagnostic action (speedtest, bufferbloat, traceroute, etc.)."""
    data = request.get_json(silent=True) or {}
    action = data.get("action")
    payload = data.get("payload", "")
    allowed = {"speedtest", "bufferbloat", "traceroute", "wifiscan", "dns_benchmark", "mdnsscan", "lanscan", "mtuscan"}
    if action not in allowed:
        return jsonify({"error": f"Invalid action '{action}'. Allowed: {', '.join(allowed)}"}), 400

    ts = datetime.now().isoformat()
    conn = get_write_db()
    try:
        cur = conn.execute(
            "INSERT INTO action_queue (timestamp, action, payload, status) VALUES (?,?,?,?)",
            (ts, action, payload, "pending"),
        )
        conn.commit()
        action_id = cur.lastrowid
        return jsonify({"id": action_id, "status": "pending", "action": action}), 202
    finally:
        conn.close()


@app.route("/api/actions/latest")
def api_latest_actions():
    rows = query("SELECT * FROM action_queue ORDER BY id DESC LIMIT 5")
    return jsonify(rows)


@app.route("/api/incidents/<filename>")
def api_incident_content(filename: str):
    """Return the text content of a single incident file safely."""
    if not filename.startswith("incident_") or not filename.endswith(".txt"):
        return jsonify({"error": "Invalid filename"}), 400
    target = (Path(INCIDENTS_PATH) / filename).resolve()
    inc_dir = Path(INCIDENTS_PATH).resolve()
    if not target.is_relative_to(inc_dir) or not target.is_file():
        return jsonify({"error": "Not found"}), 404
    return Response(target.read_text(encoding="utf-8", errors="replace"),
                    mimetype="text/plain")


@app.route("/api/status")
def api_status():
    """DB size, total sample count, and most recent sample timestamp."""
    size = Path(DB_PATH).stat().st_size if Path(DB_PATH).exists() else 0
    rows = query("SELECT COUNT(*) AS cnt, MAX(timestamp) AS last FROM samples")
    r = rows[0] if rows else {"cnt": 0, "last": None}
    return jsonify({
        "db_size_bytes": size,
        "sample_count":  r["cnt"],
        "last_sample":   r["last"],
    })


# ---------------------------------------------------------------------------
# Dashboard HTML Template
# ---------------------------------------------------------------------------

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Network Observability Monitor</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js"></script>
<style>
  *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'Segoe UI',system-ui,sans-serif;background:#0f1117;color:#e2e8f0;padding:20px}
  h1{font-size:1.3rem;font-weight:600;color:#f8fafc;margin-bottom:20px}
  h2{font-size:0.75rem;font-weight:600;color:#64748b;text-transform:uppercase;letter-spacing:.1em;margin-bottom:12px;display:flex;align-items:center}

  /* Navigation Tabs */
  .nav-tabs{display:flex;gap:8px;margin-bottom:16px;background:#161926;border:1px solid #2d3248;border-radius:10px;padding:6px;flex-wrap:wrap}
  .nav-tab{background:none;border:none;color:#94a3b8;font-size:.82rem;font-weight:600;padding:8px 16px;border-radius:6px;cursor:pointer;transition:all .15s ease}
  .nav-tab:hover{color:#f8fafc;background:#1e2130}
  .nav-tab.active{background:#2563eb;color:#ffffff;box-shadow:0 0 10px rgba(37,99,235,.4)}

  /* Time range pills */
  .range-btn{background:#0f1117;color:#94a3b8;border:1px solid #2d3248;border-radius:4px;padding:4px 10px;font-size:.72rem;font-weight:600;cursor:pointer;transition:all 0.15s ease}
  .range-btn:hover{color:#fff;border-color:#38bdf8}
  .range-btn.active{background:#1e3a5f;color:#7dd3fc;border-color:#2d6a9f}

  /* Tab pages */
  .tab-pane{display:none}
  .tab-pane.active{display:block}

  /* Status bar */
  .sbar{background:#1e2130;border:1px solid #2d3248;border-radius:8px;padding:10px 14px;
    margin-bottom:16px;display:flex;align-items:center;gap:10px;font-size:.85rem;flex-wrap:wrap}
  .dot{width:10px;height:10px;border-radius:50%;flex-shrink:0}
  .dot.ok{background:#34d399;box-shadow:0 0 6px #34d399}
  .dot.warn{background:#fbbf24;box-shadow:0 0 6px #fbbf24}
  .dot.error{background:#f87171;box-shadow:0 0 6px #f87171}
  .dot.stale{background:#94a3b8;box-shadow:0 0 6px #94a3b8}
  .sbar-right{margin-left:auto;display:flex;gap:16px;font-size:.72rem;color:#64748b}

  /* Metrics grid */
  .mgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin-bottom:16px}
  .metric{background:#1e2130;border:1px solid #2d3248;border-radius:8px;padding:12px}
  .metric .lbl{font-size:.7rem;color:#64748b;margin-bottom:4px}
  .metric .val{font-size:1.35rem;font-weight:700;font-variant-numeric:tabular-nums}
  .metric .unit{font-size:.7rem;color:#64748b;margin-left:2px}
  .ok{color:#34d399}.warn{color:#fbbf24}.error{color:#f87171}.dim{color:#94a3b8}

  /* Cards */
  .card{background:#1e2130;border:1px solid #2d3248;border-radius:8px;padding:16px;margin-bottom:16px}
  .chart-wrap{position:relative;height:190px}
  .two-col{display:grid;grid-template-columns:1fr 1fr;gap:16px}
  @media(max-width:850px){.two-col{grid-template-columns:1fr}}

  /* Tables */
  table{width:100%;border-collapse:collapse;font-size:.76rem}
  th{text-align:left;color:#64748b;font-weight:500;padding:6px 8px;border-bottom:1px solid #2d3248}
  td{padding:6px 8px;border-bottom:1px solid #1a1f2e;font-variant-numeric:tabular-nums}
  tr:last-child td{border-bottom:none}
  tr:hover td{background:#252a3a}
  .mono{font-family:monospace;font-size:.72rem}

  /* Badges */
  .badge{display:inline-block;padding:2px 7px;border-radius:99px;font-size:.66rem;font-weight:600;white-space:nowrap}
  .b-err{background:#450a0a;color:#f87171}  .b-warn{background:#422006;color:#fbbf24}
  .b-ok{background:#052e16;color:#34d399}   .b-info{background:#0c1a2e;color:#7dd3fc}
  .b-wifi{background:#1a0c2e;color:#c4b5fd} .b-net{background:#0c1a1a;color:#6ee7b7}
  .b-sys{background:#1a1a0c;color:#fde68a}

  /* Wi-Fi signal bar */
  .sig-bar{height:5px;background:#2d3248;border-radius:3px;margin-top:5px}
  .sig-fill{height:100%;border-radius:3px}

  /* Incident content expandable */
  .incident-content{display:none;margin-top:8px;background:#0f1117;border:1px solid #2d3248;
    border-radius:4px;padding:10px;font-family:monospace;font-size:.7rem;white-space:pre-wrap;
    color:#94a3b8;max-height:300px;overflow-y:auto}
  .incident-content.open{display:block}
  .expand-btn{cursor:pointer;color:#38bdf8;font-size:.72rem;text-decoration:underline;
    background:none;border:none;padding:0}

  .note{font-size:.7rem;color:#475569;margin-bottom:16px}

  /* Progress bar for CPU/RAM */
  .pbar{height:4px;background:#2d3248;border-radius:2px;margin-top:4px}
  .pbar-fill{height:100%;border-radius:2px}

  /* Action buttons */
  .act-btn{background:#1e3a5f;color:#7dd3fc;border:1px solid #2d6a9f;border-radius:6px;padding:6px 14px;font-size:.78rem;font-weight:600;cursor:pointer;transition:all 0.15s ease}
  .act-btn:hover{background:#2563eb;color:#ffffff}
  .act-btn:disabled{background:#1a202c;color:#64748b;border-color:#2d3748;cursor:not-allowed}
  .spinner{display:inline-block;width:12px;height:12px;border:2px solid rgba(255,255,255,.3);border-radius:50%;border-top-color:#fff;animation:spin 1s ease-in-out infinite;margin-right:6px}
  @keyframes spin{to{transform:rotate(360deg)}}
</style>
</head>
<body>
<div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;margin-bottom:16px">
  <h1 style="margin-bottom:0">&#x1F4E1; Network Observability Monitor</h1>
  <div style="font-size:0.75rem;color:#64748b">Unified Windows Observability Suite</div>
</div>

<!-- Tab Navigation Bar -->
<div class="nav-tabs">
  <button class="nav-tab active" onclick="setTab('telemetry', this)">&#128202; Telemetry</button>
  <button class="nav-tab" onclick="setTab('lan', this)">&#127760; LAN &amp; Devices</button>
  <button class="nav-tab" onclick="setTab('wifi', this)">&#128246; Wi-Fi &amp; RF</button>
  <button class="nav-tab" onclick="setTab('diagnostics', this)">&#128300; Diagnostics</button>
  <button class="nav-tab" onclick="setTab('events', this)">&#128220; Events &amp; Export</button>
  <button class="nav-tab" onclick="setTab('all', this)">&#128193; All Panels</button>
</div>

<!-- Status bar -->
<div class="sbar">
  <div class="dot" id="dot"></div>
  <span id="statusText">Loading&hellip;</span>
  <div class="sbar-right">
    <span id="staleWarn" style="display:none;color:#f87171">&#9888; Monitor may be offline</span>
    <span id="dbSize">DB: &mdash;</span>
    <span id="sampleCount">Samples: &mdash;</span>
    <span id="updated">&mdash;</span>
  </div>
</div>

<!-- Quick Actions Panel -->
<div class="card" style="margin-bottom:16px">
  <h2>&#9889; On-Demand Actions</h2>
  <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">
    <button class="act-btn" id="btnSpeed" onclick="triggerAction('speedtest', this)">&#128640; Speed Test</button>
    <button class="act-btn" id="btnBloat" onclick="triggerAction('bufferbloat', this)">&#128200; Bufferbloat</button>
    <button class="act-btn" id="btnLanScan" onclick="triggerAction('lanscan', this)">&#127760; Scan LAN</button>
    <button class="act-btn" id="btnMdnsScan" onclick="triggerAction('mdnsscan', this)">&#128251; Scan mDNS</button>
    <button class="act-btn" id="btnMtuScan" onclick="triggerAction('mtuscan', this)">&#128207; Path MTU</button>
    <button class="act-btn" id="btnScan" onclick="triggerAction('wifiscan', this)">&#128246; Scan Wi-Fi</button>
    <button class="act-btn" id="btnDns" onclick="triggerAction('dns_benchmark', this)">&#128269; DNS Benchmark</button>
    <div style="display:flex;gap:4px;align-items:center;margin-left:auto">
      <input id="traceTarget" type="text" placeholder="1.1.1.1" value="1.1.1.1" style="background:#0f1117;color:#e2e8f0;border:1px solid #2d3248;border-radius:4px;padding:6px 8px;font-size:.78rem;width:120px">
      <button class="act-btn" onclick="triggerTraceroute(this)">&#127937; Traceroute</button>
    </div>
  </div>
  <div id="actionStatus" style="font-size:0.75rem;color:#7dd3fc;margin-top:10px;display:none"></div>
</div>

<!-- ========================================================================= -->
<!-- PANE: TELEMETRY -->
<!-- ========================================================================= -->
<div id="pane-telemetry" class="tab-pane active">
  <!-- Metrics Grid -->
  <div class="mgrid">
    <div class="metric"><div class="lbl">Internet Ping</div>
      <div><span class="val" id="mPing">--</span><span class="unit">ms</span></div></div>
    <div class="metric"><div class="lbl">Gateway Ping</div>
      <div><span class="val" id="mGw">--</span><span class="unit">ms</span></div></div>
    <div class="metric"><div class="lbl">DNS Resolver</div>
      <div><span class="val" id="mDns">--</span><span class="unit">ms</span></div></div>
    <div class="metric"><div class="lbl">DNS Server (UDP)</div>
      <div><span class="val" id="mDnsSrv">--</span><span class="unit">ms</span></div></div>
    <div class="metric"><div class="lbl">HTTP Response</div>
      <div><span class="val" id="mHttp">--</span><span class="unit">ms</span></div></div>
    <div class="metric"><div class="lbl">Packet Loss</div>
      <div><span class="val" id="mLoss">--</span><span class="unit">%</span></div></div>
    <div class="metric"><div class="lbl">CPU</div>
      <div><span class="val" id="mCpu">--</span><span class="unit">%</span></div>
      <div class="pbar"><div class="pbar-fill" id="cpuBar" style="width:0%;background:#38bdf8"></div></div>
    </div>
    <div class="metric"><div class="lbl">RAM</div>
      <div><span class="val" id="mRam">--</span><span class="unit">%</span></div>
      <div class="pbar"><div class="pbar-fill" id="ramBar" style="width:0%;background:#818cf8"></div></div>
    </div>
    <div class="metric"><div class="lbl">Probe Duration</div>
      <div><span class="val" id="mProbe">--</span><span class="unit">ms</span></div></div>
    <div class="metric"><div class="lbl">Probed Host</div>
      <div class="val dim" id="mHost" style="font-size:.8rem;margin-top:3px">--</div></div>
    <div class="metric"><div class="lbl">IP Address</div>
      <div class="val dim" id="mIp" style="font-size:.8rem;margin-top:3px">--</div></div>
    <div class="metric"><div class="lbl">DNS Server</div>
      <div class="val dim" id="mDnsSrvIp" style="font-size:.8rem;margin-top:3px">--</div></div>
    <div class="metric" style="grid-column:span 2">
      <div class="lbl">Active Interface</div>
      <div class="val dim" id="mActiveIface" style="font-size:.85rem;margin-top:3px">--</div>
    </div>
  </div>

  <!-- Time Range Selector -->
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;margin-top:8px">
    <div style="font-size:0.75rem;font-weight:600;color:#64748b;text-transform:uppercase;letter-spacing:.05em">&#128337; History Range:</div>
    <div style="display:flex;gap:4px">
      <button class="range-btn active" onclick="setTimeRange(300, this)">5m</button>
      <button class="range-btn" onclick="setTimeRange(900, this)">15m</button>
      <button class="range-btn" onclick="setTimeRange(3600, this)">1h</button>
      <button class="range-btn" onclick="setTimeRange(21600, this)">6h</button>
      <button class="range-btn" onclick="setTimeRange(86400, this)">24h</button>
    </div>
  </div>

  <!-- Latency + DNS/HTTP -->
  <div class="two-col">
    <div class="card"><h2>Latency History</h2>
      <div class="chart-wrap"><canvas id="cLatency"></canvas></div></div>
    <div class="card"><h2>DNS &amp; HTTP</h2>
      <div class="chart-wrap"><canvas id="cDnsHttp"></canvas></div></div>
  </div>

  <!-- DNS comparison + Packet loss -->
  <div class="two-col">
    <div class="card"><h2>DNS Resolver vs Server (UDP)</h2>
      <div class="chart-wrap"><canvas id="cDnsCmp"></canvas></div></div>
    <div class="card"><h2>Packet Loss Rate</h2>
      <div class="chart-wrap"><canvas id="cLoss"></canvas></div></div>
  </div>

  <!-- CPU/RAM + Interface activity timeline -->
  <div class="two-col">
    <div class="card"><h2>CPU &amp; RAM</h2>
      <div class="chart-wrap"><canvas id="cSys"></canvas></div></div>
    <div class="card">
      <h2>Interface Activity Timeline <span id="ifaceNote" style="font-weight:400;color:#475569;text-transform:none;font-size:0.72rem;margin-left:8px"></span></h2>
      <div class="chart-wrap"><canvas id="cIfaceTimeline"></canvas></div>
      <div id="ifaceList" style="margin-top:10px;display:flex;gap:12px;flex-wrap:wrap;font-size:.74rem"></div>
    </div>
  </div>

  <!-- NIC throughput + NIC errors -->
  <div class="two-col">
    <div class="card"><h2>NIC Throughput (Active Adapters)</h2>
      <div class="chart-wrap"><canvas id="cNic"></canvas></div></div>
    <div class="card"><h2>NIC Errors &amp; Drops</h2>
      <div class="chart-wrap"><canvas id="cNicErr"></canvas></div></div>
  </div>

  <!-- TCP states -->
  <div class="card">
    <h2>TCP Connection States (Current)</h2>
    <div class="chart-wrap" style="height:140px"><canvas id="cTcp"></canvas></div>
  </div>
</div>

<!-- ========================================================================= -->
<!-- PANE: LAN & DEVICES -->
<!-- ========================================================================= -->
<div id="pane-lan" class="tab-pane">
  <!-- Network Hogs -->
  <div class="card">
    <h2>&#128187; Top Network Applications (Network Hogs)</h2>
    <table>
      <thead><tr><th>Application</th><th>PID</th><th>Connections</th><th>Download</th><th>Upload</th></tr></thead>
      <tbody id="tProcesses"><tr><td colspan="5" class="dim">Sampling processes&hellip;</td></tr></tbody>
    </table>
  </div>

  <!-- LAN ARP Neighbor Devices -->
  <div class="card">
    <h2>&#127760; LAN ARP Neighbor Devices <span id="lanCount" class="badge b-info" style="margin-left:8px">Scanning...</span></h2>
    <table>
      <thead>
        <tr>
          <th>IP Address</th>
          <th>MAC Address</th>
          <th>Vendor / Manufacturer</th>
          <th>Adapter Interface</th>
          <th>Device Type</th>
          <th>Last Seen</th>
        </tr>
      </thead>
      <tbody id="tLan"><tr><td colspan="6" class="dim">Loading LAN neighbor table&hellip;</td></tr></tbody>
    </table>
  </div>

  <!-- mDNS / Bonjour / ZeroConf Devices -->
  <div class="card">
    <h2>&#128251; Discovered mDNS / Bonjour / ZeroConf Devices <span id="mdnsCount" class="badge b-info" style="margin-left:8px">Listening...</span></h2>
    <table>
      <thead>
        <tr>
          <th>IP Address</th>
          <th>Hostname (.local)</th>
          <th>Advertised Services / Device Info</th>
          <th>Last Seen</th>
        </tr>
      </thead>
      <tbody id="tMdns"><tr><td colspan="4" class="dim">Listening for mDNS multicast broadcasts (224.0.0.251:5353)&hellip;</td></tr></tbody>
    </table>
  </div>
</div>

<!-- ========================================================================= -->
<!-- PANE: WI-FI & RF -->
<!-- ========================================================================= -->
<div id="pane-wifi" class="tab-pane">
  <!-- Wi-Fi live panel -->
  <div class="card">
    <h2>Wi-Fi Current Link</h2>
    <div style="display:flex;gap:20px;flex-wrap:wrap">
      <div><div class="lbl">SSID</div><div class="val dim" id="wSSID" style="font-size:.95rem">--</div></div>
      <div><div class="lbl">BSSID</div><div class="val dim mono" id="wBSSID" style="font-size:.8rem;margin-top:3px">--</div></div>
      <div style="min-width:120px">
        <div class="lbl">Signal</div>
        <div class="val dim" id="wSignal" style="font-size:.95rem">--%</div>
        <div class="sig-bar"><div class="sig-fill" id="wSigFill" style="width:0%"></div></div>
      </div>
      <div><div class="lbl">Band / Ch</div><div class="val dim" id="wBand" style="font-size:.85rem;margin-top:3px">--</div></div>
      <div><div class="lbl">Rx / Tx</div><div class="val dim" id="wRates" style="font-size:.82rem;margin-top:3px">--</div></div>
      <div><div class="lbl">Auth</div><div class="val dim" id="wAuth" style="font-size:.8rem;margin-top:3px">--</div></div>
    </div>
  </div>

  <!-- Wi-Fi signal chart -->
  <div class="card">
    <h2>Wi-Fi Signal History</h2>
    <div class="chart-wrap"><canvas id="cWifi"></canvas></div>
  </div>

  <!-- Wi-Fi Channel Overlap & Congestion -->
  <div class="card">
    <h2>&#128246; Wi-Fi Channel Overlap &amp; Congestion <span id="wifiChanRec" class="badge b-ok" style="margin-left:8px"></span></h2>
    <div class="two-col" style="margin-top:10px">
      <div>
        <h3 style="font-size:.72rem;color:#94a3b8;margin-bottom:6px">2.4 GHz Spectrum (Channels 1&ndash;13)</h3>
        <div class="chart-wrap" style="height:150px"><canvas id="cChan24"></canvas></div>
      </div>
      <div>
        <h3 style="font-size:.72rem;color:#94a3b8;margin-bottom:6px">5 GHz Spectrum Channels</h3>
        <div class="chart-wrap" style="height:150px"><canvas id="cChan5"></canvas></div>
      </div>
    </div>
  </div>

  <!-- Wi-Fi environment scan -->
  <div class="card">
    <h2>Wi-Fi Environment Scan <span id="scanAge" style="font-weight:400;color:#475569;text-transform:none;font-size:0.72rem;margin-left:8px"></span></h2>
    <table>
      <thead>
        <tr>
          <th>SSID</th>
          <th>BSSID</th>
          <th>Signal</th>
          <th>Ch</th>
          <th>Band</th>
          <th>Auth</th>
          <th>Cipher</th>
        </tr>
      </thead>
      <tbody id="tScan"><tr><td colspan="7" class="dim">Waiting for first scan&hellip;</td></tr></tbody>
    </table>
  </div>
</div>

<!-- ========================================================================= -->
<!-- PANE: DIAGNOSTICS -->
<!-- ========================================================================= -->
<div id="pane-diagnostics" class="tab-pane">
  <!-- Multi-DNS Benchmark -->
  <div class="card">
    <h2>&#127760; Multi-DNS Latency Benchmark <span id="dnsBenchFastest" class="badge b-ok" style="margin-left:8px"></span></h2>
    <div class="mgrid" style="grid-template-columns:repeat(auto-fit,minmax(120px,1fr));margin-bottom:8px">
      <div class="metric"><div class="lbl">Local ISP DNS</div><div><span class="val" id="dLocal">--</span><span class="unit">ms</span></div></div>
      <div class="metric"><div class="lbl">Cloudflare (1.1.1.1)</div><div><span class="val" id="dCf">--</span><span class="unit">ms</span></div></div>
      <div class="metric"><div class="lbl">Google (8.8.8.8)</div><div><span class="val" id="dGoog">--</span><span class="unit">ms</span></div></div>
      <div class="metric"><div class="lbl">Quad9 (9.9.9.9)</div><div><span class="val" id="dQuad">--</span><span class="unit">ms</span></div></div>
    </div>
    <div id="dnsRecommendation" style="font-size:0.75rem;color:#7dd3fc;margin-top:6px"></div>
  </div>

  <!-- Path MTU & Gateway Diagnostics -->
  <div class="card">
    <h2>&#128207; Path MTU &amp; Packet Fragmentation Diagnostics</h2>
    <div class="mgrid" style="grid-template-columns:repeat(auto-fit,minmax(130px,1fr));margin-bottom:12px">
      <div class="metric"><div class="lbl">Probed Target</div><div class="val dim" id="mtuTarget" style="font-size:1.1rem">--</div></div>
      <div class="metric"><div class="lbl">Path MTU</div><div><span class="val" id="mtuVal">--</span><span class="unit">bytes</span></div></div>
      <div class="metric"><div class="lbl">Max ICMP Payload</div><div><span class="val" id="mtuPayload">--</span><span class="unit">bytes</span></div></div>
      <div class="metric"><div class="lbl">Fragmentation</div><div class="val" id="mtuFrag" style="font-size:1.1rem">--</div></div>
      <div class="metric" style="grid-column:span 2"><div class="lbl">Diagnostic Analysis</div><div class="val dim" id="mtuNotes" style="font-size:.82rem;margin-top:2px">--</div></div>
    </div>
    <table>
      <thead><tr><th>Time</th><th>Target Host</th><th>Path MTU</th><th>Payload</th><th>Status</th><th>Diagnostic Notes</th></tr></thead>
      <tbody id="tMtu"><tr><td colspan="6" class="dim">Run MTU probe via On-Demand Actions or wait for schedule&hellip;</td></tr></tbody>
    </table>
  </div>

  <!-- Bufferbloat -->
  <div class="card">
    <h2>Bufferbloat History</h2>
    <table>
      <thead><tr><th>Time</th><th>Rating</th><th>Baseline</th><th>Loaded</th><th>Delta</th><th>Download</th><th>Host</th></tr></thead>
      <tbody id="tBloat"><tr><td colspan="7" class="dim">Waiting for first scan (runs every 5 min)&hellip;</td></tr></tbody>
    </table>
  </div>

  <!-- Speed test -->
  <div class="card">
    <h2>Speed Test History <span id="speedAge" style="font-weight:400;color:#475569;text-transform:none;font-size:0.72rem;margin-left:8px"></span></h2>
    <div class="two-col" style="margin-bottom:14px">
      <div class="chart-wrap" style="height:160px"><canvas id="cSpeedDl"></canvas></div>
      <div class="chart-wrap" style="height:160px"><canvas id="cSpeedUl"></canvas></div>
    </div>
    <table>
      <thead><tr><th>Time</th><th>Download</th><th>Upload</th><th>Duration</th></tr></thead>
      <tbody id="tSpeed"><tr><td colspan="4" class="dim">Waiting for first test (runs every 15 min)&hellip;</td></tr></tbody>
    </table>
  </div>
</div>

<!-- ========================================================================= -->
<!-- PANE: EVENTS & EXPORT -->
<!-- ========================================================================= -->
<div id="pane-events" class="tab-pane">
  <!-- Events + Incidents -->
  <div class="two-col">
    <div class="card"><h2>Recent Events</h2>
      <table><thead><tr><th>Time</th><th>Cat</th><th>Message</th></tr></thead>
      <tbody id="tEvents"><tr><td colspan="3" class="dim">Loading&hellip;</td></tr></tbody></table>
    </div>
    <div class="card"><h2>Diagnostic Incidents</h2>
      <table><thead><tr><th>File</th><th>Size</th><th>Time</th></tr></thead>
      <tbody id="tIncidents"><tr><td colspan="3" class="dim">Loading&hellip;</td></tr></tbody></table>
    </div>
  </div>

  <!-- Export Data -->
  <div class="card">
    <h2>Export Telemetry &amp; Discovery Data</h2>
    <div style="display:flex;gap:12px;flex-wrap:wrap;align-items:flex-end">
      <div>
        <div class="lbl" style="margin-bottom:4px">Table</div>
        <select id="expTable" style="background:#0f1117;color:#e2e8f0;border:1px solid #2d3248;border-radius:4px;padding:5px 8px;font-size:.8rem">
          <option value="samples">samples (Core telemetry)</option>
          <option value="lan_devices">lan_devices (ARP Neighbors)</option>
          <option value="mdns_devices">mdns_devices (mDNS ZeroConf)</option>
          <option value="mtu_samples">mtu_samples (Path MTU)</option>
          <option value="process_samples">process_samples (Network Hogs)</option>
          <option value="dns_benchmarks">dns_benchmarks (Multi-DNS)</option>
          <option value="wifi_samples">wifi_samples (Wi-Fi Link)</option>
          <option value="wifi_scan_results">wifi_scan_results (RF Scan)</option>
          <option value="nic_samples">nic_samples (NIC Throughput)</option>
          <option value="tcp_states">tcp_states (TCP Connections)</option>
          <option value="bufferbloat_samples">bufferbloat_samples</option>
          <option value="speed_test_results">speed_test_results</option>
          <option value="events">events</option>
          <option value="action_queue">action_queue</option>
        </select>
      </div>
      <div>
        <div class="lbl" style="margin-bottom:4px">From</div>
        <input id="expFrom" type="datetime-local" style="background:#0f1117;color:#e2e8f0;border:1px solid #2d3248;border-radius:4px;padding:5px 8px;font-size:.8rem">
      </div>
      <div>
        <div class="lbl" style="margin-bottom:4px">To</div>
        <input id="expTo" type="datetime-local" style="background:#0f1117;color:#e2e8f0;border:1px solid #2d3248;border-radius:4px;padding:5px 8px;font-size:.8rem">
      </div>
      <div>
        <div class="lbl" style="margin-bottom:4px">Format</div>
        <select id="expFmt" style="background:#0f1117;color:#e2e8f0;border:1px solid #2d3248;border-radius:4px;padding:5px 8px;font-size:.8rem">
          <option value="csv">CSV</option><option value="json">JSON</option>
        </select>
      </div>
      <button onclick="doExport()" class="act-btn">Download</button>
    </div>
  </div>
</div>

<script>
// ---------------------------------------------------------------------------
// Chart Factory & Global Settings
// ---------------------------------------------------------------------------
const G = { text:'#94a3b8', grid:'#1a1f2e' };

function mkChart(id, datasets, yLabel, type='line') {
  return new Chart(document.getElementById(id).getContext('2d'), {
    type,
    data: { labels: [], datasets },
    options: {
      responsive:true, maintainAspectRatio:false, animation:false,
      plugins:{ legend:{ labels:{ color:G.text, font:{size:10} } } },
      scales:{
        x:{ ticks:{ color:G.text, maxTicksLimit:6, font:{size:9} }, grid:{ color:G.grid } },
        y:{ ticks:{ color:G.text, font:{size:9} }, grid:{ color:G.grid }, beginAtZero:true,
            title: yLabel ? { display:true, text:yLabel, color:G.text, font:{size:9} } : undefined },
      },
    },
  });
}

function ds(label, color, fill=false) {
  const bg = color.replace('rgb(','rgba(').replace(')',',0.08)');
  return { label, data:[], borderColor:color, backgroundColor:bg,
           borderWidth:1.5, pointRadius:0, tension:0.2, fill };
}

const cLatency = mkChart('cLatency', [ds('Internet Ping','rgb(56,189,248)',true), ds('Gateway Ping','rgb(129,140,248)',true)], 'ms');
const cDnsHttp = mkChart('cDnsHttp', [ds('DNS Resolver','rgb(52,211,153)',true), ds('HTTP','rgb(251,191,36)',true)], 'ms');
const cDnsCmp  = mkChart('cDnsCmp',  [ds('Resolver','rgb(52,211,153)'), ds('Server UDP','rgb(251,113,133)')], 'ms');
const cLoss    = mkChart('cLoss',    [ds('Loss %','rgb(248,113,113)',true)], '%');
const cSys     = mkChart('cSys',     [ds('CPU %','rgb(56,189,248)'), ds('RAM %','rgb(129,140,248)')], '%');
const cWifi    = mkChart('cWifi',    [ds('Signal %','rgb(167,139,250)',true)], '%');
const cSpeedDl = mkChart('cSpeedDl', [ds('Download Mbps','rgb(52,211,153)',true)], 'Mbps');
const cSpeedUl = mkChart('cSpeedUl', [ds('Upload Mbps',  'rgb(251,191,36)',true)], 'Mbps');
const cChan24  = new Chart(document.getElementById('cChan24').getContext('2d'), {
  type:'bar',
  data:{ labels:['1','2','3','4','5','6','7','8','9','10','11','12','13'], datasets:[{ label:'APs on Channel', data:[], backgroundColor:'rgba(56,189,248,.6)' }] },
  options:{ responsive:true, maintainAspectRatio:false, animation:false, plugins:{ legend:{ display:false } }, scales:{ x:{ ticks:{ color:G.text, font:{size:9} }, grid:{ color:G.grid } }, y:{ ticks:{ color:G.text, stepSize:1, font:{size:9} }, grid:{ color:G.grid }, beginAtZero:true } } },
});
const cChan5   = new Chart(document.getElementById('cChan5').getContext('2d'), {
  type:'bar',
  data:{ labels:[], datasets:[{ label:'APs on Channel', data:[], backgroundColor:'rgba(167,139,250,.6)' }] },
  options:{ responsive:true, maintainAspectRatio:false, animation:false, plugins:{ legend:{ display:false } }, scales:{ x:{ ticks:{ color:G.text, font:{size:9} }, grid:{ color:G.grid } }, y:{ ticks:{ color:G.text, stepSize:1, font:{size:9} }, grid:{ color:G.grid }, beginAtZero:true } } },
});

const cNic    = mkChart('cNic',    [], 'KB/s');
const cNicErr = mkChart('cNicErr', [], '/s');
const cIfaceTimeline = mkChart('cIfaceTimeline', [], 'KB/s');

const NIC_COLOURS = [
  'rgb(52,211,153)', 'rgb(251,191,36)', 'rgb(56,189,248)',
  'rgb(248,113,113)','rgb(167,139,250)','rgb(251,146,60)',
];
const nicThroughputAdapters = new Set();
const nicErrorAdapters      = new Set();

function ensureNicDataset(chart, adapterSet, iface, suffix) {
  if (adapterSet.has(iface)) return;
  adapterSet.add(iface);
  const idx = adapterSet.size - 1;
  const colour = NIC_COLOURS[idx % NIC_COLOURS.length];
  chart.data.datasets.push(ds(`${iface} ${suffix}`, colour));
  chart.data.datasets[chart.data.datasets.length - 1].data = [];
}

const cTcp = new Chart(document.getElementById('cTcp').getContext('2d'), {
  type:'bar',
  data:{ labels:[''], datasets:[
    { label:'ESTABLISHED', data:[0], backgroundColor:'rgba(56,189,248,.7)' },
    { label:'TIME_WAIT',   data:[0], backgroundColor:'rgba(251,191,36,.7)'  },
    { label:'CLOSE_WAIT',  data:[0], backgroundColor:'rgba(248,113,113,.7)' },
    { label:'LISTEN',      data:[0], backgroundColor:'rgba(52,211,153,.5)'  },
    { label:'OTHER',       data:[0], backgroundColor:'rgba(148,163,184,.4)' },
  ]},
  options:{
    indexAxis:'y', responsive:true, maintainAspectRatio:false, animation:false,
    plugins:{ legend:{ labels:{ color:G.text, font:{size:10} } } },
    scales:{
      x:{ stacked:true, ticks:{ color:G.text, font:{size:9} }, grid:{ color:G.grid } },
      y:{ stacked:true, ticks:{ color:G.text, font:{size:9} }, grid:{ color:G.grid } },
    },
  },
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
const ts   = iso => iso ? iso.substring(11,19) : '';
const fmt  = (v,d=1) => (v==null) ? '—' : Number(v).toFixed(d);
const kb   = v => (v==null) ? null : v/1024;

function pingCls(ms) {
  if (ms==null) return 'error';
  return ms>500?'error':ms>150?'warn':'ok';
}
function lossCls(p) { return !p?'ok':p>10?'error':p>2?'warn':'ok'; }
function sysCls(p)  { return p>90?'error':p>70?'warn':'ok'; }
function probeCls(ms, interval) { return ms > interval*1000*0.8 ? 'warn' : 'ok'; }

function catBadge(cat) {
  return `<span class="badge ${{fault:'b-err',wifi:'b-wifi',network:'b-net',system:'b-sys',info:'b-info'}[cat]||'b-info'}">${cat}</span>`;
}
function statusFrom(notes) {
  if (!notes) return 'ok';
  return (notes.includes('packet_loss')||notes.includes('severe_latency')) ? 'error' : 'warn';
}
function upd(chart, labels, ...series) {
  chart.data.labels = labels;
  series.forEach((d,i) => chart.data.datasets[i].data = d);
  chart.update('none');
}

// ---------------------------------------------------------------------------
// Tab Switching & Time-Range Controls
// ---------------------------------------------------------------------------
let currentHistoryN = 300;

function setTab(name, btn) {
  document.querySelectorAll('.nav-tab').forEach(b => b.classList.remove('active'));
  if (btn) btn.classList.add('active');
  const panes = document.querySelectorAll('.tab-pane');
  if (name === 'all') {
    panes.forEach(p => p.style.display = 'block');
  } else {
    panes.forEach(p => {
      p.style.display = (p.id === 'pane-' + name) ? 'block' : 'none';
    });
  }
}

function setTimeRange(n, btn) {
  document.querySelectorAll('.range-btn').forEach(b => b.classList.remove('active'));
  if (btn) btn.classList.add('active');
  currentHistoryN = n;
  updateHistory();
  updateWifi();
  updateNic();
  updateIfaceTimeline();
}

// ---------------------------------------------------------------------------
// Stale Detection
// ---------------------------------------------------------------------------
let lastSampleTs = null;
function checkStale() {
  if (!lastSampleTs) return;
  const age = (Date.now() - new Date(lastSampleTs).getTime()) / 1000;
  const warn = document.getElementById('staleWarn');
  const dot  = document.getElementById('dot');
  if (age > 15) {
    warn.style.display = 'inline';
    dot.className = 'dot stale';
    document.getElementById('statusText').textContent =
      `Monitor offline or stalled (last sample ${Math.round(age)}s ago)`;
  } else {
    warn.style.display = 'none';
  }
}
setInterval(checkStale, 5000);

let pollInterval = 1.0;

// ---------------------------------------------------------------------------
// Telemetry & Metrics
// ---------------------------------------------------------------------------
async function updateStatus() {
  const r = await fetch('/api/status').catch(()=>null);
  if (!r?.ok) return;
  const d = await r.json();
  const mb = (d.db_size_bytes/1048576).toFixed(1);
  document.getElementById('dbSize').textContent      = `DB: ${mb} MB`;
  document.getElementById('sampleCount').textContent = `Samples: ${d.sample_count.toLocaleString()}`;
  if (d.last_sample) lastSampleTs = d.last_sample;
}

async function updateLatest() {
  const r = await fetch('/api/latest').catch(()=>null);
  if (!r?.ok) return;
  const d = await r.json();

  lastSampleTs = d.timestamp;

  const set = (id, val, cls) => {
    const el = document.getElementById(id);
    el.textContent = val;
    if (cls) el.className = `val ${cls}`;
  };
  set('mPing',   fmt(d.internet_ping),   pingCls(d.internet_ping));
  set('mGw',     fmt(d.gateway_ping),    pingCls(d.gateway_ping));
  set('mDns',    fmt(d.dns_ms),          pingCls(d.dns_ms));
  set('mDnsSrv', fmt(d.dns_server_ms),   pingCls(d.dns_server_ms));
  set('mHttp',   fmt(d.http_ms),         pingCls(d.http_ms));
  set('mLoss',   fmt(d.packet_loss_rate),lossCls(d.packet_loss_rate));
  set('mCpu',    fmt(d.cpu_pct),         sysCls(d.cpu_pct));
  set('mRam',    fmt(d.ram_pct),         sysCls(d.ram_pct));
  set('mProbe',  fmt(d.probe_duration_ms,0), probeCls(d.probe_duration_ms, pollInterval));
  document.getElementById('mHost').textContent    = d.probed_host  || '—';
  document.getElementById('mIp').textContent      = d.ip_address   || '—';
  document.getElementById('mDnsSrvIp').textContent= d.dns_server   || '—';
  document.getElementById('cpuBar').style.width   = `${d.cpu_pct||0}%`;
  document.getElementById('ramBar').style.width   = `${d.ram_pct||0}%`;

  const status = statusFrom(d.notes);
  const dot = document.getElementById('dot');
  if (!document.getElementById('staleWarn').style.display || document.getElementById('staleWarn').style.display === 'none') {
    dot.className = `dot ${status}`;
    document.getElementById('statusText').textContent =
      d.notes ? `Fault: ${d.notes}` : 'All network metrics within nominal thresholds';
  }
  document.getElementById('updated').textContent = `Updated ${new Date().toLocaleTimeString()}`;
}

async function updateHistory() {
  const r = await fetch(`/api/history?n=${currentHistoryN}`).catch(()=>null);
  if (!r?.ok) return;
  const rows = await r.json();
  const lbl = rows.map(r => ts(r.timestamp));
  upd(cLatency, lbl, rows.map(r=>r.internet_ping), rows.map(r=>r.gateway_ping));
  upd(cDnsHttp, lbl, rows.map(r=>r.dns_ms),        rows.map(r=>r.http_ms));
  upd(cDnsCmp,  lbl, rows.map(r=>r.dns_ms),        rows.map(r=>r.dns_server_ms));
  upd(cLoss,    lbl, rows.map(r=>r.packet_loss_rate));
  upd(cSys,     lbl, rows.map(r=>r.cpu_pct),       rows.map(r=>r.ram_pct));
}

// ---------------------------------------------------------------------------
// Wi-Fi Updates
// ---------------------------------------------------------------------------
async function updateWifi() {
  const r = await fetch(`/api/wifi?n=${currentHistoryN}`).catch(()=>null);
  if (!r?.ok) return;
  const rows = await r.json();
  if (!rows.length) return;
  upd(cWifi, rows.map(r=>ts(r.timestamp)), rows.map(r=>r.signal_pct));
  const w = rows[rows.length-1];
  document.getElementById('wSSID').textContent  = w.ssid    || '—';
  document.getElementById('wBSSID').textContent = w.bssid   || '—';
  document.getElementById('wSignal').textContent= w.signal_pct!=null ? `${w.signal_pct}%` : '—';
  document.getElementById('wSigFill').style.width= `${w.signal_pct||0}%`;
  const bc = w.signal_pct>70?'#34d399':w.signal_pct>40?'#fbbf24':'#f87171';
  document.getElementById('wSigFill').style.background = bc;
  document.getElementById('wBand').textContent  = `${w.band||'?'} / Ch ${w.channel||'?'}`;
  document.getElementById('wRates').textContent = `${fmt(w.rx_rate_mbps)} / ${fmt(w.tx_rate_mbps)} Mbps`;
  document.getElementById('wAuth').textContent  = w.auth || '—';
}

async function updateWifiChannels() {
  const r = await fetch('/api/wifi_channels').catch(()=>null);
  if (!r?.ok) return;
  const data = await r.json();
  if (data.recommendation_24) {
    document.getElementById('wifiChanRec').textContent = data.recommendation_24;
  }
  const c24Counts = [1,2,3,4,5,6,7,8,9,10,11,12,13].map(ch => data.channels_24[ch]?.count || 0);
  cChan24.data.datasets[0].data = c24Counts;
  cChan24.update('none');

  const ch5Keys = Object.keys(data.channels_5).sort((a,b) => Number(a)-Number(b));
  if (ch5Keys.length) {
    cChan5.data.labels = ch5Keys;
    cChan5.data.datasets[0].data = ch5Keys.map(k => data.channels_5[k].count);
    cChan5.update('none');
  }
}

async function updateWifiScan() {
  const r = await fetch('/api/wifi_scan').catch(()=>null);
  if (!r?.ok) return;
  const rows = await r.json();
  const tb = document.getElementById('tScan');

  if (!rows.length) {
    tb.innerHTML = '<tr><td colspan="7" class="dim">No scan data yet (runs every 60 s)</td></tr>';
    return;
  }

  const age = rows[0]?.scan_timestamp;
  if (age) {
    const secs = Math.round((Date.now() - new Date(age).getTime()) / 1000);
    document.getElementById('scanAge').textContent =
      `— last scan ${secs}s ago, ${rows.length} networks visible`;
  }

  const sigBar = (pct) => {
    if (pct == null) return '—';
    const colour = pct > 70 ? '#34d399' : pct > 40 ? '#fbbf24' : '#f87171';
    return `<div style="display:flex;align-items:center;gap:6px">
      <span style="font-variant-numeric:tabular-nums;min-width:32px">${pct}%</span>
      <div style="flex:1;height:5px;background:#2d3248;border-radius:3px;min-width:60px">
        <div style="width:${pct}%;height:100%;border-radius:3px;background:${colour}"></div>
      </div>
    </div>`;
  };

  tb.innerHTML = rows.map(r => `<tr>
    <td>${r.ssid || '<span style="color:#475569;font-style:italic">hidden</span>'}</td>
    <td class="mono">${r.bssid}</td>
    <td>${sigBar(r.signal_pct)}</td>
    <td>${r.channel ?? '—'}</td>
    <td>${r.band   ?? '—'}</td>
    <td>${r.authentication ?? '—'}</td>
    <td>${r.cipher ?? '—'}</td>
  </tr>`).join('');
}

// ---------------------------------------------------------------------------
// NIC & Interface Updates
// ---------------------------------------------------------------------------
async function updateNic() {
  const r = await fetch(`/api/nic?n=${currentHistoryN}`).catch(()=>null);
  if (!r?.ok) return;
  const rows = await r.json();
  if (!rows.length) return;

  const allIfaces = [...new Set(rows.map(r => r.interface))];
  const activeIfaces = allIfaces.filter(iface => {
    const ifRows = rows.filter(r => r.interface === iface);
    const peak = Math.max(...ifRows.map(r => (r.bytes_recv_ps||0)+(r.bytes_sent_ps||0)));
    return peak > 1024;
  });

  if (!activeIfaces.length) return;

  const labels = rows
    .filter(r => r.interface === activeIfaces[0])
    .map(r => ts(r.timestamp));

  activeIfaces.forEach(iface => {
    ensureNicDataset(cNic,    nicThroughputAdapters, iface, 'KB/s');
    ensureNicDataset(cNicErr, nicErrorAdapters,      iface, 'err/s');
  });

  cNic.data.labels    = labels;
  cNicErr.data.labels = labels;

  const ifaceArr = [...nicThroughputAdapters];
  ifaceArr.forEach((iface, i) => {
    const ifRows = rows.filter(r => r.interface === iface);
    cNic.data.datasets[i].data =
      ifRows.map(r => kb((r.bytes_recv_ps||0) + (r.bytes_sent_ps||0)));
    cNicErr.data.datasets[i].data =
      ifRows.map(r => (r.errin_ps||0)+(r.errout_ps||0)+
                      (r.dropin_ps||0)+(r.dropout_ps||0));
  });

  cNic.update('none');
  cNicErr.update('none');
}

async function updateNicActive() {
  const r = await fetch('/api/nic/active').catch(()=>null);
  if (!r?.ok) return;
  const d = await r.json();

  const el = document.getElementById('mActiveIface');
  if (d.active) {
    el.textContent = d.active;
    el.className = 'val ok';
  } else {
    el.textContent = '—';
    el.className = 'val dim';
  }

  const list = document.getElementById('ifaceList');
  if (!d.interfaces?.length) { list.innerHTML = ''; return; }

  list.innerHTML = d.interfaces.map((iface, i) => {
    const isActive = i === 0 && iface.total_bps > 1024;
    const colour   = isActive ? '#34d399' : '#64748b';
    return `<div style="color:${colour}">
      ${isActive ? '▶ ' : ''}<strong>${iface.interface}</strong>
      &nbsp;↓${(iface.bytes_recv_ps/1024).toFixed(1)}
      &nbsp;↑${(iface.bytes_sent_ps/1024).toFixed(1)} KB/s
    </div>`;
  }).join('');
}

const timelineAdapters = new Set();
async function updateIfaceTimeline() {
  const r = await fetch(`/api/nic/timeline?n=${currentHistoryN}`).catch(()=>null);
  if (!r?.ok) return;
  const data = await r.json();

  const ifaces = Object.keys(data);
  if (!ifaces.length) return;

  const labels = (data[ifaces[0]] || []).map(s => ts(s.timestamp));
  ifaces.forEach(iface => {
    if (!timelineAdapters.has(iface)) {
      timelineAdapters.add(iface);
      const idx    = timelineAdapters.size - 1;
      const colour = NIC_COLOURS[idx % NIC_COLOURS.length];
      cIfaceTimeline.data.datasets.push(ds(iface, colour));
    }
  });

  cIfaceTimeline.data.labels = labels;
  const ifaceArr = [...timelineAdapters];
  ifaceArr.forEach((iface, i) => {
    const samples = data[iface] || [];
    cIfaceTimeline.data.datasets[i].data = samples.map(s => kb(s.total_bps));
  });

  cIfaceTimeline.update('none');
  document.getElementById('ifaceNote').textContent =
    `— ${ifaces.length} adapter${ifaces.length !== 1 ? 's' : ''}`;
}

async function updateTcp() {
  const r = await fetch('/api/tcp?n=1').catch(()=>null);
  if (!r?.ok) return;
  const rows = await r.json();
  if (!rows.length) return;
  const t = rows[rows.length-1];
  cTcp.data.datasets[0].data = [t.established||0];
  cTcp.data.datasets[1].data = [t.time_wait||0];
  cTcp.data.datasets[2].data = [t.close_wait||0];
  cTcp.data.datasets[3].data = [t.listen||0];
  cTcp.data.datasets[4].data = [(t.syn_sent||0)+(t.syn_recv||0)+(t.fin_wait1||0)+
    (t.fin_wait2||0)+(t.closing||0)+(t.last_ack||0)+(t.other||0)];
  cTcp.update('none');
}

// ---------------------------------------------------------------------------
// Network Hogs, LAN Neighbors & mDNS Discovery
// ---------------------------------------------------------------------------
async function updateProcesses() {
  const r = await fetch('/api/processes').catch(()=>null);
  if (!r?.ok) return;
  const rows = await r.json();
  const tb = document.getElementById('tProcesses');
  if (!rows.length) {
    tb.innerHTML = '<tr><td colspan="5" class="dim">No network-active applications detected</td></tr>';
    return;
  }
  tb.innerHTML = rows.map(p => `<tr>
    <td style="font-weight:600;color:#f8fafc">${p.name}</td>
    <td class="mono" style="color:#64748b">${p.pid}</td>
    <td>${p.conn_count} conn${p.conn_count !== 1 ? 's' : ''}</td>
    <td style="color:#34d399">&darr; ${(p.read_bytes_ps/1024).toFixed(1)} KB/s</td>
    <td style="color:#fbbf24">&uarr; ${(p.write_bytes_ps/1024).toFixed(1)} KB/s</td>
  </tr>`).join('');
}

async function updateLanDevices() {
  const r = await fetch('/api/lan_devices?n=200').catch(()=>null);
  if (!r?.ok) return;
  const rows = await r.json();
  const tb = document.getElementById('tLan');
  document.getElementById('lanCount').textContent = `${rows.length} devices detected`;

  if (!rows.length) {
    tb.innerHTML = '<tr><td colspan="6" class="dim">No LAN devices discovered yet</td></tr>';
    return;
  }

  tb.innerHTML = rows.map(d => {
    const isGw = (d.device_type === 'gateway');
    const typeBadge = isGw ? '<span class="badge b-err">Gateway / Router</span>' : '<span class="badge b-info">LAN Host</span>';
    const vendorBadge = d.vendor ? `<span class="badge b-net">${d.vendor}</span>` : '<span style="color:#64748b">Unknown OUI</span>';
    return `<tr>
      <td class="mono" style="font-weight:600;color:#f8fafc">${d.ip_address}</td>
      <td class="mono" style="color:#94a3b8">${d.mac_address}</td>
      <td>${vendorBadge}</td>
      <td class="mono" style="color:#64748b">${d.interface_ip || '—'}</td>
      <td>${typeBadge}</td>
      <td style="color:#64748b">${d.last_seen ? d.last_seen.substring(11,19) : '—'}</td>
    </tr>`;
  }).join('');
}

async function updateMdns() {
  const r = await fetch('/api/mdns?n=100').catch(()=>null);
  if (!r?.ok) return;
  const rows = await r.json();
  const tb = document.getElementById('tMdns');
  document.getElementById('mdnsCount').textContent = `${rows.length} active announcements`;

  if (!rows.length) {
    tb.innerHTML = '<tr><td colspan="4" class="dim">Listening for mDNS ZeroConf announcements&hellip;</td></tr>';
    return;
  }

  tb.innerHTML = rows.map(m => {
    const srvBadges = (m.services || '').split(',').filter(Boolean).map(s =>
      `<span class="badge b-wifi">${s.trim()}</span>`
    ).join(' ') || '<span style="color:#64748b">Device Announcement</span>';

    return `<tr>
      <td class="mono" style="font-weight:600;color:#f8fafc">${m.ip_address}</td>
      <td class="mono" style="color:#38bdf8">${m.hostname || '—'}</td>
      <td>${srvBadges}</td>
      <td style="color:#64748b">${m.last_seen ? m.last_seen.substring(11,19) : '—'}</td>
    </tr>`;
  }).join('');
}

// ---------------------------------------------------------------------------
// Path MTU & Multi-DNS Diagnostics
// ---------------------------------------------------------------------------
async function updateMtu() {
  const r = await fetch('/api/mtu').catch(()=>null);
  if (!r?.ok) return;
  const rows = await r.json();
  const tb = document.getElementById('tMtu');
  if (!rows.length) return;

  const latest = rows[0];
  document.getElementById('mtuTarget').textContent = latest.target_host || '—';
  document.getElementById('mtuVal').textContent    = latest.path_mtu ? `${latest.path_mtu}` : '—';
  document.getElementById('mtuPayload').textContent= latest.max_unfragmented_payload ? `${latest.max_unfragmented_payload}` : '—';

  const fragEl = document.getElementById('mtuFrag');
  if (latest.status === 'optimal') {
    fragEl.innerHTML = '<span class="badge b-ok">Optimal (1500)</span>';
  } else if (latest.status === 'reduced') {
    fragEl.innerHTML = '<span class="badge b-warn">Reduced (' + (latest.path_mtu || 'PPPoE') + ')</span>';
  } else {
    fragEl.innerHTML = '<span class="badge b-info">' + (latest.status || 'Unknown') + '</span>';
  }

  document.getElementById('mtuNotes').textContent = latest.notes || '—';

  tb.innerHTML = rows.map(m => `<tr>
    <td style="color:#64748b">${ts(m.timestamp)}</td>
    <td class="mono">${m.target_host}</td>
    <td style="font-weight:600;color:#38bdf8">${m.path_mtu ? m.path_mtu + ' bytes' : '—'}</td>
    <td>${m.max_unfragmented_payload ? m.max_unfragmented_payload + ' bytes' : '—'}</td>
    <td><span class="badge ${m.status==='optimal'?'b-ok':m.status==='reduced'?'b-warn':'b-info'}">${m.status}</span></td>
    <td style="color:#94a3b8">${m.notes || '—'}</td>
  </tr>`).join('');
}

async function updateDnsBenchmark() {
  const r = await fetch('/api/dns_benchmark?n=1').catch(()=>null);
  if (!r?.ok) return;
  const rows = await r.json();
  if (!rows.length) return;
  const b = rows[0];
  document.getElementById('dLocal').textContent = fmt(b.local_ms);
  document.getElementById('dCf').textContent    = fmt(b.cloudflare_ms);
  document.getElementById('dGoog').textContent  = fmt(b.google_ms);
  document.getElementById('dQuad').textContent  = fmt(b.quad9_ms);
  if (b.fastest) {
    document.getElementById('dnsBenchFastest').textContent = `Fastest: ${b.fastest}`;
    if (b.local_ms && b.cloudflare_ms && b.cloudflare_ms < b.local_ms) {
      const diff = Math.round(b.local_ms - b.cloudflare_ms);
      document.getElementById('dnsRecommendation').textContent =
        `Tip: Cloudflare (1.1.1.1) is ${diff} ms faster than your Local ISP DNS.`;
    } else {
      document.getElementById('dnsRecommendation').textContent =
        'Local DNS latency is healthy and competitive with public resolvers.';
    }
  }
}

async function updateBloat() {
  const r = await fetch('/api/bufferbloat?n=20').catch(()=>null);
  if (!r?.ok) return;
  const rows = await r.json();
  const tb = document.getElementById('tBloat');
  if (!rows.length) {
    tb.innerHTML = '<tr><td colspan="7" class="dim">No scans yet (runs every 5 min)&hellip;</td></tr>';
    return;
  }
  const rc = { good:'b-ok', moderate:'b-warn', bad:'b-err', severe:'b-err', unknown:'b-info' };
  tb.innerHTML = rows.map(b => `<tr>
    <td style="color:#64748b;white-space:nowrap">${ts(b.timestamp)}</td>
    <td><span class="badge ${rc[b.rating]||'b-info'}">${b.rating}</span></td>
    <td>${fmt(b.baseline_ms)} ms</td>
    <td>${fmt(b.loaded_ms)} ms</td>
    <td style="font-weight:600;color:${b.delta_ms>300?'#f87171':b.delta_ms>100?'#fbbf24':b.delta_ms>30?'#fb923c':'#34d399'}">
      +${fmt(b.delta_ms)} ms</td>
    <td>${fmt(b.download_mbps,2)} Mbps</td>
    <td class="mono" style="font-size:.7rem">${b.ping_host}</td>
  </tr>`).join('');
}

async function updateSpeed() {
  const r = await fetch('/api/speed_test?n=50').catch(()=>null);
  if (!r?.ok) return;
  const rows = await r.json();
  const tb = document.getElementById('tSpeed');

  if (!rows.length) {
    tb.innerHTML = '<tr><td colspan="4" class="dim">No tests yet (runs every 15 min)&hellip;</td></tr>';
    return;
  }

  const latest = rows[0];
  if (latest?.timestamp) {
    const secs = Math.round((Date.now() - new Date(latest.timestamp).getTime()) / 1000);
    const mins = Math.floor(secs / 60);
    document.getElementById('speedAge').textContent =
      `— last test ${mins > 0 ? mins + 'm' : secs + 's'} ago`;
  }

  const chronological = [...rows].reverse();
  const labels = chronological.map(r => ts(r.timestamp));
  upd(cSpeedDl, labels, chronological.map(r => r.download_mbps));
  upd(cSpeedUl, labels, chronological.map(r => r.upload_mbps));

  const maxDl = Math.max(...rows.map(r => r.download_mbps || 0), 1);
  const speedCls = (mbps) => {
    if (mbps == null) return 'error';
    const ratio = mbps / maxDl;
    return ratio > 0.7 ? 'ok' : ratio > 0.4 ? 'warn' : 'error';
  };

  tb.innerHTML = rows.map(s => `<tr>
    <td style="color:#64748b;white-space:nowrap">${ts(s.timestamp)}</td>
    <td class="${speedCls(s.download_mbps)}" style="font-weight:600">
      ${fmt(s.download_mbps,2)} Mbps</td>
    <td class="${speedCls(s.upload_mbps)}" style="font-weight:600">
      ${fmt(s.upload_mbps,2)} Mbps</td>
    <td style="color:#64748b">${s.duration_seconds}s each</td>
  </tr>`).join('');
}

// ---------------------------------------------------------------------------
// Events, Incidents & Export
// ---------------------------------------------------------------------------
async function updateEvents() {
  const r = await fetch('/api/events?n=100').catch(()=>null);
  if (!r?.ok) return;
  const rows = await r.json();
  const tb = document.getElementById('tEvents');
  if (!rows.length) { tb.innerHTML='<tr><td colspan="3" class="dim">No events yet</td></tr>'; return; }
  tb.innerHTML = rows.map(e => {
    const isErr = e.message.includes('packet_loss')||e.message.includes('severe_latency');
    const msgHtml = e.message.split(',').map(m => {
      const t=m.trim();
      return `<span class="badge ${isErr?'b-err':'b-warn'}">${t}</span>`;
    }).join(' ');
    return `<tr>
      <td style="color:#64748b;white-space:nowrap">${ts(e.timestamp)}</td>
      <td>${catBadge(e.category)}</td>
      <td>${msgHtml}</td>
    </tr>`;
  }).join('');
}

const expandedIncidents = new Set();
async function loadIncidentContent(filename, cell) {
  if (expandedIncidents.has(filename)) {
    expandedIncidents.delete(filename);
    cell.querySelector('.incident-content').classList.remove('open');
    cell.querySelector('.expand-btn').textContent = 'show';
    return;
  }
  const r = await fetch(`/api/incidents/${encodeURIComponent(filename)}`).catch(()=>null);
  if (!r?.ok) return;
  const text = await r.text();
  expandedIncidents.add(filename);
  const pre = cell.querySelector('.incident-content');
  pre.textContent = text;
  pre.classList.add('open');
  cell.querySelector('.expand-btn').textContent = 'hide';
}

async function updateIncidents() {
  const r = await fetch('/api/incidents').catch(()=>null);
  if (!r?.ok) return;
  const rows = await r.json();
  const tb = document.getElementById('tIncidents');
  if (!rows.length) { tb.innerHTML='<tr><td colspan="3" class="dim">No incidents yet</td></tr>'; return; }
  tb.innerHTML = rows.map(i => `<tr>
    <td>
      <span class="mono">${i.filename}</span>
      <button class="expand-btn" onclick="loadIncidentContent('${i.filename}',this.closest('td'))">show</button>
      <div class="incident-content"></div>
    </td>
    <td>${(i.size_bytes/1024).toFixed(1)} KB</td>
    <td style="color:#64748b">${i.modified.substring(0,19).replace('T',' ')}</td>
  </tr>`).join('');
}

(function initExportDates() {
  const pad = n => String(n).padStart(2,'0');
  const toLocal = d =>
    `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}`+
    `T${pad(d.getHours())}:${pad(d.getMinutes())}`;
  const now = new Date();
  document.getElementById('expTo').value   = toLocal(now);
  document.getElementById('expFrom').value = toLocal(new Date(now - 86400000));
})();

function doExport() {
  const table   = document.getElementById('expTable').value;
  const fmt     = document.getElementById('expFmt').value;
  const from    = document.getElementById('expFrom').value;
  const to      = document.getElementById('expTo').value;
  const fromIso = from.length === 16 ? from + ':00' : from;
  const toIso   = to.length   === 16 ? to   + ':00' : to;
  const url = `/api/export?table=${encodeURIComponent(table)}&format=${fmt}`
            + `&from=${encodeURIComponent(fromIso)}&to=${encodeURIComponent(toIso)}`;
  const a = document.createElement('a');
  a.href = url;
  a.download = '';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}

// ---------------------------------------------------------------------------
// On-Demand Actions
// ---------------------------------------------------------------------------
async function triggerAction(actionName, btn) {
  if (btn) btn.disabled = true;
  const statusEl = document.getElementById('actionStatus');
  statusEl.style.display = 'block';
  statusEl.innerHTML = `<span class="spinner"></span>Requesting ${actionName}...`;
  try {
    const r = await fetch('/api/actions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: actionName })
    });
    const d = await r.json();
    if (d.id) {
      statusEl.innerHTML = `<span class="spinner"></span>${actionName} queued (ID ${d.id}), executing in background...`;
      pollAction(d.id, btn);
    } else {
      statusEl.textContent = d.error || 'Failed to queue action';
      if (btn) btn.disabled = false;
    }
  } catch (err) {
    statusEl.textContent = `Action failed: ${err}`;
    if (btn) btn.disabled = false;
  }
}

async function triggerTraceroute(btn) {
  const target = document.getElementById('traceTarget').value.trim() || '1.1.1.1';
  if (btn) btn.disabled = true;
  const statusEl = document.getElementById('actionStatus');
  statusEl.style.display = 'block';
  statusEl.innerHTML = `<span class="spinner"></span>Running traceroute to ${target}... (may take 20-40s)`;
  try {
    const r = await fetch('/api/actions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'traceroute', payload: target })
    });
    const d = await r.json();
    if (d.id) {
      pollAction(d.id, btn);
    } else {
      statusEl.textContent = d.error || 'Failed to start traceroute';
      if (btn) btn.disabled = false;
    }
  } catch (err) {
    statusEl.textContent = `Traceroute request failed: ${err}`;
    if (btn) btn.disabled = false;
  }
}

async function pollAction(id, btn) {
  const statusEl = document.getElementById('actionStatus');
  const timer = setInterval(async () => {
    const r = await fetch('/api/actions/latest').catch(()=>null);
    if (!r?.ok) return;
    const items = await r.json();
    const item = items.find(x => x.id === id);
    if (item) {
      if (item.status === 'completed') {
        clearInterval(timer);
        statusEl.innerHTML = `&#10004; ${item.result || (item.action + ' finished successfully')}`;
        if (btn) btn.disabled = false;
        refresh();
      } else if (item.status === 'failed') {
        clearInterval(timer);
        statusEl.innerHTML = `&#10008; ${item.result || (item.action + ' failed')}`;
        if (btn) btn.disabled = false;
      }
    }
  }, 2000);
}

// ---------------------------------------------------------------------------
// Main Polling Loop
// ---------------------------------------------------------------------------
async function refresh() {
  await Promise.all([
    updateStatus(), updateLatest(), updateHistory(),
    updateWifi(), updateNicActive(), updateIfaceTimeline(),
    updateNic(), updateTcp(), updateBloat(), updateSpeed(),
    updateEvents(), updateIncidents(), updateWifiScan(),
    updateProcesses(), updateDnsBenchmark(), updateWifiChannels(),
    updateLanDevices(), updateMdns(), updateMtu(),
  ]);
}

refresh();
setInterval(refresh, 5000);
</script>
</body>
</html>"""


@app.route("/")
def dashboard():
    return Response(DASHBOARD_HTML, mimetype="text/html")


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

def main():
    global DB_PATH, INCIDENTS_PATH

    parser = argparse.ArgumentParser(description="Network Monitor Web Dashboard")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--db",   default="", help="Override DB path from config")
    args = parser.parse_args()

    with open(CONFIG_FILE, "r", encoding="utf-8") as fh:
        config = yaml.safe_load(fh)

    DB_PATH        = args.db or config["storage"]["sqlite_db"]
    INCIDENTS_PATH = config["storage"]["incidents_path"]

    if not Path(DB_PATH).exists():
        print(f"Warning: database not found at {DB_PATH}")
        print("Start advanced_network_monitor.py first to create it.")

    print(f"Dashboard: http://{args.host}:{args.port}")
    print(f"Database:  {DB_PATH}")
    app.run(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    main()
