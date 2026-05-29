# Network Observability Monitor

Windows-only Python tool for continuous network health monitoring. Probes
internet connectivity, gateway responsiveness, DNS resolution (system resolver
and direct UDP), HTTP reachability, Wi-Fi metrics across all adapters, NIC
throughput and errors for every active interface, TCP connection state, and
system CPU/RAM on a configurable interval. Runs periodic bufferbloat scans and
speed tests. Persists all data to SQLite with automatic retention enforcement.
Provides a terminal TUI and a separate web dashboard.

## Requirements

- Windows 10 or later
- Python 3.10+
- `ping`, `tracert`, `ipconfig`, `netsh` on PATH (all standard on Windows)

## Installation

```bash
pip install requests psutil pyyaml windows-curses flask
```

## File layout

```
advanced_network_monitor.py   -- monitor process (TUI or headless)
web_dashboard.py              -- web dashboard (separate process)
config/
  default.yaml                -- all configuration
  schema.sql                  -- SQLite schema (applied automatically)
data/
  sqlite/network_monitor.db   -- created on first run
  incidents/                  -- tracert output files saved on fault
logs/
  network_monitor.log         -- rotating event log
```

## Permissions

The monitor runs as a standard (non-admin) user with one caveat.

`psutil.net_connections()` on Windows returns only connections owned by the
current user when run without elevation. System-wide TCP state counts require
admin privileges. The monitor handles this gracefully -- the `except` block
returns a zeroed `TcpStateSample` rather than crashing, so all other probes
continue normally. To get complete TCP state data, run from an elevated prompt
or a service account with the relevant privileges.

All other probes (`ping`, `tracert`, `ipconfig /all`, `netsh wlan`, psutil NIC
counters, SQLite writes) work correctly as a standard user provided the working
directory is writable.

## Running

### TUI mode

```bash
python advanced_network_monitor.py
```

### Headless mode + web dashboard

Open two terminals:

```bash
# Terminal 1 -- monitor writes to the database
python advanced_network_monitor.py --headless

# Terminal 2 -- dashboard reads from the database
python web_dashboard.py
```

Open `http://127.0.0.1:5000` in a browser.

```bash
# Expose on the local network
python web_dashboard.py --host 0.0.0.0 --port 8080

# Override the database path
python web_dashboard.py --db path/to/network_monitor.db
```

## TUI controls

| Key | Action |
|-----|--------|
| Q   | Quit (writes `monitor_stop` event before exiting) |

## Web dashboard panels

- **Status bar** -- health indicator (green/amber/red/grey), active fault labels,
  DB size, total sample count, last updated time. Goes grey with a warning banner
  if the most recent sample is more than 15 s old (monitor offline or stalled).
- **Metrics grid** -- internet ping, gateway ping, DNS resolver time, DNS server
  UDP latency, HTTP response, packet loss rate, CPU % and RAM % with progress bars,
  probe duration, probed host, IP address, DNS server IP.
- **Latency History** -- last 300 samples of internet and gateway ping.
- **DNS & HTTP** -- last 300 samples of DNS resolver and HTTP response times.
- **DNS Resolver vs Server (UDP)** -- side-by-side comparison of OS resolver
  latency and direct UDP probe latency to the DNS server IP. Divergence indicates
  a caching or stub-resolver effect masking real DNS server performance.
- **Packet Loss Rate** -- rolling loss percentage over last 300 samples.
- **CPU & RAM** -- system utilisation history.
- **Wi-Fi Signal** -- signal strength history chart.
- **Wi-Fi panel** -- live SSID, BSSID, signal bar, band/channel, Rx/Tx rate, auth type.
- **NIC Throughput** -- combined KB/s per adapter, one dataset per interface. Both
  Ethernet and Wi-Fi appear simultaneously when both are active.
- **NIC Errors & Drops** -- combined error and drop rates per adapter per second.
- **TCP Connection States** -- current connection counts by state (stacked bar).
- **Wi-Fi Environment Scan** -- table of all BSSIDs visible at the last scan,
  sorted by signal strength. Shows SSID, BSSID, inline signal bar, channel,
  band, authentication, and cipher. Scan age and network count in the heading.
- **Bufferbloat History** -- results of periodic bufferbloat scans showing
  baseline ping, loaded ping, delta, rating, and download throughput during test.
- **Speed Test History** -- download and upload throughput charts plus a result
  table. Download and upload shown separately; rows colour-coded relative to the
  maximum seen in the result set so degradation is visually obvious.
- **Export** -- download any table as CSV or JSON for a configurable time window.
- **Events** -- all events from the database with time, category badge, and message.
- **Incidents** -- tracert output files; click `show` on any row to expand the full
  tracert output inline in the table.

## Web dashboard API endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /api/latest` | Most recent sample row |
| `GET /api/history?n=300` | Last n samples, oldest-first |
| `GET /api/events?n=100` | Last n events, newest-first |
| `GET /api/wifi?n=300` | Last n Wi-Fi samples, oldest-first |
| `GET /api/nic?n=300` | Last n NIC samples, oldest-first |
| `GET /api/tcp?n=1` | Last n TCP state snapshots |
| `GET /api/wifi_scan` | All BSSIDs from the most recent scan |
| `GET /api/wifi_scan/history` | Per-scan timestamps and network counts |
| `GET /api/bufferbloat?n=50` | Last n bufferbloat results, newest-first |
| `GET /api/speed_test?n=50` | Last n speed test results, newest-first |
| `GET /api/incidents` | Incident file list with metadata |
| `GET /api/incidents/<filename>` | Content of a specific incident file |
| `GET /api/status` | DB size, sample count, last sample timestamp |
| `GET /api/export` | Time-windowed export of any table (see below) |

### Export endpoint

```
GET /api/export?table=samples&from=2024-01-01T00:00:00&to=2024-01-02T00:00:00&format=csv
```

Parameters:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `table` | `samples` | Any table name (see schema section) |
| `from` | 24 h ago | ISO-8601 start timestamp, inclusive |
| `to` | now | ISO-8601 end timestamp, inclusive |
| `format` | `csv` | `csv` or `json` |

Returns a file download. The dashboard Export panel provides a UI for this.

## How it works

### Threads

Three threads run concurrently:

- **monitor_loop** -- runs all probes on a fixed interval, analyses results,
  persists to SQLite, fires events. Compensates sleep time for probe duration
  so the cycle period stays close to the configured interval.
- **tui** (main thread) -- curses UI, redraws at ~10 fps. Skipped in `--headless`.
- **retention_loop** -- sleeps one hour between runs; deletes rows older than
  `general.retention_days` from all tables and writes a `system` event.

### Polling cycle

Each iteration:

1. Measure elapsed time since the previous iteration (for NIC rate calculation).
2. Advance round-robin host cyclers (ping, DNS, HTTP).
3. Retrieve gateway IP from cache (refreshed every 60 s, or immediately on IP change).
4. Ping the selected internet host and the gateway.
5. Time a DNS resolution via the system resolver.
6. Send a raw UDP DNS query directly to the DNS server IP on port 53 and time
   the response (independent of the OS resolver and any local caching).
7. Time a full HTTP GET including TLS handshake.
8. Read Wi-Fi metrics via `netsh wlan show interfaces` (if `wifi.enabled`).
9. If `_cycle_count % scan_interval_cycles == 0`: run full environment scan via
   `netsh wlan show networks mode=bssid`.
10. If a speed test is due this cycle: run download then upload (see below).
    Otherwise, if a bufferbloat scan is due: run the bufferbloat probe.
    Speed test and bufferbloat never run on the same cycle to avoid link contention.
11. Derive per-second NIC I/O rates from consecutive `psutil.net_io_counters()`
    snapshots. All non-loopback NICs with any traffic are recorded.
12. Count TCP connections by state via `psutil.net_connections()`.
13. Parse all adapter IPs and DNS server from `ipconfig /all`. Events fire
    when any adapter's IP changes, gains, or loses an address.
14. Sample CPU and RAM utilisation.
15. Record wall-clock time for steps 3--14 as `probe_duration_ms`.
16. Update rolling stats window; compute packet loss rate.
17. Analyse against thresholds; build fault label string.
18. Persist all samples to SQLite.
19. Fire events for faults, Wi-Fi changes, network state changes, and
    periodic scan/test results.
20. If `probe_duration_ms > poll_interval_seconds * 1000`: fire `slow_probe` event.
21. On `packet_loss`, `high_latency`, or `severe_latency`: probe all internet
    hosts concurrently, log results, run `tracert`, save incident file.
22. Sleep `max(0, interval - total_elapsed)`.

### Multi-host cycling

Normal cycles use one host per cycler (ping, DNS, HTTP) in round-robin order.
Fault cycles probe all `internet_ping_hosts` concurrently so "one host down"
can be distinguished from "all internet unreachable".

### Gateway caching

The gateway IP is cached with a 60 s TTL (`GATEWAY_CACHE_TTL`). Running
`ipconfig` every second would cost ~50 ms per iteration. The cache is
invalidated immediately on any `ip_change` or `ip_gained` event.

### DNS server direct probe

A minimal 29-byte DNS UDP packet (A query for `a.root-servers.net`) is built
via `struct.pack` and sent to port 53 on the DNS server IP. This isolates raw
DNS server latency from OS caching. A large gap between this and the system
resolver time indicates caching or stub-resolver effects.

### NIC monitoring

`NicProbe` in `auto` mode records every non-loopback NIC with any traffic each
cycle. Both Ethernet and Wi-Fi adapters appear simultaneously with no extra
configuration. The dashboard NIC charts build one dataset per interface
dynamically as new adapter names are discovered, so any number of NICs or
Wi-Fi interfaces are handled correctly.

### Wi-Fi monitoring

`WifiProbe` reads `netsh wlan show interfaces` each cycle regardless of whether
Wi-Fi is the default route. On a wired-primary machine with Wi-Fi associated,
signal strength, BSSID, channel, link rates, and auth type are all captured.
Set `wifi.enabled: true` even on wired-primary machines if a Wi-Fi adapter is
present.

BSSID changes (roaming) and band changes fire `wifi` category events. Set
`wifi.enabled: false` only if no Wi-Fi adapter is present.

### Wi-Fi environment scan

Every `wifi.scan_interval_cycles` cycles (default 60 = once per minute),
`WifiScanner.scan()` runs `netsh wlan show networks mode=bssid`. Every visible
BSSID is recorded with SSID, signal %, channel, band, authentication, and
cipher. Band is derived from channel: 1--14 = 2.4 GHz, 36--177 = 5 GHz.

The scan runs inside the probe block; its duration contributes to
`probe_duration_ms`. On a busy RF environment this may add 1--3 s.

### Bufferbloat probe

Every `bufferbloat.interval_cycles` cycles (default 300 = every 5 minutes),
`BufferbloatProbe.run()`:

1. Records current rolling average ping as baseline.
2. Starts a background download thread (Cloudflare `__down` endpoint).
3. Fires `ping_count` pings (default 10) spread across `test_duration_seconds`.
4. Computes mean loaded RTT and delta vs baseline.
5. Rates the result: good (<30 ms delta), moderate (30--100), bad (100--300),
   severe (>300).

The test blocks for approximately `test_duration_seconds`. Skipped on cycles
where a speed test fires (they would interfere).

### Speed test

Every `speedtest.interval_cycles` cycles (default 900 = every 15 minutes),
`SpeedTestProbe.run()`:

1. **Download** -- streams `download_url` for `test_duration_seconds`,
   counts bytes received, computes Mbps from client-side elapsed time.
2. **Upload** -- POSTs a generator that yields a pre-allocated 10 MB buffer
   in 64 KB chunks until a monotonic deadline, giving the server a continuous
   stream for the full test window. Throughput computed from bytes sent and
   elapsed time.

Total blocking time is approximately `2 * test_duration_seconds` (default 20 s).
If a speed test and bufferbloat scan would fire on the same cycle, the speed
test takes priority and bufferbloat is deferred to its next cycle.

Both results are persisted to SQLite and a `system` event is fired with the
dl/ul summary.

### Startup and shutdown events

`monitor_start` is written on construction after storage is ready.
`monitor_stop` is written by `shutdown()`, called from `SIGINT`/`SIGTERM`
handlers, on TUI quit, and on `KeyboardInterrupt`. The events table therefore
has a complete record of monitor uptime alongside connectivity events.

### Retention enforcement

`Storage.purge_old_rows(days)` deletes from all eight tables using a single
cutoff timestamp. Runs hourly in the retention thread. Fires a `system` event
after each purge. The SQLite file will not grow indefinitely.

### Probe timing budget

`probe_duration_ms` is recorded every cycle. If it exceeds
`poll_interval_seconds * 1000`, a `slow_probe` system event fires. The sleep
is `max(0, interval - elapsed)` so drift is minimised. On bufferbloat and
speed test cycles, the duration will naturally be much larger than the
interval; this is expected and visible in the probe duration metric.

### Fault labels

| Label              | Trigger |
|--------------------|---------|
| `packet_loss`      | Internet ping returned no response |
| `high_latency`     | Ping > `thresholds.high_latency_ms` |
| `severe_latency`   | Ping > `thresholds.severe_latency_ms` (supersedes `high_latency`) |
| `high_packet_loss` | Rolling loss rate > `thresholds.packet_loss_rate_pct` |
| `high_jitter`      | Rolling jitter > `thresholds.high_jitter_ms` |
| `slow_dns`         | DNS resolver > `thresholds.slow_dns_ms` |
| `isp_issue_likely` | Gateway < 10 ms but ping > `high_latency_ms` |
| `nic_errors`       | Combined NIC errors + drops > `thresholds.nic_error_rate_ps` per second |

### Event categories

| Category  | Written by |
|-----------|------------|
| `fault`   | Threshold breach, multi-host probe result |
| `wifi`    | BSSID roam or band change |
| `network` | Adapter IP change, gain, or loss |
| `system`  | monitor_start, monitor_stop, retention_purge, slow_probe, bufferbloat result, speedtest result |
| `info`    | tracert start / failure |

## Database schema

Defined in `config/schema.sql`. Applied automatically on first run.
Safe to re-apply on an existing database (all statements use `IF NOT EXISTS`).

Manual initialisation:

```bash
sqlite3 data/sqlite/network_monitor.db < config/schema.sql
```

### `samples`

| Column              | Type    | Description |
|---------------------|---------|-------------|
| `id`                | INTEGER | PK |
| `timestamp`         | TEXT    | ISO-8601 local time |
| `probed_host`       | TEXT    | Internet host this cycle (round-robin) |
| `internet_ping`     | REAL    | RTT to probed_host, ms. NULL = failure |
| `gateway_ping`      | REAL    | RTT to default gateway, ms. NULL = failure |
| `dns_ms`            | REAL    | System resolver time, ms. NULL = failure |
| `dns_server_ms`     | REAL    | Direct UDP probe to DNS server, ms. NULL = failure |
| `http_ms`           | REAL    | HTTP GET time including TLS, ms. NULL = failure |
| `packet_loss_rate`  | REAL    | Rolling loss %, 0--100 |
| `ip_address`        | TEXT    | Primary adapter IPv4 address |
| `dns_server`        | TEXT    | DNS server IP in use |
| `cpu_pct`           | REAL    | System CPU utilisation % |
| `ram_pct`           | REAL    | System RAM utilisation % |
| `probe_duration_ms` | REAL    | Wall-clock time for all probes this cycle, ms |
| `notes`             | TEXT    | Comma-separated fault labels, '' if healthy |

### `events`

| Column      | Type    | Description |
|-------------|---------|-------------|
| `id`        | INTEGER | PK |
| `timestamp` | TEXT    | ISO-8601 local time |
| `category`  | TEXT    | fault / wifi / network / system / info |
| `message`   | TEXT    | Event description |

### `wifi_samples`

| Column         | Type    | Description |
|----------------|---------|-------------|
| `id`           | INTEGER | PK |
| `timestamp`    | TEXT    | ISO-8601 local time |
| `ssid`         | TEXT    | Connected SSID |
| `bssid`        | TEXT    | Access point MAC address |
| `signal_pct`   | INTEGER | Signal strength 0--100 |
| `channel`      | INTEGER | Wi-Fi channel |
| `band`         | TEXT    | 2.4GHz / 5GHz / 6GHz |
| `rx_rate_mbps` | REAL    | Receive link rate |
| `tx_rate_mbps` | REAL    | Transmit link rate |
| `auth`         | TEXT    | Authentication type |

### `nic_samples`

One row per NIC per cycle. Multiple rows per cycle when multiple adapters are active.

| Column           | Type    | Description |
|------------------|---------|-------------|
| `id`             | INTEGER | PK |
| `timestamp`      | TEXT    | ISO-8601 local time |
| `interface`      | TEXT    | NIC name (e.g. `Ethernet`, `Wi-Fi`) |
| `bytes_sent_ps`  | REAL    | Bytes sent per second |
| `bytes_recv_ps`  | REAL    | Bytes received per second |
| `errin_ps`       | REAL    | Inbound errors per second |
| `errout_ps`      | REAL    | Outbound errors per second |
| `dropin_ps`      | REAL    | Inbound drops per second |
| `dropout_ps`     | REAL    | Outbound drops per second |

### `tcp_states`

One row per cycle. Columns: `id`, `timestamp`, then one INTEGER per TCP state:
`established`, `time_wait`, `close_wait`, `syn_sent`, `syn_recv`, `fin_wait1`,
`fin_wait2`, `closing`, `last_ack`, `listen`, `other`.

### `wifi_scan_results`

One row per BSSID per scan. All rows from the same scan share `scan_timestamp`.

| Column           | Type    | Description |
|------------------|---------|-------------|
| `id`             | INTEGER | PK |
| `scan_timestamp` | TEXT    | ISO-8601 time the scan ran |
| `ssid`           | TEXT    | Network name; empty string = hidden network |
| `bssid`          | TEXT    | Access point MAC address |
| `signal_pct`     | INTEGER | Signal strength 0--100 |
| `channel`        | INTEGER | Primary channel number |
| `band`           | TEXT    | 2.4GHz / 5GHz / NULL if indeterminate |
| `authentication` | TEXT    | e.g. WPA2-Personal |
| `cipher`         | TEXT    | e.g. CCMP |

### `bufferbloat_samples`

| Column           | Type    | Description |
|------------------|---------|-------------|
| `id`             | INTEGER | PK |
| `timestamp`      | TEXT    | ISO-8601 local time |
| `baseline_ms`    | REAL    | Rolling average ping before test, ms |
| `loaded_ms`      | REAL    | Mean ping RTT during download, ms |
| `delta_ms`       | REAL    | loaded_ms - baseline_ms (bufferbloat score) |
| `rating`         | TEXT    | good / moderate / bad / severe |
| `download_mbps`  | REAL    | Throughput achieved during test window |
| `ping_host`      | TEXT    | Host pinged during test |
| `download_url`   | TEXT    | URL used for the download |

### `speed_test_results`

| Column              | Type    | Description |
|---------------------|---------|-------------|
| `id`                | INTEGER | PK |
| `timestamp`         | TEXT    | ISO-8601 local time |
| `download_mbps`     | REAL    | Download throughput, Mbps |
| `upload_mbps`       | REAL    | Upload throughput, Mbps |
| `download_bytes`    | INTEGER | Raw bytes received during test window |
| `upload_bytes`      | INTEGER | Raw bytes sent during test window |
| `duration_seconds`  | REAL    | Configured test duration per direction |
| `download_url`      | TEXT    | URL used for download |
| `upload_url`        | TEXT    | URL used for upload |

## Configuration reference

### `general`

| Key | Default | Description |
|-----|---------|-------------|
| `poll_interval_seconds` | `1` | Polling interval. Sleep per cycle is `max(0, interval - probe_duration)` |
| `retention_days` | `14` | Rows older than this are deleted hourly from all eight tables |
| `timezone` | `Europe/London` | Informational; timestamps are ISO-8601 local time |

### `storage`

| Key | Default | Description |
|-----|---------|-------------|
| `sqlite_db` | `data/sqlite/network_monitor.db` | SQLite database path. Created on first run. |
| `event_log.path` | `logs/network_monitor.log` | Rotating log file |
| `event_log.max_size_mb` | `25` | Max size per log file before rotation |
| `event_log.backup_count` | `10` | Rotated files to keep |
| `incidents_path` | `data/incidents/` | Directory for tracert output files |

### `network`

| Key | Default | Description |
|-----|---------|-------------|
| `internet_ping_hosts` | `[1.1.1.1, 8.8.8.8, teams.microsoft.com]` | Round-robin ping targets; all probed concurrently on fault |
| `dns_hosts` | `[teams.microsoft.com, microsoft.com, google.com]` | Round-robin DNS resolution targets |
| `http_targets` | `[https://www.microsoft.com, ...]` | Round-robin HTTP GET targets |

### `wifi`

| Key | Default | Description |
|-----|---------|-------------|
| `enabled` | `true` | Enable Wi-Fi monitoring via `netsh`. Set `true` even on wired-primary machines -- signal, BSSID, roaming, and environment scans all work when Wi-Fi is associated but not the default route. Set `false` only if no Wi-Fi adapter is present. |
| `roaming_detection` | `true` | Informational; detection always runs when `enabled: true` |
| `scan_interval_cycles` | `60` | Cycles between full environment scans. At 1 s = once per minute |

### `nic`

| Key | Default | Description |
|-----|---------|-------------|
| `interface` | `auto` | `auto` records every non-loopback NIC with any traffic. Both Ethernet and Wi-Fi appear simultaneously. Use an exact psutil name (e.g. `Wi-Fi`, `Ethernet`) to restrict to one adapter. |

### `thresholds`

| Key | Default | Description |
|-----|---------|-------------|
| `high_latency_ms` | `150` | Triggers `high_latency` |
| `severe_latency_ms` | `500` | Triggers `severe_latency`; supersedes `high_latency`; fires fault diagnostics |
| `high_jitter_ms` | `50` | Triggers `high_jitter` |
| `slow_dns_ms` | `500` | Triggers `slow_dns` on system resolver time |
| `packet_loss_rate_pct` | `5` | Rolling loss % above this triggers `high_packet_loss` |
| `nic_error_rate_ps` | `1.0` | Combined NIC errors + drops/s above this triggers `nic_errors` |

### `diagnostics`

| Key | Default | Description |
|-----|---------|-------------|
| `traceroute_on_fault` | `true` | Run `tracert` on `packet_loss` / `high_latency` / `severe_latency` |

### `bufferbloat`

| Key | Default | Description |
|-----|---------|-------------|
| `enabled` | `true` | Enable periodic bufferbloat scans |
| `download_url` | Cloudflare 100 MB endpoint | URL to download during the test |
| `test_duration_seconds` | `10` | Seconds the download runs while pings are fired |
| `ping_count` | `10` | Number of pings fired during the download window |
| `interval_cycles` | `300` | Cycles between scans. At 1 s = every 5 minutes. Skipped if a speed test fires on the same cycle. |

### `speedtest`

| Key | Default | Description |
|-----|---------|-------------|
| `enabled` | `true` | Enable periodic speed tests |
| `download_url` | Cloudflare 100 MB endpoint | URL used for download direction |
| `upload_url` | `https://speed.cloudflare.com/__up` | URL used for upload direction |
| `test_duration_seconds` | `10` | Seconds per direction. Total blocking time ≈ 20 s. |
| `interval_cycles` | `900` | Cycles between tests. At 1 s = every 15 minutes. Takes priority over bufferbloat if both would fire on the same cycle. |

### `tui`

| Key | Default | Description |
|-----|---------|-------------|
| `enabled` | `true` | Informational; TUI runs unless `--headless` is passed |
| `refresh_rate_ms` | `1000` | Informational; TUI redraws at ~100 ms regardless |
| `max_events` | `20` | Recent Events panel line count |
