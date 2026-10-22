#!/usr/bin/env python3
"""
web_dashboard.py -- Network Observability Web Dashboard

Serves a read-only web UI over the SQLite database written by
advanced_network_monitor.py. Runs as a separate process.

Endpoints
---------
  GET /                           Dashboard HTML
  GET /api/latest                 Most recent sample
  GET /api/history?n=300          Last n samples, oldest-first
  GET /api/events?n=100           Last n events, newest-first
  GET /api/wifi?n=300             Last n Wi-Fi samples, oldest-first
  GET /api/nic?n=300              Last n NIC samples, oldest-first
  GET /api/tcp?n=1                Last n TCP state snapshots
  GET /api/incidents              Incident file list
  GET /api/incidents/<filename>   Content of a specific incident file
  GET /api/status                 DB size, sample count, last timestamp

Requirements: flask pyyaml
"""

from __future__ import annotations

import argparse
import sqlite3
from datetime import datetime
from pathlib import Path

import yaml
from flask import Flask, Response, jsonify, request

CONFIG_FILE = "config/default.yaml"

app = Flask(__name__)
DB_PATH:        str = ""
INCIDENTS_PATH: str = ""


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------

def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True, timeout=5)
    conn.execute("PRAGMA busy_timeout = 5000;")
    conn.row_factory = sqlite3.Row
    return conn


def get_write_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=5)
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA busy_timeout = 5000;")
    return conn


def query(sql: str, params: tuple = ()) -> list[dict]:
    conn = get_db()
    try:
        return [dict(r) for r in conn.execute(sql, params).fetchall()]
    finally:
        conn.close()


def n_param(default: int = 300, cap: int = 10_000) -> int:
    try:
        val = int(request.args.get("n", default))
        return max(1, min(val, cap))
    except (ValueError, TypeError):
        return default


# ---------------------------------------------------------------------------
# API routes
# ---------------------------------------------------------------------------

@app.route("/api/latest")
def api_latest():
    rows = query("SELECT * FROM samples ORDER BY timestamp DESC LIMIT 1")
    if not rows:
        return jsonify({"error": "No data yet"}), 404
    return jsonify(rows[0])


@app.route("/api/history")
def api_history():
    rows = query("""
        SELECT * FROM (SELECT * FROM samples ORDER BY timestamp DESC LIMIT ?)
        ORDER BY timestamp ASC
    """, (n_param(),))
    return jsonify(rows)


@app.route("/api/events")
def api_events():
    rows = query(
        "SELECT * FROM events ORDER BY timestamp DESC LIMIT ?",
        (n_param(default=100, cap=5_000),),
    )
    return jsonify(rows)


@app.route("/api/wifi")
def api_wifi():
    rows = query("""
        SELECT * FROM (SELECT * FROM wifi_samples ORDER BY timestamp DESC LIMIT ?)
        ORDER BY timestamp ASC
    """, (n_param(),))
    return jsonify(rows)


@app.route("/api/nic")
def api_nic():
    rows = query("""
        SELECT * FROM (SELECT * FROM nic_samples ORDER BY timestamp DESC LIMIT ?)
        ORDER BY timestamp ASC
    """, (n_param(),))
    return jsonify(rows)


@app.route("/api/nic/active")
def api_nic_active():
    """Return the interface with the highest combined bytes/s in the last sample.

    Also returns all interfaces from the last cycle with their rates, so the
    dashboard can display a ranked list and highlight the active one.
    """
    latest_ts = query(
        "SELECT MAX(timestamp) AS ts FROM nic_samples"
    )
    if not latest_ts or not latest_ts[0]["ts"]:
        return jsonify({"active": None, "interfaces": []})

    ts = latest_ts[0]["ts"]
    rows = query("""
        SELECT *, (bytes_sent_ps + bytes_recv_ps) AS total_bps
        FROM nic_samples WHERE timestamp = ?
        ORDER BY total_bps DESC
    """, (ts,))

    return jsonify({
        "active": rows[0]["interface"] if rows else None,
        "interfaces": rows,
        "timestamp": ts,
    })


@app.route("/api/nic/timeline")
def api_nic_timeline():
    """Return per-interface bytes/s over time for the interface activity chart.

    Returns the last n samples per interface, pivoted so the response is a
    dict of {interface_name: [{timestamp, total_bps}]} for easy JS charting.
    Only interfaces with meaningful traffic (peak > 1 KB/s) are included to
    suppress loopback and Hyper-V virtual adapters that generate noise.
    """
    n = n_param(default=300)

    # Get all distinct interfaces
    ifaces = query("SELECT DISTINCT interface FROM nic_samples")
    result = {}

    for row in ifaces:
        iface = row["interface"]
        samples = query("""
            SELECT * FROM (
                SELECT timestamp,
                       (bytes_sent_ps + bytes_recv_ps) AS total_bps
                FROM nic_samples WHERE interface = ?
                ORDER BY timestamp DESC LIMIT ?
            ) ORDER BY timestamp ASC
        """, (iface, n))

        # Suppress interfaces that never exceeded 1 KB/s in this window.
        peak = max((s["total_bps"] for s in samples), default=0)
        if peak > 1024:
            result[iface] = samples

    return jsonify(result)


@app.route("/api/tcp")
def api_tcp():
    rows = query("""
        SELECT * FROM (SELECT * FROM tcp_states ORDER BY timestamp DESC LIMIT ?)
        ORDER BY timestamp ASC
    """, (n_param(default=1),))
    return jsonify(rows)


@app.route("/api/wifi_scan")
def api_wifi_scan():
    """Return all rows from the most recent environment scan.

    Finds the latest scan_timestamp then returns every row with that
    timestamp, ordered by signal strength descending so the strongest
    networks appear first in the dashboard table.
    """
    latest = query(
        "SELECT MAX(scan_timestamp) AS ts FROM wifi_scan_results"
    )
    if not latest or not latest[0]["ts"]:
        return jsonify([])
    rows = query("""
        SELECT * FROM wifi_scan_results
        WHERE scan_timestamp = ?
        ORDER BY signal_pct DESC
    """, (latest[0]["ts"],))
    return jsonify(rows)


@app.route("/api/wifi_scan/history")
def api_wifi_scan_history():
    """Return distinct scan timestamps for the last n scans (default 60).

    Used by the dashboard to show how many networks were visible per scan
    over time -- useful for detecting RF environment changes.
    """
    rows = query("""
        SELECT scan_timestamp, COUNT(*) AS network_count
        FROM wifi_scan_results
        GROUP BY scan_timestamp
        ORDER BY scan_timestamp DESC
        LIMIT ?
    """, (n_param(default=60, cap=1440),))
    return jsonify(rows)


@app.route("/api/incidents")
def api_incidents():
    """List incident files with name, size, and modification time."""
    path = Path(INCIDENTS_PATH)
    if not path.exists():
        return jsonify([])
    incidents = []
    for f in sorted(path.glob("incident_*.txt"), reverse=True):
        st = f.stat()
        incidents.append({
            "filename": f.name,
            "size_bytes": st.st_size,
            "modified": datetime.fromtimestamp(st.st_mtime).isoformat(),
        })
    return jsonify(incidents)


@app.route("/api/bufferbloat")
def api_bufferbloat():
    """Last n bufferbloat scan results, newest-first."""
    rows = query(
        "SELECT * FROM bufferbloat_samples ORDER BY timestamp DESC LIMIT ?",
        (n_param(default=50, cap=500),),
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
    """Export a time-windowed slice of any table as CSV or JSON.

    Query parameters
    ----------------
    table   -- samples | events | wifi_samples | nic_samples | tcp_states |
               wifi_scan_results | bufferbloat_samples  (default: samples)
    from    -- ISO-8601 start timestamp inclusive (default: 24 h ago)
    to      -- ISO-8601 end timestamp   inclusive (default: now)
    format  -- csv | json  (default: csv)
    """
    import csv
    import io
    import json as json_mod
    from datetime import timedelta

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
        target = channels_24 if "2.4" in str(band) or ch <= 14 else channels_5
        if ch not in target:
            target[ch] = {"count": 0, "max_signal": 0}
        target[ch]["count"] += 1
        sig = r.get("signal_pct") or 0
        if sig > target[ch]["max_signal"]:
            target[ch]["max_signal"] = sig

    # Find cleanest standard 2.4 GHz channel among 1, 6, 11
    best_ch = None
    min_score = 999999
    for ch in [1, 6, 11]:
        c_info = channels_24.get(ch, {"count": 0, "max_signal": 0})
        score = c_info["count"] * 10 + c_info["max_signal"]
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
    allowed = {"speedtest", "bufferbloat", "traceroute", "wifiscan", "dns_benchmark"}
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

    # CSV -- empty file if no rows (still valid CSV with headers if we had them,
    # but without rows we have no fieldnames, so return empty body).
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
# Dashboard HTML
# ---------------------------------------------------------------------------

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Network Monitor</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js"></script>
<style>
  *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'Segoe UI',system-ui,sans-serif;background:#0f1117;color:#e2e8f0;padding:20px}
  h1{font-size:1.3rem;font-weight:600;color:#f8fafc;margin-bottom:20px}
  h2{font-size:0.75rem;font-weight:600;color:#64748b;text-transform:uppercase;letter-spacing:.1em;margin-bottom:12px}

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
  .metric .val{font-size:1.4rem;font-weight:700;font-variant-numeric:tabular-nums}
  .metric .unit{font-size:.7rem;color:#64748b;margin-left:2px}
  .ok{color:#34d399}.warn{color:#fbbf24}.error{color:#f87171}.dim{color:#94a3b8}

  /* Cards */
  .card{background:#1e2130;border:1px solid #2d3248;border-radius:8px;padding:16px;margin-bottom:16px}
  .chart-wrap{position:relative;height:190px}
  .two-col{display:grid;grid-template-columns:1fr 1fr;gap:16px}
  @media(max-width:700px){.two-col{grid-template-columns:1fr}}

  /* Tables */
  table{width:100%;border-collapse:collapse;font-size:.76rem}
  th{text-align:left;color:#64748b;font-weight:500;padding:5px 8px;border-bottom:1px solid #2d3248}
  td{padding:5px 8px;border-bottom:1px solid #1a1f2e;font-variant-numeric:tabular-nums}
  tr:last-child td{border-bottom:none}
  tr:hover td{background:#252a3a}
  .mono{font-family:monospace;font-size:.72rem}

  /* Badges */
  .badge{display:inline-block;padding:1px 6px;border-radius:99px;font-size:.66rem;font-weight:600;white-space:nowrap}
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
<h1>&#x1F4E1; Network Observability Monitor</h1>

<!-- Status bar -->
<div class="sbar">
  <div class="dot" id="dot"></div>
  <span id="statusText">Loading&hellip;</span>
  <div class="sbar-right">
    <span id="staleWarn" style="display:none;color:#f87171">&#9888; Monitor may be offline</span>
    <span id="dbSize">DB: —</span>
    <span id="sampleCount">Samples: —</span>
    <span id="updated">—</span>
  </div>
</div>

<!-- Quick Actions Panel (Feature 1) -->
<div class="card" style="margin-bottom:16px">
  <h2>&#9889; On-Demand Actions</h2>
  <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:center">
    <button class="act-btn" id="btnSpeed" onclick="triggerAction('speedtest', this)">&#128640; Run Speed Test</button>
    <button class="act-btn" id="btnBloat" onclick="triggerAction('bufferbloat', this)">&#128200; Run Bufferbloat Test</button>
    <button class="act-btn" id="btnScan" onclick="triggerAction('wifiscan', this)">&#128246; Scan Wi-Fi Now</button>
    <button class="act-btn" id="btnDns" onclick="triggerAction('dns_benchmark', this)">&#127760; Benchmark DNS</button>
    <div style="display:flex;gap:4px;align-items:center;margin-left:auto">
      <input id="traceTarget" type="text" placeholder="1.1.1.1" value="1.1.1.1" style="background:#0f1117;color:#e2e8f0;border:1px solid #2d3248;border-radius:4px;padding:6px 8px;font-size:.78rem;width:130px">
      <button class="act-btn" onclick="triggerTraceroute(this)">&#128269; Traceroute</button>
    </div>
  </div>
  <div id="actionStatus" style="font-size:0.75rem;color:#7dd3fc;margin-top:10px;display:none"></div>
</div>

<!-- Metrics -->
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

<p class="note">Auto-refreshes every 5 s</p>

<!-- Multi-DNS Benchmark (Feature 6) & Network Hogs (Feature 3) -->
<div class="two-col">
  <div class="card">
    <h2>&#127760; Multi-DNS Latency Benchmark <span id="dnsBenchFastest" class="badge b-ok" style="margin-left:8px"></span></h2>
    <div class="mgrid" style="grid-template-columns:repeat(auto-fit,minmax(110px,1fr));margin-bottom:8px">
      <div class="metric"><div class="lbl">Local ISP DNS</div><div><span class="val" id="dLocal">--</span><span class="unit">ms</span></div></div>
      <div class="metric"><div class="lbl">Cloudflare (1.1.1.1)</div><div><span class="val" id="dCf">--</span><span class="unit">ms</span></div></div>
      <div class="metric"><div class="lbl">Google (8.8.8.8)</div><div><span class="val" id="dGoog">--</span><span class="unit">ms</span></div></div>
      <div class="metric"><div class="lbl">Quad9 (9.9.9.9)</div><div><span class="val" id="dQuad">--</span><span class="unit">ms</span></div></div>
    </div>
    <div id="dnsRecommendation" style="font-size:0.75rem;color:#7dd3fc;margin-top:6px"></div>
  </div>
  <div class="card">
    <h2>&#128187; Top Network Applications (Network Hogs)</h2>
    <table>
      <thead><tr><th>Application</th><th>PID</th><th>Connections</th><th>Download</th><th>Upload</th></tr></thead>
      <tbody id="tProcesses"><tr><td colspan="5" class="dim">Sampling processes&hellip;</td></tr></tbody>
    </table>
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

<!-- CPU/RAM + Wi-Fi signal -->
<div class="two-col">
  <div class="card"><h2>CPU &amp; RAM</h2>
    <div class="chart-wrap"><canvas id="cSys"></canvas></div></div>
  <div class="card"><h2>Wi-Fi Signal</h2>
    <div class="chart-wrap"><canvas id="cWifi"></canvas></div></div>
</div>

<!-- Wi-Fi live panel -->
<div class="card">
  <h2>Wi-Fi</h2>
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

<!-- Interface activity timeline -->
<div class="card">
  <h2>Interface Activity <span id="ifaceNote" style="font-weight:400;color:#475569;text-transform:none;font-size:0.72rem"></span></h2>
  <div class="chart-wrap" style="height:200px"><canvas id="cIfaceTimeline"></canvas></div>
  <div id="ifaceList" style="margin-top:12px;display:flex;gap:16px;flex-wrap:wrap;font-size:.76rem"></div>
</div>

<!-- NIC throughput + NIC errors (datasets built dynamically per adapter) -->
<div class="two-col">
  <div class="card"><h2>NIC Throughput</h2>
    <div class="chart-wrap"><canvas id="cNic"></canvas></div></div>
  <div class="card"><h2>NIC Errors &amp; Drops</h2>
    <div class="chart-wrap"><canvas id="cNicErr"></canvas></div></div>
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
  <h2>Speed Test History <span id="speedAge" style="font-weight:400;color:#475569;text-transform:none;font-size:0.72rem"></span></h2>
  <div class="two-col" style="margin-bottom:14px">
    <div class="chart-wrap" style="height:160px"><canvas id="cSpeedDl"></canvas></div>
    <div class="chart-wrap" style="height:160px"><canvas id="cSpeedUl"></canvas></div>
  </div>
  <table>
    <thead><tr><th>Time</th><th>Download</th><th>Upload</th><th>Duration</th></tr></thead>
    <tbody id="tSpeed"><tr><td colspan="4" class="dim">Waiting for first test (runs every 15 min)&hellip;</td></tr></tbody>
  </table>
</div>

<!-- Export -->
<div class="card">
  <h2>Export Data</h2>
  <div style="display:flex;gap:12px;flex-wrap:wrap;align-items:flex-end">
    <div>
      <div class="lbl" style="margin-bottom:4px">Table</div>
      <select id="expTable" style="background:#0f1117;color:#e2e8f0;border:1px solid #2d3248;border-radius:4px;padding:4px 8px;font-size:.8rem">
        <option>samples</option><option>events</option><option>wifi_samples</option>
        <option>nic_samples</option><option>tcp_states</option>
        <option>wifi_scan_results</option><option>bufferbloat_samples</option>
        <option>speed_test_results</option><option>action_queue</option><option>process_samples</option><option>dns_benchmarks</option>
      </select>
    </div>
    <div>
      <div class="lbl" style="margin-bottom:4px">From</div>
      <input id="expFrom" type="datetime-local" style="background:#0f1117;color:#e2e8f0;border:1px solid #2d3248;border-radius:4px;padding:4px 8px;font-size:.8rem">
    </div>
    <div>
      <div class="lbl" style="margin-bottom:4px">To</div>
      <input id="expTo" type="datetime-local" style="background:#0f1117;color:#e2e8f0;border:1px solid #2d3248;border-radius:4px;padding:4px 8px;font-size:.8rem">
    </div>
    <div>
      <div class="lbl" style="margin-bottom:4px">Format</div>
      <select id="expFmt" style="background:#0f1117;color:#e2e8f0;border:1px solid #2d3248;border-radius:4px;padding:4px 8px;font-size:.8rem">
        <option value="csv">CSV</option><option value="json">JSON</option>
      </select>
    </div>
    <button onclick="doExport()" style="background:#1e3a5f;color:#7dd3fc;border:1px solid #2d6a9f;border-radius:4px;padding:6px 14px;font-size:.8rem;cursor:pointer">
      Download
    </button>
  </div>
</div>

<!-- TCP states -->
<div class="card"><h2>TCP Connection States (current)</h2>
  <div class="chart-wrap" style="height:140px"><canvas id="cTcp"></canvas></div></div>

<!-- Wi-Fi Channel Overlap & Congestion (Feature 7) -->
<div class="card">
  <h2>&#128246; Wi-Fi Channel Overlap &amp; Congestion <span id="wifiChanRec" class="badge b-ok" style="margin-left:8px"></span></h2>
  <div class="two-col" style="margin-top:10px">
    <div>
      <h3 style="font-size:.72rem;color:#94a3b8;margin-bottom:6px">2.4 GHz Spectrum (Channels 1–13)</h3>
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
  <h2>Wi-Fi Environment Scan <span id="scanAge" style="font-weight:400;color:#475569;text-transform:none;font-size:0.72rem"></span></h2>
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

<!-- Events + Incidents -->
<div class="two-col">
  <div class="card"><h2>Events</h2>
    <table><thead><tr><th>Time</th><th>Cat</th><th>Message</th></tr></thead>
    <tbody id="tEvents"><tr><td colspan="3" class="dim">Loading&hellip;</td></tr></tbody></table>
  </div>
  <div class="card"><h2>Incidents</h2>
    <table><thead><tr><th>File</th><th>Size</th><th>Time</th></tr></thead>
    <tbody id="tIncidents"><tr><td colspan="3" class="dim">Loading&hellip;</td></tr></tbody></table>
  </div>
</div>

<script>
// ---------------------------------------------------------------------------
// Chart factory
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

// NIC charts are initialised empty; datasets are added dynamically as new
// interface names are discovered. This handles any number of NICs and Wi-Fi
// adapters without hardcoding dataset indices.
const cNic    = mkChart('cNic',    [], 'KB/s');
const cNicErr = mkChart('cNicErr', [], '/s');

// Interface activity timeline -- one line per active interface.
const cIfaceTimeline = mkChart('cIfaceTimeline', [], 'KB/s');

// Colour palette for NIC adapter datasets. Cycles if more than palette length.
const NIC_COLOURS = [
  'rgb(52,211,153)', 'rgb(251,191,36)', 'rgb(56,189,248)',
  'rgb(248,113,113)','rgb(167,139,250)','rgb(251,146,60)',
];
// Track which interface names have been added to each NIC chart.
const nicThroughputAdapters = new Set();
const nicErrorAdapters      = new Set();

function ensureNicDataset(chart, adapterSet, iface, suffix) {
  if (adapterSet.has(iface)) return;
  adapterSet.add(iface);
  const idx = adapterSet.size - 1;
  const colour = NIC_COLOURS[idx % NIC_COLOURS.length];
  chart.data.datasets.push(
    ds(`${iface} ${suffix}`, colour)
  );
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

function notesHtml(notes) {
  if (!notes) return '<span class="badge b-ok">healthy</span>';
  return notes.split(',').map(n => {
    const t=n.trim();
    const c=(t==='packet_loss'||t==='severe_latency')?'b-err':'b-warn';
    return `<span class="badge ${c}">${t}</span>`;
  }).join(' ');
}
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
// Stale detection -- warn if last sample is > 15 s old
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

// ---------------------------------------------------------------------------
// Interval hint for probe duration colouring (fetched from status)
// ---------------------------------------------------------------------------
let pollInterval = 1.0;

// ---------------------------------------------------------------------------
// Fetch and render
// ---------------------------------------------------------------------------
async function updateStatus() {
  const r = await fetch('/api/status').catch(()=>null);
  if (!r?.ok) return;
  const d = await r.json();
  const mb = (d.db_size_bytes/1048576).toFixed(1);
  document.getElementById('dbSize').textContent        = `DB: ${mb} MB`;
  document.getElementById('sampleCount').textContent   = `Samples: ${d.sample_count.toLocaleString()}`;
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
  // Only update dot if monitor is not already stale.
  if (!document.getElementById('staleWarn').style.display || document.getElementById('staleWarn').style.display === 'none') {
    dot.className = `dot ${status}`;
    document.getElementById('statusText').textContent =
      d.notes ? `Fault: ${d.notes}` : 'All metrics within bounds';
  }
  document.getElementById('updated').textContent = `Updated ${new Date().toLocaleTimeString()}`;
}

async function updateHistory() {
  const r = await fetch('/api/history?n=300').catch(()=>null);
  if (!r?.ok) return;
  const rows = await r.json();
  const lbl = rows.map(r => ts(r.timestamp));
  upd(cLatency, lbl, rows.map(r=>r.internet_ping), rows.map(r=>r.gateway_ping));
  upd(cDnsHttp, lbl, rows.map(r=>r.dns_ms),        rows.map(r=>r.http_ms));
  upd(cDnsCmp,  lbl, rows.map(r=>r.dns_ms),        rows.map(r=>r.dns_server_ms));
  upd(cLoss,    lbl, rows.map(r=>r.packet_loss_rate));
  upd(cSys,     lbl, rows.map(r=>r.cpu_pct),       rows.map(r=>r.ram_pct));
}

async function updateWifi() {
  const r = await fetch('/api/wifi?n=300').catch(()=>null);
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

async function updateNic() {
  const r = await fetch('/api/nic?n=300').catch(()=>null);
  if (!r?.ok) return;
  const rows = await r.json();
  if (!rows.length) return;

  // Only show adapters that have carried meaningful traffic (peak > 1 KB/s).
  // This suppresses Hyper-V virtual adapters and idle Wi-Fi from cluttering
  // the throughput chart while keeping them in the timeline.
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

// Stores expanded incident filenames to toggle.
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

async function updateBloat() {
  const r = await fetch('/api/bufferbloat?n=20').catch(()=>null);
  if (!r?.ok) return;
  const rows = await r.json();
  const tb = document.getElementById('tBloat');
  if (!rows.length) {
    tb.innerHTML = '<tr><td colspan="7" class="dim">No scans yet (runs every 5 min)</td></tr>';
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
    tb.innerHTML = '<tr><td colspan="4" class="dim">No tests yet (runs every 15 min)</td></tr>';
    return;
  }

  // Update age label using most recent result (rows are newest-first).
  const latest = rows[0];
  if (latest?.timestamp) {
    const secs = Math.round((Date.now() - new Date(latest.timestamp).getTime()) / 1000);
    const mins = Math.floor(secs / 60);
    document.getElementById('speedAge').textContent =
      `— last test ${mins > 0 ? mins + 'm' : secs + 's'} ago`;
  }

  // Charts expect oldest-first.
  const chronological = [...rows].reverse();
  const labels = chronological.map(r => ts(r.timestamp));
  upd(cSpeedDl, labels, chronological.map(r => r.download_mbps));
  upd(cSpeedUl, labels, chronological.map(r => r.upload_mbps));

  // Colour-code download speed relative to the maximum seen.
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

// Initialise export date pickers to last 24 h.
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
  const table  = document.getElementById('expTable').value;
  const fmt    = document.getElementById('expFmt').value;
  const from   = document.getElementById('expFrom').value;
  const to     = document.getElementById('expTo').value;
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

async function updateNicActive() {
  const r = await fetch('/api/nic/active').catch(()=>null);
  if (!r?.ok) return;
  const d = await r.json();

  // Update the Active Interface metric in the grid.
  const el = document.getElementById('mActiveIface');
  if (d.active) {
    el.textContent = d.active;
    el.className = 'val ok';
  } else {
    el.textContent = '—';
    el.className = 'val dim';
  }

  // Render a ranked interface list below the timeline chart.
  const list = document.getElementById('ifaceList');
  if (!d.interfaces?.length) { list.innerHTML = ''; return; }

  list.innerHTML = d.interfaces.map((iface, i) => {
    const isActive = i === 0 && iface.total_bps > 1024;
    const colour   = isActive ? '#34d399' : '#64748b';
    const kbs      = (iface.total_bps / 1024).toFixed(1);
    return `<div style="color:${colour}">
      ${isActive ? '▶ ' : ''}<strong>${iface.interface}</strong>
      &nbsp;↓${(iface.bytes_recv_ps/1024).toFixed(1)}
      &nbsp;↑${(iface.bytes_sent_ps/1024).toFixed(1)} KB/s
    </div>`;
  }).join('');
}

// Track which interfaces have been added to the timeline chart.
const timelineAdapters = new Set();

async function updateIfaceTimeline() {
  const r = await fetch('/api/nic/timeline?n=300').catch(()=>null);
  if (!r?.ok) return;
  const data = await r.json();

  const ifaces = Object.keys(data);
  if (!ifaces.length) return;

  // Use the first interface's timestamps as the shared x-axis.
  const labels = (data[ifaces[0]] || []).map(s => ts(s.timestamp));

  // Add a dataset for each new interface.
  ifaces.forEach(iface => {
    if (!timelineAdapters.has(iface)) {
      timelineAdapters.add(iface);
      const idx    = timelineAdapters.size - 1;
      const colour = NIC_COLOURS[idx % NIC_COLOURS.length];
      cIfaceTimeline.data.datasets.push(ds(iface, colour));
    }
  });

  cIfaceTimeline.data.labels = labels;

  // Populate each dataset. Use adapter insertion order.
  const ifaceArr = [...timelineAdapters];
  ifaceArr.forEach((iface, i) => {
    const samples = data[iface] || [];
    cIfaceTimeline.data.datasets[i].data = samples.map(s => kb(s.total_bps));
  });

  cIfaceTimeline.update('none');

  // Update the note in the heading.
  document.getElementById('ifaceNote').textContent =
    `— ${ifaces.length} active adapter${ifaces.length !== 1 ? 's' : ''}`;
}


// ---------------------------------------------------------------------------
// On-Demand Actions & Pollers (Feature 1)
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
      statusEl.innerHTML = `<span class="spinner"></span>${actionName} queued (ID ${d.id}), running in background...`;
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
  statusEl.innerHTML = `<span class="spinner"></span>Running traceroute to ${target}... (may take 30-60s)`;
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
// Process Network Hogs (Feature 3)
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

// ---------------------------------------------------------------------------
// Multi-DNS Benchmark (Feature 6)
// ---------------------------------------------------------------------------
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

// ---------------------------------------------------------------------------
// Wi-Fi Channel Overlap (Feature 7)
// ---------------------------------------------------------------------------
async function updateWifiChannels() {
  const r = await fetch('/api/wifi_channels').catch(()=>null);
  if (!r?.ok) return;
  const data = await r.json();
  if (data.recommendation_24) {
    document.getElementById('wifiChanRec').textContent = data.recommendation_24;
  }
  // 2.4 GHz channels 1..13
  const c24Counts = [1,2,3,4,5,6,7,8,9,10,11,12,13].map(ch => data.channels_24[ch]?.count || 0);
  cChan24.data.datasets[0].data = c24Counts;
  cChan24.update('none');

  // 5 GHz channels
  const ch5Keys = Object.keys(data.channels_5).sort((a,b) => Number(a)-Number(b));
  if (ch5Keys.length) {
    cChan5.data.labels = ch5Keys;
    cChan5.data.datasets[0].data = ch5Keys.map(k => data.channels_5[k].count);
    cChan5.update('none');
  }
}

async function refresh() {
  await Promise.all([
    updateStatus(), updateLatest(), updateHistory(),
    updateWifi(), updateNicActive(), updateIfaceTimeline(),
    updateNic(), updateTcp(), updateBloat(), updateSpeed(),
    updateEvents(), updateIncidents(), updateWifiScan(),
    updateProcesses(), updateDnsBenchmark(), updateWifiChannels(),
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
# Entry point
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