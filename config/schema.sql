-- schema.sql -- Network Observability Monitor database schema
--
-- Applied automatically by Storage._apply_schema() on first run.
-- Safe to re-apply on an existing database: all statements use IF NOT EXISTS.
-- New columns on existing tables are added via ALTER TABLE ... ADD COLUMN IF NOT EXISTS
-- so the schema can be re-applied after upgrades without data loss.
--
-- Manual initialisation:
--   sqlite3 data/sqlite/network_monitor.db < config/schema.sql


-- ---------------------------------------------------------------------------
-- samples
-- One row per polling cycle. All timing columns are milliseconds; NULL means
-- the probe failed. probe_duration_ms is the wall-clock time the entire set
-- of probes took; if it exceeds poll_interval_seconds a warning event fires.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS samples (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp         TEXT    NOT NULL,
    probed_host       TEXT,
    internet_ping     REAL,
    gateway_ping      REAL,
    dns_ms            REAL,
    dns_server_ms     REAL,    -- direct UDP latency to the DNS server IP, ms
    http_ms           REAL,
    packet_loss_rate  REAL,
    ip_address        TEXT,
    dns_server        TEXT,
    cpu_pct           REAL,    -- system CPU utilisation % at time of sample
    ram_pct           REAL,    -- system RAM utilisation % at time of sample
    probe_duration_ms REAL,    -- wall-clock time for all probes this cycle, ms
    notes             TEXT    NOT NULL
);

-- ---------------------------------------------------------------------------
-- events
-- Fault events, state changes, Wi-Fi roaming, startup/shutdown, warnings.
-- category: fault | wifi | network | system | info
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT    NOT NULL,
    category  TEXT    NOT NULL DEFAULT 'fault',
    message   TEXT    NOT NULL
);

-- ---------------------------------------------------------------------------
-- wifi_samples -- one row per cycle when Wi-Fi is active
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS wifi_samples (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp     TEXT    NOT NULL,
    ssid          TEXT,
    bssid         TEXT,
    signal_pct    INTEGER,
    channel       INTEGER,
    band          TEXT,
    rx_rate_mbps  REAL,
    tx_rate_mbps  REAL,
    auth          TEXT
);

-- ---------------------------------------------------------------------------
-- nic_samples -- per-NIC I/O rates; rates are per-second deltas
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS nic_samples (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp      TEXT    NOT NULL,
    interface      TEXT    NOT NULL,
    bytes_sent_ps  REAL,
    bytes_recv_ps  REAL,
    errin_ps       REAL,
    errout_ps      REAL,
    dropin_ps      REAL,
    dropout_ps     REAL
);

-- ---------------------------------------------------------------------------
-- tcp_states -- TCP connection counts by state, one row per cycle
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tcp_states (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp    TEXT    NOT NULL,
    established  INTEGER,
    time_wait    INTEGER,
    close_wait   INTEGER,
    syn_sent     INTEGER,
    syn_recv     INTEGER,
    fin_wait1    INTEGER,
    fin_wait2    INTEGER,
    closing      INTEGER,
    last_ack     INTEGER,
    listen       INTEGER,
    other        INTEGER
);

-- ---------------------------------------------------------------------------
-- wifi_scan_results
-- One row per BSSID per scan. A scan runs every wifi.scan_interval_cycles
-- polling cycles (default 60). Each scan inserts all visible networks so
-- the dashboard can show the full RF environment at a point in time.
-- signal_pct is the Windows percentage (0-100); channel is the primary
-- channel number. authentication and cipher come from netsh output directly.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS wifi_scan_results (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_timestamp  TEXT    NOT NULL,  -- ISO-8601 time the scan ran
    ssid            TEXT,              -- network name; empty string = hidden network
    bssid           TEXT    NOT NULL,
    signal_pct      INTEGER,
    channel         INTEGER,
    band            TEXT,              -- 2.4GHz / 5GHz / 6GHz derived from channel
    authentication  TEXT,
    cipher          TEXT
);

-- ---------------------------------------------------------------------------
-- Indexes -- all on timestamp for time-range queries from the dashboard
-- ---------------------------------------------------------------------------
-- ---------------------------------------------------------------------------
-- bufferbloat_samples
-- One row per bufferbloat scan. baseline_ms is the rolling average ping at
-- scan time; loaded_ms is the mean ping RTT measured while a background
-- download saturates the link; delta_ms = loaded_ms - baseline_ms.
-- rating: good (<30 ms delta), moderate (30-100), bad (100-300), severe (>300)
-- download_mbps is the throughput achieved during the test window.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS bufferbloat_samples (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT    NOT NULL,
    baseline_ms     REAL,    -- rolling avg ping before test
    loaded_ms       REAL,    -- mean ping during download
    delta_ms        REAL,    -- loaded_ms - baseline_ms
    rating          TEXT,    -- good / moderate / bad / severe
    download_mbps   REAL,    -- throughput during test window
    ping_host       TEXT,    -- host used for pings during test
    download_url    TEXT     -- URL used for the download
);

-- ---------------------------------------------------------------------------
-- speed_test_results
-- One row per speed test. Download and upload are measured sequentially.
-- All throughput values are Mbps. duration_seconds is the configured test
-- window per direction (download and upload use the same duration).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS speed_test_results (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp           TEXT    NOT NULL,
    download_mbps       REAL,    -- achieved download throughput, Mbps
    upload_mbps         REAL,    -- achieved upload throughput, Mbps
    download_bytes      INTEGER, -- total bytes received during test window
    upload_bytes        INTEGER, -- total bytes sent during test window
    duration_seconds    REAL,    -- configured test duration per direction
    download_url        TEXT,    -- URL used for download
    upload_url          TEXT     -- URL used for upload
);

CREATE INDEX IF NOT EXISTS idx_samples_ts    ON samples             (timestamp);
CREATE INDEX IF NOT EXISTS idx_events_ts     ON events              (timestamp);
CREATE INDEX IF NOT EXISTS idx_wifi_ts       ON wifi_samples        (timestamp);
CREATE INDEX IF NOT EXISTS idx_nic_ts        ON nic_samples         (timestamp);
CREATE INDEX IF NOT EXISTS idx_tcp_ts        ON tcp_states          (timestamp);
CREATE INDEX IF NOT EXISTS idx_scan_ts       ON wifi_scan_results   (scan_timestamp);
CREATE INDEX IF NOT EXISTS idx_bloat_ts      ON bufferbloat_samples (timestamp);
CREATE INDEX IF NOT EXISTS idx_speed_ts      ON speed_test_results  (timestamp);
