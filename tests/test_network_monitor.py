import os
import sqlite3
import tempfile
import unittest
from unittest import mock

import advanced_network_monitor as anm
import web_dashboard


class TestNetworkMonitor(unittest.TestCase):
    def test_rolling_stats(self):
        stats = anm.RollingStats(size=10)
        self.assertEqual(stats.average(), 0.0)
        self.assertEqual(stats.jitter(), 0.0)
        self.assertEqual(stats.packet_loss_rate(), 0.0)

        stats.add(10.0)
        stats.add(20.0)
        stats.add(None)  # lost packet
        stats.add(30.0)

        self.assertEqual(stats.average(), 20.0)
        self.assertAlmostEqual(stats.packet_loss_rate(), 25.0)
        # Differences: |20 - 10| = 10, |30 - 20| = 10 -> jitter = 10.0
        self.assertEqual(stats.jitter(), 10.0)

    def test_host_cycler(self):
        cycler = anm.HostCycler(["a.com", "b.com"])
        self.assertEqual(cycler.next(), "a.com")
        self.assertEqual(cycler.next(), "b.com")
        self.assertEqual(cycler.next(), "a.com")
        self.assertEqual(cycler.all(), ["a.com", "b.com"])

        with self.assertRaises(ValueError):
            anm.HostCycler([])

    def test_ping_rtt_parsing(self):
        parse = anm.parse_ping_rtt
        self.assertEqual(parse("Reply from 1.1.1.1: bytes=32 time=9ms TTL=59\r\n"), 9.0)
        self.assertEqual(parse("Reply from 192.168.1.1: bytes=32 time<1ms TTL=64\r\n"), 0.5)
        # Localised output must not be reported as packet loss
        self.assertEqual(parse("Antwort von 8.8.8.8: Bytes=32 Zeit=14ms TTL=117\r\n"), 14.0)
        self.assertEqual(parse("Réponse de 8.8.8.8 : octets=32 temps=14 ms TTL=117\r\n"), 14.0)
        self.assertEqual(parse("Ответ от 8.8.8.8: число байт=32 время=14мс TTL=117\r\n"), 14.0)
        # Failures
        self.assertIsNone(parse("Request timed out.\r\n"))
        self.assertIsNone(parse("Reply from 192.168.1.1: Destination host unreachable.\r\n"))

    def test_lan_scan_tags_gateway(self):
        arp_out = (
            "Interface: 192.168.1.5 --- 0x5\n"
            "  Internet Address      Physical Address      Type\n"
            "  192.168.1.1           cc-28-aa-00-00-01     dynamic\n"
            "  192.168.1.20          b8-27-eb-00-00-02     dynamic\n"
        )
        with mock.patch.object(anm.cmd_logger, "check_output", return_value=arp_out):
            devices = anm.LanNeighborProbe().scan(gateway_ip="192.168.1.1")
        types = {d.ip_address: d.device_type for d in devices}
        self.assertEqual(types, {"192.168.1.1": "gateway", "192.168.1.20": "dynamic"})

    def test_purge_keeps_devices_still_seen(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = anm.Storage(os.path.join(tmpdir, "test.db"))
            try:
                old = "2000-01-01T00:00:00"
                now = anm.datetime.now().isoformat()
                storage.upsert_lan_devices([
                    anm.LanDevice(old, "10.0.0.2", "aa:bb:cc:dd:ee:ff", "x", "10.0.0.5", "dynamic", now),
                    anm.LanDevice(old, "10.0.0.3", "aa:bb:cc:dd:ee:00", "x", "10.0.0.5", "dynamic", old),
                ])
                storage.purge_old_rows(retention_days=30)
                ips = [r[0] for r in storage.connection.execute("SELECT ip_address FROM lan_devices")]
                self.assertEqual(ips, ["10.0.0.2"])
            finally:
                storage.close()

    def test_web_dashboard_config_file_exists(self):
        self.assertTrue(web_dashboard.CONFIG_FILE.is_file())

    def test_storage_thread_safety_and_actions(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            storage = anm.Storage(db_path)
            try:
                # Test WAL mode enabled
                cur = storage.connection.execute("PRAGMA journal_mode;")
                mode = cur.fetchone()[0]
                self.assertEqual(mode.lower(), "wal")

                # Test action queue
                storage.connection.execute(
                    "INSERT INTO action_queue (timestamp, action, payload, status) VALUES (?,?,?,?)",
                    ("2026-10-22T22:00:00", "speedtest", "", "pending"),
                )
                storage.connection.commit()

                pending = storage.poll_pending_action()
                self.assertIsNotNone(pending)
                self.assertEqual(pending["action"], "speedtest")

                # Next poll should be empty since status was set to running
                self.assertIsNone(storage.poll_pending_action())

                storage.update_action(pending["id"], "completed", "Test success")
                cur = storage.connection.execute(
                    "SELECT status, result FROM action_queue WHERE id = ?", (pending["id"],)
                )
                row = cur.fetchone()
                self.assertEqual(row[0], "completed")
                self.assertEqual(row[1], "Test success")
            finally:
                storage.close()

    def test_storage_device_discovery_and_mtu(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            storage = anm.Storage(db_path)
            try:
                # LAN devices upsert
                storage.upsert_lan_devices([
                    anm.LanDevice(
                        timestamp="2026-10-23T05:00:00",
                        ip_address="10.0.10.1",
                        mac_address="cc:28:aa:11:22:33",
                        vendor="Ubiquiti",
                        interface_ip="10.0.10.100",
                        device_type="gateway",
                        last_seen="2026-10-23T05:00:00",
                    ),
                    anm.LanDevice(
                        timestamp="2026-10-23T05:00:00",
                        ip_address="10.0.10.50",
                        mac_address="b8:27:eb:11:22:33",
                        vendor="Raspberry Pi",
                        interface_ip="10.0.10.100",
                        device_type="host",
                        last_seen="2026-10-23T05:00:00",
                    ),
                ])

                cur = storage.connection.execute("SELECT COUNT(*) FROM lan_devices")
                self.assertEqual(cur.fetchone()[0], 2)

                # Upsert update last_seen
                storage.upsert_lan_devices([
                    anm.LanDevice(
                        timestamp="2026-10-23T05:05:00",
                        ip_address="10.0.10.1",
                        mac_address="cc:28:aa:11:22:33",
                        vendor="Ubiquiti",
                        interface_ip="10.0.10.100",
                        device_type="gateway",
                        last_seen="2026-10-23T05:05:00",
                    )
                ])
                cur = storage.connection.execute("SELECT last_seen FROM lan_devices WHERE ip_address='10.0.10.1'")
                self.assertEqual(cur.fetchone()[0], "2026-10-23T05:05:00")

                # mDNS devices upsert
                storage.upsert_mdns_devices([
                    anm.MdnsDevice(
                        timestamp="2026-10-23T05:00:00",
                        ip_address="10.0.10.50",
                        hostname="raspberrypi.local",
                        services=["_ssh._tcp.local", "_http._tcp.local"],
                        last_seen="2026-10-23T05:00:00",
                    )
                ])
                cur = storage.connection.execute("SELECT hostname FROM mdns_devices WHERE ip_address='10.0.10.50'")
                self.assertEqual(cur.fetchone()[0], "raspberrypi.local")

                # Path MTU sample insert
                storage.insert_mtu_sample(anm.MtuSample(
                    timestamp="2026-10-23T05:00:00",
                    target_host="1.1.1.1",
                    max_unfragmented_payload=1464,
                    path_mtu=1492,
                    status="reduced",
                    notes="Reduced MTU (1492), likely PPPoE or VPN",
                ))
                cur = storage.connection.execute("SELECT path_mtu FROM mtu_samples WHERE target_host='1.1.1.1'")
                self.assertEqual(cur.fetchone()[0], 1492)
            finally:
                storage.close()

    def test_n_param_sanitization(self):
        with web_dashboard.app.test_request_context("/api/history?n=-1"):
            self.assertEqual(web_dashboard.n_param(), 1)

        with web_dashboard.app.test_request_context("/api/history?n=50000"):
            self.assertEqual(web_dashboard.n_param(), 10000)

        with web_dashboard.app.test_request_context("/api/history?n=invalid"):
            self.assertEqual(web_dashboard.n_param(), 300)

    def test_web_dashboard_routes(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            storage = anm.Storage(db_path)
            try:
                # Populate sample data
                s = anm.Sample(
                    timestamp="2026-10-22T22:00:00",
                    probed_host="1.1.1.1",
                    internet_ping=12.5,
                    gateway_ping=1.0,
                    dns_ms=15.0,
                    dns_server_ms=14.0,
                    http_ms=45.0,
                    packet_loss_rate=0.0,
                    ip_address="192.168.1.100",
                    dns_server="1.1.1.1",
                    cpu_pct=5.0,
                    ram_pct=40.0,
                    probe_duration_ms=120.0,
                    notes="",
                )
                storage.insert_sample(s)

                storage.insert_process_samples([
                    anm.ProcessSample(
                        timestamp="2026-10-22T22:00:00",
                        pid=1234,
                        name="testapp.exe",
                        conn_count=3,
                        read_bytes_ps=50000.0,
                        write_bytes_ps=10000.0,
                    )
                ])

                storage.insert_dns_benchmark(anm.DnsBenchmarkSample(
                    timestamp="2026-10-22T22:00:00",
                    local_ms=25.0,
                    cloudflare_ms=12.0,
                    google_ms=18.0,
                    quad9_ms=20.0,
                    fastest="Cloudflare",
                ))

                storage.insert_wifi_scan([
                    anm.WifiScanEntry(
                        scan_timestamp="2026-10-22T22:00:00",
                        ssid="TestWifi",
                        bssid="aa:bb:cc:dd:ee:ff",
                        signal_pct=85,
                        channel=6,
                        band="2.4GHz",
                        authentication="WPA2",
                        cipher="CCMP",
                    ),
                    anm.WifiScanEntry(
                        scan_timestamp="2026-10-22T22:00:00",
                        ssid="OtherWifi",
                        bssid="11:22:33:44:55:66",
                        signal_pct=40,
                        channel=11,
                        band="2.4GHz",
                        authentication="WPA2",
                        cipher="CCMP",
                    ),
                ])

                storage.upsert_lan_devices([
                    anm.LanDevice(
                        timestamp="2026-10-23T05:00:00",
                        ip_address="10.0.10.1",
                        mac_address="cc:28:aa:11:22:33",
                        vendor="Ubiquiti",
                        interface_ip="10.0.10.100",
                        device_type="gateway",
                        last_seen="2026-10-23T05:00:00",
                    )
                ])

                storage.upsert_mdns_devices([
                    anm.MdnsDevice(
                        timestamp="2026-10-23T05:00:00",
                        ip_address="10.0.10.50",
                        hostname="raspberrypi.local",
                        services=["_ssh._tcp.local"],
                        last_seen="2026-10-23T05:00:00",
                    )
                ])

                storage.insert_mtu_sample(anm.MtuSample(
                    timestamp="2026-10-23T05:00:00",
                    target_host="1.1.1.1",
                    max_unfragmented_payload=1464,
                    path_mtu=1492,
                    status="reduced",
                    notes="Reduced MTU (1492), likely PPPoE or VPN",
                ))
            finally:
                storage.close()

            web_dashboard.DB_PATH = db_path
            web_dashboard.INCIDENTS_PATH = os.path.join(tmpdir, "incidents")
            os.makedirs(web_dashboard.INCIDENTS_PATH, exist_ok=True)

            client = web_dashboard.app.test_client()

            # Test /api/latest
            resp = client.get("/api/latest")
            self.assertEqual(resp.status_code, 200)
            self.assertEqual(resp.json["probed_host"], "1.1.1.1")

            # Test /api/processes (Feature 3)
            resp = client.get("/api/processes")
            self.assertEqual(resp.status_code, 200)
            self.assertEqual(len(resp.json), 1)
            self.assertEqual(resp.json[0]["name"], "testapp.exe")

            # Test /api/dns_benchmark (Feature 6)
            resp = client.get("/api/dns_benchmark")
            self.assertEqual(resp.status_code, 200)
            self.assertEqual(len(resp.json), 1)
            self.assertEqual(resp.json[0]["fastest"], "Cloudflare")

            # Test /api/wifi_channels (Feature 7)
            resp = client.get("/api/wifi_channels")
            self.assertEqual(resp.status_code, 200)
            self.assertIn("recommendation_24", resp.json)
            self.assertEqual(resp.json["best_channel_24"], 1)

            # Test /api/lan_devices (Feature: LAN Neighbor discovery)
            resp = client.get("/api/lan_devices")
            self.assertEqual(resp.status_code, 200)
            self.assertEqual(len(resp.json), 1)
            self.assertEqual(resp.json[0]["vendor"], "Ubiquiti")

            # Test /api/mdns (Feature: mDNS / ZeroConf)
            resp = client.get("/api/mdns")
            self.assertEqual(resp.status_code, 200)
            self.assertEqual(len(resp.json), 1)
            self.assertEqual(resp.json[0]["hostname"], "raspberrypi.local")

            # Test /api/mtu (Feature: Path MTU)
            resp = client.get("/api/mtu")
            self.assertEqual(resp.status_code, 200)
            self.assertEqual(len(resp.json), 1)
            self.assertEqual(resp.json[0]["path_mtu"], 1492)

            # Test /api/export (Feature: Data export)
            resp = client.get("/api/export?table=lan_devices&format=json")
            self.assertEqual(resp.status_code, 200)
            self.assertIn("application/json", resp.content_type)

            resp_csv = client.get("/api/export?table=lan_devices&format=csv")
            self.assertEqual(resp_csv.status_code, 200)
            self.assertIn("text/csv", resp_csv.content_type)

            # Test /api/actions POST & GET (Feature 1 + New actions)
            for act in ["speedtest", "lanscan", "mdnsscan", "mtuscan"]:
                resp = client.post("/api/actions", json={"action": act})
                self.assertEqual(resp.status_code, 202)
                self.assertIn("id", resp.json)

            resp = client.get("/api/actions/latest")
            self.assertEqual(resp.status_code, 200)
            self.assertTrue(len(resp.json) >= 4)


if __name__ == "__main__":
    unittest.main()
