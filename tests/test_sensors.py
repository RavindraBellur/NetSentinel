"""Sensors, quiet hours and dependencies - against real local services, including a self-signed HTTPS server."""
import datetime
import http.server
import os
import socketserver
import ssl
import tempfile
import threading
import unittest

from tests import _env  # noqa: F401
from netscan import poll, sensors, settings, snmp, store


def http_server(status=200, body=b"Booking engine OK"):
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            self.send_response(status); self.end_headers(); self.wfile.write(body)
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def self_signed(days):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "nvr.local")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=days)).sign(key, hashes.SHA256()))
    d = tempfile.mkdtemp()
    cp, kp = os.path.join(d, "c.pem"), os.path.join(d, "k.pem")
    open(cp, "wb").write(cert.public_bytes(serialization.Encoding.PEM))
    open(kp, "wb").write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    return cp, kp


def https_server(days):
    srv, port = http_server()
    cp, kp = self_signed(days)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cp, kp)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    return srv, port


class Checks(unittest.TestCase):
    def test_http_status_and_word(self):
        srv, port = http_server()
        try:
            url = f"http://127.0.0.1:{port}/"
            self.assertEqual(sensors.check_http({"target": url, "expect_text": "booking"})[0], sensors.UP)
            self.assertEqual(sensors.check_http({"target": url, "expect_text": "payment"})[0], sensors.DOWN)
        finally:
            srv.shutdown(); srv.server_close()
        srv, port = http_server(status=500)
        try:
            self.assertEqual(sensors.check_http({"target": f"http://127.0.0.1:{port}/"})[0], sensors.DOWN)
        finally:
            srv.shutdown(); srv.server_close()

    def test_self_signed_certificate_expiry_is_read(self):
        srv, port = https_server(days=10)
        try:
            state, days, msg = sensors.check_cert({"target": "127.0.0.1", "port": port,
                                                   "warn_value": "21", "crit_value": "7"})
            self.assertEqual(state, sensors.WARN, msg)
            self.assertTrue(9 <= days <= 10.5, days)
            self.assertIn("self-signed", msg)
            # a self-signed web page: refused by default, accepted with verify off
            url = f"https://127.0.0.1:{port}/"
            self.assertEqual(sensors.check_http({"target": url})[0], sensors.DOWN)
            self.assertEqual(sensors.check_http({"target": url, "verify": "false"})[0], sensors.UP)
        finally:
            srv.shutdown(); srv.server_close()

    def test_cert_about_to_expire_is_down(self):
        srv, port = https_server(days=3)
        try:
            self.assertEqual(sensors.check_cert({"target": "127.0.0.1", "port": port})[0], sensors.DOWN)
        finally:
            srv.shutdown(); srv.server_close()

    def test_snmp_thresholds_typed_as_text(self):
        real = snmp.get
        try:
            snmp.get = lambda *a, **k: [("1.3.6.1.2.1.33.1.2.4.0", 2, 35)]     # UPS: 35% battery
            base = {"target": "10.0.0.9", "oid": "1.3.6.1.2.1.33.1.2.4.0", "operator": "<"}
            self.assertEqual(sensors.check_snmp(dict(base, warn_value="50", crit_value="20"))[0], sensors.WARN)
            self.assertEqual(sensors.check_snmp(dict(base, warn_value="40", crit_value="38"))[0], sensors.DOWN)
            self.assertEqual(sensors.check_snmp(dict(base, warn_value="", crit_value=""))[0], sensors.UP)
        finally:
            snmp.get = real


class Runner(unittest.TestCase):
    def setUp(self):
        settings.reset()

    def test_already_failing_sensor_alerts_on_first_check(self):
        srv, port = http_server(status=503)
        try:
            settings.save({"sensors": [{"name": "Booking engine", "type": "http",
                                        "target": f"http://127.0.0.1:{port}/", "interval": 15}]})
            changed = sensors.SensorRunner().run_once()
            self.assertEqual([c["state"] for c in changed], [sensors.DOWN])
        finally:
            srv.shutdown(); srv.server_close()

    def test_healthy_first_check_is_quiet_and_change_alerts(self):
        settings.save({"sensors": [{"name": "Gateway", "type": "tcp", "target": "127.0.0.1", "port": 1,
                                    "interval": 15}]})
        r = sensors.SensorRunner()
        self.assertEqual([c["state"] for c in r.run_once()], [sensors.DOWN])   # port 1 is closed
        r.last_run.clear()
        self.assertEqual(r.run_once(), [])                                      # still down: no repeat

    def test_quiet_hours_silence_a_sensor(self):
        now = datetime.datetime.now()
        fmt = "%Y-%m-%d %H:%M"
        settings.save({"sensors": [{"name": "Gateway", "type": "tcp", "target": "127.0.0.1", "port": 1}],
                       "maintenance": [{"match": "Gateway", "from": (now - datetime.timedelta(hours=1)).strftime(fmt),
                                        "to": (now + datetime.timedelta(hours=1)).strftime(fmt), "reason": "ISP work"}]})
        r = sensors.SensorRunner()
        self.assertEqual(r.run_once(), [])
        self.assertTrue(r.states[next(iter(r.states))]["maintenance"])


class HistoryAndNewKinds(unittest.TestCase):
    def test_proc_check(self):
        import os, sys
        me = os.path.basename(sys.executable).lower()[:6]          # e.g. "python"
        self.assertEqual(sensors.check_proc({"target": me})[0], sensors.UP)
        self.assertEqual(sensors.check_proc({"target": "no-such-process-xyz"})[0], sensors.DOWN)

    def test_service_check_unknown_service_is_down(self):
        state, _v, msg = sensors.check_service({"target": "no-such-service-xyz"})
        self.assertEqual(state, sensors.DOWN)

    def test_history_saved_read_and_pruned(self):
        store.add_sensor_sample("S-test", "up", 12.5)
        store.add_sensor_sample("S-test", "down", None)
        summary = store.sensor_summary("S-test", 24)
        self.assertEqual(summary["count"], 2)
        self.assertEqual(summary["up_pct"], 50.0)
        store._exec("INSERT INTO sensor_samples (id, ts, state, value) VALUES (?,?,?,?)",
                    ("S-test", 1000, "up", 1.0))                    # a sample from 1970
        store.prune_sensor_samples(30)
        self.assertEqual(store.sensor_summary("S-test", 24 * 365 * 60)["count"], 2)


class FakeScanner:
    flow = None
    gateway_state = {}


class DeviceNoiseControl(unittest.TestCase):
    """Dependencies and quiet hours stop device incidents from opening."""

    def setUp(self):
        settings.reset()
        self.p = poll.Poller(FakeScanner(), log=lambda m: None)
        self.th = settings.get("thresholds")

    def run_bad(self, ip, times=4):
        for _ in range(times):
            self.p._incident_machine(ip, {"ip": ip, "label": ip}, "down", 0, 100, [], [], self.th,
                                     settings.load())

    def test_child_behind_dead_parent_is_suppressed_and_chains(self):
        settings.save({"dependencies": {"10.0.0.30": "10.0.0.2", "10.0.0.31": "10.0.0.30"}})
        self.p.device_state["10.0.0.2"] = {"state": "down", "bad": 5, "good": 0, "incident": "x", "sev": ""}
        self.run_bad("10.0.0.30")
        self.run_bad("10.0.0.31")
        self.assertIsNone(self.p.device_state["10.0.0.30"]["incident"])
        self.assertIsNone(self.p.device_state["10.0.0.31"]["incident"])
        self.assertIn("parent", self.p.device_state["10.0.0.31"]["suppressed"])

    def test_quiet_hours_silence_a_device(self):
        now = datetime.datetime.now()
        fmt = "%Y-%m-%d %H:%M"
        settings.save({"maintenance": [{"match": "10.0.0.40", "from": (now - datetime.timedelta(hours=1)).strftime(fmt),
                                        "to": (now + datetime.timedelta(hours=1)).strftime(fmt), "reason": "AP swap"}]})
        self.run_bad("10.0.0.40")
        self.assertIsNone(self.p.device_state["10.0.0.40"]["incident"])
        self.assertEqual(self.p.device_state["10.0.0.40"]["suppressed"], "AP swap")
        events = [e for e in store.events(limit=50) if "quiet hours" in (e.get("message") or "")]
        self.assertTrue(events)


if __name__ == "__main__":
    unittest.main()
