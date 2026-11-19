"""Factory-password check against fake devices on this PC: no false alarms, real hits found."""
import base64
import http.server
import socket
import socketserver
import threading
import unittest

from tests import _env  # noqa: F401
from netscan import defaults as d

CFG = {"defaults_check": {"enabled": True, "i_own_this_network": True, "allow_ips": ["127.0.0.1"],
                          "max_attempts": 30, "delay_ms": 200}}


def web(mode):
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            if mode == "open":
                self.send_response(200); self.end_headers(); self.wfile.write(b"<form>login</form>")
            elif mode == "redirect":
                self.send_response(302); self.send_header("Location", "/login.html"); self.end_headers()
            else:
                pw = b"admin:12345" if mode == "factory" else b"admin:Str0ng!pass"
                if self.headers.get("Authorization") == "Basic " + base64.b64encode(pw).decode():
                    self.send_response(200); self.end_headers()
                else:
                    self.send_response(401); self.send_header("WWW-Authenticate", 'Basic realm="x"')
                    self.end_headers()
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


class HttpChecks(unittest.TestCase):
    def test_page_without_password_is_not_a_finding(self):
        for mode in ("open", "redirect"):
            srv, port = web(mode)
            try:
                self.assertFalse(d.http_demands_login("127.0.0.1", port), mode)
            finally:
                srv.shutdown(); srv.server_close()

    def test_factory_password_found_and_strong_one_not(self):
        srv, port = web("factory")
        try:
            self.assertTrue(d.http_demands_login("127.0.0.1", port))
            self.assertTrue(d.check_http("127.0.0.1", port, "admin", "12345"))
            self.assertFalse(d.check_http("127.0.0.1", port, "admin", "admin"))
        finally:
            srv.shutdown(); srv.server_close()
        srv, port = web("strong")
        try:
            self.assertFalse(any(d.check_http("127.0.0.1", port, u, p) for u, p in d.DEFAULT_CREDENTIALS))
        finally:
            srv.shutdown(); srv.server_close()


def rtsp(mode):
    s = socket.socket(); s.bind(("127.0.0.1", 0)); s.listen(5)

    def run():
        while True:
            try:
                c, _ = s.accept()
            except OSError:
                return
            req = c.recv(1024).decode()
            good = "Authorization: Basic " + base64.b64encode(b"admin:admin").decode()
            ok = mode == "open" or good in req
            c.sendall(b"RTSP/1.0 200 OK\r\n\r\n" if ok else b"RTSP/1.0 401 Unauthorized\r\n\r\n")
            c.close()
    threading.Thread(target=run, daemon=True).start()
    return s, s.getsockname()[1]


class RtspChecks(unittest.TestCase):
    def test_open_stream(self):
        s, port = rtsp("open")
        try:
            self.assertTrue(d.rtsp_opens_without_login("127.0.0.1", port))
            self.assertFalse(d.rtsp_demands_login("127.0.0.1", port))
        finally:
            s.close()

    def test_factory_rtsp_login(self):
        s, port = rtsp("auth")
        try:
            self.assertTrue(d.rtsp_demands_login("127.0.0.1", port))
            self.assertTrue(d.check_rtsp("127.0.0.1", port, "admin", "admin"))
            self.assertFalse(d.check_rtsp("127.0.0.1", port, "admin", "wrong"))
        finally:
            s.close()


class Guards(unittest.TestCase):
    def test_refusals(self):
        base = dict(CFG["defaults_check"])
        self.assertFalse(d.allowed({"defaults_check": dict(base, enabled=False)}, "127.0.0.1")[0])
        self.assertFalse(d.allowed({"defaults_check": dict(base, i_own_this_network=False)}, "127.0.0.1")[0])
        self.assertFalse(d.allowed({"defaults_check": dict(base, allow_ips=[])}, "127.0.0.1")[0])
        public = {"defaults_check": dict(base, allow_ips=["8.8.8.8"])}
        ok, why = d.allowed(public, "8.8.8.8")
        self.assertFalse(ok)
        self.assertIn("not a private LAN address", why)
        lan = {"defaults_check": dict(base, allow_ips=["192.168.1.50"])}
        self.assertTrue(d.allowed(lan, "192.168.1.50")[0])

    def test_scan_device_respects_guards(self):
        dev = {"ip": "8.8.8.8", "ports": [{"port": 80}]}
        cfg = {"defaults_check": dict(CFG["defaults_check"], allow_ips=["8.8.8.8"])}
        self.assertEqual(d.scan_device(dev, cfg), [])


if __name__ == "__main__":
    unittest.main()
