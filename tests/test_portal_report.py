"""Reporting to the Prahari portal: a portal token alone is enough, and reporting starts on Save."""
import http.server
import json
import threading
import unittest

from tests import _env  # noqa: F401
from netscan import settings, sites


class FakeScanner:
    branch_reporter = None

    def snapshot(self):
        return {"version": "test", "health": {"score": 90, "up": 9, "down": 1, "monitored": 10},
                "devices": [{}] * 10, "open_incidents": [], "traffic": {}, "internet": []}


class PortalTarget(unittest.TestCase):
    def tearDown(self):
        settings.save({"branch": {"hub_url": "", "token": ""}})

    def test_portal_token_needs_no_hub_url(self):
        settings.save({"branch": {"hub_url": "", "token": "psk_abc"}})
        self.assertEqual(sites.branch_target(), (sites.PORTAL_URL, "psk_abc"))

    def test_other_token_still_needs_a_hub_url(self):
        settings.save({"branch": {"hub_url": "", "token": "nsb_abc"}})
        self.assertEqual(sites.branch_target(), ("", ""))
        settings.save({"branch": {"hub_url": "http://10.0.0.5:8777/", "token": "nsb_abc"}})
        self.assertEqual(sites.branch_target(), ("http://10.0.0.5:8777", "nsb_abc"))

    def test_report_goes_to_the_configured_hub_with_the_token(self):
        got = {}

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                got["path"] = self.path
                got["token"] = self.headers.get("X-Branch-Token")
                got["body"] = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"ok": true}')

        srv = http.server.HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            settings.save({"branch": {"hub_url": f"http://127.0.0.1:{srv.server_port}", "token": "psk_live"}})
            rep = sites.BranchReporter(FakeScanner())
            self.assertTrue(rep.push(), rep.last_error)
            self.assertEqual(got["path"], sites.REPORT_PATH)
            self.assertEqual(got["token"], "psk_live")
            self.assertEqual(got["body"]["health"]["score"], 90)
        finally:
            srv.shutdown()


if __name__ == "__main__":
    unittest.main()
