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

    def test_organisation_key_needs_no_hub_url_but_a_site_name(self):
        settings.save({"site_name": ""})
        ok, msg = sites.connect_portal("pok_" + "k" * 30)
        self.assertFalse(ok)
        self.assertIn("name", msg)
        ok, _ = sites.connect_portal("pok_" + "k" * 30, "Corporate Office")
        self.assertTrue(ok)
        self.assertEqual(sites.branch_target(), (sites.PORTAL_URL, "pok_" + "k" * 30))
        self.assertEqual(sites.summary.__name__, "summary")

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


class FullReport(unittest.TestCase):
    def test_report_carries_every_device_compactly(self):
        devs = [{"ip": f"10.0.0.{i}", "mac": "aa:bb", "hostname": f"host{i}", "vendor": "Hikvision", "type_label": "Camera",
                 "state": "down" if i == 3 else "up", "latency_ms": 2.345, "loss_pct": 0, "ports": [{"port": 80}, 554, "x"],
                 "is_gateway": i == 1} for i in range(1, 251)]

        class S(FakeScanner):
            def snapshot(self):
                return {"health": {}, "devices": devs, "open_incidents": [{"id": n, "title": f"t{n}"} for n in range(70)],
                        "traffic": {"top": [{"name": str(n)} for n in range(20)]}, "internet": []}
        rep = sites.summary(S())
        self.assertEqual(rep["devices"], 250)
        self.assertEqual(len(rep["device_list"]), 250)
        d3 = [d for d in rep["device_list"] if d["ip"] == "10.0.0.3"][0]
        self.assertEqual((d3["name"], d3["type"], d3["state"], d3["lat"], d3["ports"]), ("host3", "Camera", "down", 2.3, [80, 554]))
        self.assertTrue([d for d in rep["device_list"] if d["ip"] == "10.0.0.1"][0]["gw"])
        self.assertEqual(len(rep["incidents"]), 50)
        self.assertEqual(len(rep["traffic"]["top"]), 10)
        self.assertRegex(rep["install_id"], r"^[0-9a-f]{16}$")
        self.assertEqual(rep["install_id"], sites.summary(S())["install_id"], "the id stays the same")
        self.assertLess(len(json.dumps(rep)), 256 * 1024, "a 250-device report stays well under the portal's limit")


class DeviceListOnlyWhenNeeded(unittest.TestCase):
    def test_list_sent_on_change_and_every_5_minutes_only(self):
        bodies = []

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                bodies.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"ok": true}')

        devs = [{"ip": "10.0.0.%d" % i, "state": "up", "hostname": "d%d" % i} for i in range(1, 40)]

        class S(FakeScanner):
            standby = ""

            def snapshot(self):
                return {"health": {}, "devices": devs, "open_incidents": [], "traffic": {}, "internet": []}
        srv = http.server.HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            settings.save({"branch": {"hub_url": f"http://127.0.0.1:{srv.server_port}", "token": "psk_x"}})
            rep = sites.BranchReporter(S())
            rep.push(); rep.push()
            self.assertIn("device_list", bodies[0], "first report carries the list")
            self.assertNotIn("device_list", bodies[1], "an unchanged list is not sent again")
            self.assertEqual(bodies[1]["devices"], 39, "totals are always sent")
            devs[3]["state"] = "down"
            rep.push()
            self.assertIn("device_list", bodies[2], "a device changing state sends the list")
            rep._list_at -= sites.LIST_EVERY + 1
            rep.push()
            self.assertIn("device_list", bodies[3], "and at least every 5 minutes")
        finally:
            srv.shutdown()
            settings.save({"branch": {"hub_url": "", "token": ""}})


class OnePerNetwork(unittest.TestCase):
    def test_network_fingerprint(self):
        gw = {"ip": "192.168.0.1", "mac": "AA:BB:CC:00:11:22", "is_gateway": True}
        a = sites.network_id({"devices": [gw]})
        self.assertTrue(a.startswith("mac:"))
        self.assertEqual(a, sites.network_id({"devices": [dict(gw, mac="aa:bb:cc:00:11:22")]}), "MAC case does not matter")
        self.assertNotEqual(a, sites.network_id({"devices": [dict(gw, mac="aa:bb:cc:00:11:23")]}), "another router = another network")
        same_range = {"local": {"network": "192.168.0.0/24", "gateway": "192.168.0.1"}}
        self.assertEqual(sites.network_id(same_range), "", "subnet alone is not enough - every office has 192.168.0.x")
        x = sites.network_id(dict(same_range, public={"ip": "49.36.1.2"}))
        y = sites.network_id(dict(same_range, public={"ip": "103.5.6.7"}))
        self.assertTrue(x.startswith("net:") and x != y, "same IP range behind different internet lines = different networks")

    def test_refused_report_puts_this_copy_in_standby_and_a_good_one_resumes(self):
        answer = {"code": 409, "body": b'{"standby": true, "error": "Another Prahari already watches this network."}'}

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                self.rfile.read(int(self.headers["Content-Length"]))
                self.send_response(answer["code"])
                self.end_headers()
                self.wfile.write(answer["body"])

        srv = http.server.HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            settings.save({"branch": {"hub_url": f"http://127.0.0.1:{srv.server_port}", "token": "psk_x"}})
            sc = FakeScanner()
            sc.standby = ""
            rep = sites.BranchReporter(sc)
            self.assertFalse(rep.push())
            self.assertIn("Another Prahari", sc.standby)
            self.assertIn("Another Prahari", rep.status()["standby"])
            from netscan import poll
            p = poll.Poller.__new__(poll.Poller)
            p.scanner = sc
            self.assertIsNone(p.poll_once(), "no polling (so no alerts) in standby")
            answer.update(code=200, body=b'{"ok": true}')
            self.assertTrue(rep.push())
            self.assertEqual(sc.standby, "", "takes over when the portal accepts it")
        finally:
            srv.shutdown()
            settings.save({"branch": {"hub_url": "", "token": ""}})


class ConnectPortal(unittest.TestCase):
    def tearDown(self):
        settings.save({"branch": {"hub_url": "", "token": ""}, "portal": {"asked": False, "dismissed": False}})

    def test_rejects_things_that_are_not_portal_tokens(self):
        for bad in ("", "hello", "nsb_" + "a" * 30, "psk_short", "psk_" + "a" * 30 + " ; rm"):
            ok, msg = sites.connect_portal(bad)
            self.assertFalse(ok, bad)
        self.assertEqual(sites.branch_target(), ("", ""))

    def test_saves_token_name_and_points_at_the_portal(self):
        ok, _ = sites.connect_portal('  "psk_' + "A1b2-_" * 5 + '"  ', "SLIPL Corporate Office")
        self.assertTrue(ok)
        self.assertEqual(settings.get("site_name"), "SLIPL Corporate Office")
        self.assertEqual(sites.branch_target(), (sites.PORTAL_URL, "psk_" + "A1b2-_" * 5))
        self.assertTrue(settings.get("portal")["asked"])


if __name__ == "__main__":
    unittest.main()
