"""Both internet lines of a dual-WAN firewall, read over SNMP (interface IPs + up/down)."""
import threading
import unittest

from tests import _env  # noqa: F401
from netscan import monitor, sites, snmp


class FakeScanner:
    def __init__(self):
        self.lock = threading.RLock()
        self.devices = {}
        self.snmp_interfaces = {}
        self.snmp_port_map = {}
        self.wan_rate = {}

    def snapshot(self):
        return {"health": {}, "devices": [], "open_incidents": [], "traffic": {}, "internet": [],
                "wan": {"ips": ["106.51.126.176"], "isp": "ACT"}}


# A Sophos-like firewall: Port1 LAN, Port2 ACT (public, up), Port3 Jio (public, DOWN), Port4 guest LAN
MIB = {
    snmp.OID_IF_NAME: [("1", "Port1"), ("2", "Port2"), ("3", "Port3"), ("4", "Port4"), ("5", "lo")],
    snmp.OID_IP_AD_IFINDEX: [("192.168.0.1", 1), ("106.51.126.176", 2), ("49.207.12.9", 3), ("10.10.0.1", 4), ("127.0.0.1", 5)],
    snmp.OID_IF_OPER: [("1", 1), ("2", 1), ("3", 2), ("4", 1), ("5", 1)],
}


def fake_walk_bulk(host, base, community="public", timeout=1.5, max_rows=4000):
    return [(base + "." + k, 4 if isinstance(v, str) else 2, v) for k, v in MIB.get(base, [])]


class WanLines(unittest.TestCase):
    def setUp(self):
        self.real = snmp.walk_bulk
        snmp.walk_bulk = fake_walk_bulk

    def tearDown(self):
        snmp.walk_bulk = self.real

    def test_ifname_oid_exists(self):
        self.assertEqual(snmp.OID_IF_NAME, "1.3.6.1.2.1.31.1.1.1.1", "the interface poller needs ifName")

    def test_both_public_lines_found_with_their_state(self):
        sc = FakeScanner()
        p = monitor.SnmpPoller.__new__(monitor.SnmpPoller)
        p.scanner = sc
        p._prev, p._fdb_cache, p.fdb_interval = {}, {}, 600
        p._poll_host("192.168.0.1", "prahari-ro")
        lines = {x["ip"]: x for x in sc.wan_lines}
        self.assertEqual(set(lines), {"106.51.126.176", "49.207.12.9"}, "only the internet-facing interfaces")
        self.assertTrue(lines["106.51.126.176"]["up"])
        self.assertFalse(lines["49.207.12.9"]["up"], "the idle/backup line's real state")
        self.assertEqual(lines["49.207.12.9"]["interface"], "Port3")
        rep = sites.summary(sc)
        self.assertEqual(len(rep["wan"]["lines"]), 2, "both lines go to the portal")
        sc.wan_lines_at -= 1000
        self.assertEqual(sites.summary(sc)["wan"]["lines"], [], "stale readings are not reported")


if __name__ == "__main__":
    unittest.main()
