"""UDP service probes against fake services: a port counts as open only when the service answers."""
import socket
import struct
import threading
import unittest

from tests import _env  # noqa: F401
from netscan import discovery, ports


def udp_server(reply_fn):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))

    def run():
        while True:
            try:
                data, addr = s.recvfrom(4096)
            except OSError:
                return
            out = reply_fn(data)
            if out:
                s.sendto(out, addr)
    threading.Thread(target=run, daemon=True).start()
    return s, s.getsockname()[1]


def nbstat_reply(_req):
    name = b"RECEPTION-PC   " + b"\x00"            # 15 chars + suffix 0x00 (workstation)
    rd = bytes([1]) + name + b"\x04\x00" + b"\x00" * 6
    head = b"\xab\xcd\x84\x00\x00\x00\x00\x01\x00\x00\x00\x00"
    question = b"\x20" + b"CK" + b"A" * 30 + b"\x00" + b"\x00\x21\x00\x01"
    return head + question + b"\x00\x00\x00\x00" + struct.pack(">H", len(rd)) + rd


class UdpProbes(unittest.TestCase):
    def tearDown(self):
        for s in getattr(self, "_socks", []):
            s.close()

    def serve(self, fn):
        s, port = udp_server(fn)
        self._socks = getattr(self, "_socks", []) + [s]
        return port

    def test_ntp(self):
        port = self.serve(lambda req: b"\x1c" + b"\x00" * 47 if req[0] == 0x1b else b"")
        self.assertTrue(discovery.probe_ntp("127.0.0.1", port))
        garbage = self.serve(lambda req: b"hello")
        self.assertFalse(discovery.probe_ntp("127.0.0.1", garbage))

    def test_upnp_reports_server_header(self):
        port = self.serve(lambda req: (b"HTTP/1.1 200 OK\r\nSERVER: Linux/3.10 UPnP/1.0 Hikvision-Webs/1.0\r\n"
                                       b"ST: upnp:rootdevice\r\n\r\n") if req.startswith(b"M-SEARCH") else b"")
        self.assertIn("Hikvision", discovery.probe_ssdp("127.0.0.1", port))

    def test_mdns(self):
        port = self.serve(lambda req: req[:2] + b"\x84\x00" + b"\x00\x00\x00\x01\x00\x00\x00\x00")
        self.assertTrue(discovery.probe_mdns("127.0.0.1", port))

    def test_netbios_name(self):
        port = self.serve(nbstat_reply)
        self.assertEqual(discovery.netbios_name("127.0.0.1", 1.0, port=port), "RECEPTION-PC")
        self.assertTrue(discovery.probe_netbios("127.0.0.1", port))

    def test_silence_is_not_open(self):
        silent = self.serve(lambda req: b"")
        self.assertFalse(discovery.probe_ntp("127.0.0.1", silent, timeout=0.3))
        self.assertEqual(discovery.probe_ssdp("127.0.0.1", silent, timeout=0.3), "")
        self.assertFalse(discovery.probe_mdns("127.0.0.1", silent, timeout=0.3))


class SnmpCommunities(unittest.TestCase):
    def test_configured_community_is_tried(self):
        from netscan import settings, snmp
        settings.reset()
        settings.save({"discovery": {"snmp_communities": ["hotel-ro-2026"]}})
        real = snmp.get
        try:
            snmp.get = lambda ip, oids, community="public", timeout=1.0, retries=1: (
                [(oids[0], 4, "Aruba Instant On AP22")] if community == "hotel-ro-2026" else None)
            self.assertEqual(discovery.probe_snmp("192.168.1.40"), "hotel-ro-2026")
            self.assertEqual(discovery.snmp_communities()[0], "hotel-ro-2026")
            snmp.get = lambda *a, **k: None
            self.assertEqual(discovery.probe_snmp("192.168.1.41"), "")
        finally:
            snmp.get = real
            settings.reset()


class Coverage(unittest.TestCase):
    def test_every_catalogued_service_is_probed(self):
        probed = set(discovery.TCP_PORTS) | set(discovery.UDP_SERVICES)
        for port in (25, 123, 137, 161, 554, 587, 631, 993, 995, 1900, 5353, 8000, 8081, 8888, 9000):
            self.assertIn(port, probed)
            self.assertIn(port, ports.CATALOGUE)
        for udp in discovery.UDP_SERVICES:
            self.assertNotIn(udp, discovery.TCP_PORTS)

    def test_exposure_marks_udp_and_names_upnp_device(self):
        dev = {"ip": "192.168.1.30", "label": "Lobby NVR", "type": "nvr",
               "upnp_server": "Hikvision-Webs/1.0",
               "ports": [{"port": 554, "proto": "tcp"}, {"port": 1900, "proto": "udp"}]}
        found = {f["port"]: f for f in ports.exposure([dev])["findings"]}
        self.assertEqual(found[1900]["proto"], "udp")
        self.assertEqual(found[1900]["risk"], ports.HIGH)
        self.assertIn("Hikvision", found[1900]["why"])
        self.assertEqual(found[554]["risk"], ports.HIGH)


if __name__ == "__main__":
    unittest.main()
