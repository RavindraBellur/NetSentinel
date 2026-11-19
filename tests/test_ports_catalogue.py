import re
import unittest

from tests import _env
from netscan import discovery, ports


class Catalogue(unittest.TestCase):
    def test_no_duplicate_ports(self):
        # a duplicated key in a dict literal silently overwrites the first entry
        with open(ports.__file__, encoding="utf-8") as fh:
            keys = re.findall(r"^\s{4}(\d+):\s*\(", fh.read(), re.M)
        self.assertEqual(len(keys), len(set(keys)))

    def test_every_entry_is_complete(self):
        for port, entry in ports.CATALOGUE.items():
            self.assertEqual(len(entry), 5, port)
            self.assertTrue(all(str(x).strip() for x in entry), port)

    def test_camera_ports_graded(self):
        self.assertEqual(ports.CATALOGUE[554][1], ports.HIGH)
        self.assertEqual(ports.CATALOGUE[1900][1], ports.HIGH)

    def test_scanned_tcp_ports_have_advice(self):
        for p in (554, 631, 8000, 8081, 8888, 9000):
            self.assertIn(p, discovery.TCP_PORTS)
            self.assertIn(p, ports.CATALOGUE)


if __name__ == "__main__":
    unittest.main()
