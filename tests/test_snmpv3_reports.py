import os
import tempfile
import unittest

from tests import _env  # noqa: F401
from netscan import snmpv3


class SnmpV3(unittest.TestCase):
    def test_rfc3414_key_localisation_vectors(self):
        eid = bytes.fromhex("000000000000000000000002")
        self.assertEqual(snmpv3.password_to_key("maplesyrup", eid, "md5").hex(),
                         "526f5eed9fcce26f8964c2930787d82b")
        self.assertEqual(snmpv3.password_to_key("maplesyrup", eid, "sha1").hex(),
                         "6695febc9288e36282235fc7151f128497b38f3f")


class Reports(unittest.TestCase):
    def test_sla_pdf_is_written(self):
        from netscan import sla
        out = tempfile.mkdtemp()
        path = sla.render(None, site="Test Site", out_dir=out)
        with open(path, "rb") as fh:
            data = fh.read()
        self.assertTrue(data.startswith(b"%PDF-"))
        self.assertIn(b"%%EOF", data[-64:])
        self.assertGreater(os.path.getsize(path), 1000)


if __name__ == "__main__":
    unittest.main()
