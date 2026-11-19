"""Windows sign-in. Logic tests run everywhere; the real-Windows test runs on the CI Windows
runner, which creates a throw-away administrator and a standard user first (NS_TEST_WIN_* env)."""
import os
import unittest

from tests import _env  # noqa: F401
from netscan import osauth


class Logic(unittest.TestCase):
    def test_split_user(self):
        self.assertEqual(osauth.split_user("ravi"), ("ravi", "."))
        self.assertEqual(osauth.split_user("OFFICE\\ravi"), ("ravi", "OFFICE"))
        self.assertEqual(osauth.split_user("ravi@office.local"), ("ravi@office.local", None))

    def test_roles(self):
        self.assertEqual(osauth.role_for(True, {}), "admin")
        self.assertIsNone(osauth.role_for(False, {}))                        # refused by default
        self.assertEqual(osauth.role_for(False, {"auth": {"windows_users_role": "viewer"}}), "viewer")
        self.assertIsNone(osauth.role_for(False, {"auth": {"windows_users_role": "admin"}}))  # never escalates

    def test_check_with_fake_windows(self):
        fake = lambda u, d, p: (p == "right", u == "boss", "" if p == "right" else "Wrong user name or password.")
        self.assertEqual(osauth.check("boss", "right", fake)[:2], (True, True))
        self.assertEqual(osauth.check("clerk", "right", fake)[:2], (True, False))
        self.assertFalse(osauth.check("boss", "wrong", fake)[0])
        self.assertFalse(osauth.check("boss", "", fake)[0])
        boom = lambda u, d, p: 1 / 0
        self.assertFalse(osauth.check("boss", "x", boom)[0])                  # never crashes the login page


@unittest.skipUnless(osauth.available() and os.environ.get("NS_TEST_WIN_ADMIN"), "needs the CI Windows accounts")
class RealWindows(unittest.TestCase):
    def test_administrator_account(self):
        ok, admin, name, msg = osauth.check(os.environ["NS_TEST_WIN_ADMIN"], os.environ["NS_TEST_WIN_PASS"])
        self.assertTrue(ok, msg)
        self.assertTrue(admin)

    def test_standard_account(self):
        ok, admin, name, msg = osauth.check(os.environ["NS_TEST_WIN_USER"], os.environ["NS_TEST_WIN_PASS"])
        self.assertTrue(ok, msg)
        self.assertFalse(admin)

    def test_wrong_password(self):
        ok, admin, name, msg = osauth.check(os.environ["NS_TEST_WIN_ADMIN"], "definitely-wrong-1")
        self.assertFalse(ok)
        self.assertIn("Wrong", msg)

    def test_local_prefix(self):
        ok, admin, _n, msg = osauth.check(".\\" + os.environ["NS_TEST_WIN_ADMIN"], os.environ["NS_TEST_WIN_PASS"])
        self.assertTrue(ok and admin, msg)


if __name__ == "__main__":
    unittest.main()
