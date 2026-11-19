import unittest

from tests import _env  # noqa: F401
from netscan import safety, settings


class PrivateTargets(unittest.TestCase):
    def test_private_lan_allowed(self):
        for ip in ("192.168.1.20", "10.0.0.5", "172.16.4.1", "169.254.1.1", "fd00::1"):
            self.assertTrue(safety.private_target(ip)[0], ip)

    def test_public_and_odd_refused(self):
        for ip in ("8.8.8.8", "1.1.1.1", "203.0.113.9", "127.0.0.1", "0.0.0.0", "224.0.0.1", "not-an-ip", ""):
            self.assertFalse(safety.private_target(ip)[0], ip)

    def test_acknowledgement_recorded_once(self):
        events = []
        patch = {"defaults_check": {"i_own_this_network": True}, "remediation": {"dry_run": False}}
        notes = safety.record_acknowledgements({}, patch, "ravi", lambda *a: events.append(a))
        self.assertEqual(patch["defaults_check"]["acknowledged_by"], "ravi")
        self.assertEqual(patch["remediation"]["live_enabled_by"], "ravi")
        self.assertEqual(len(notes), 2)
        self.assertEqual(len(events), 2)
        again = {"defaults_check": {"i_own_this_network": True}}
        old = {"defaults_check": {"i_own_this_network": True}}
        self.assertEqual(safety.record_acknowledgements(old, again, "x"), [])


class SecretsNeverReachTheBrowser(unittest.TestCase):
    def test_every_secret_masked(self):
        settings.reset()
        settings.save({"email": {"password": "smtp-secret"}, "ai": {"api_key": "sk-ant-secret"},
                       "telegram": {"token": "123:tg-secret"},
                       "snmp_v3": {"auth_password": "v3auth-secret", "priv_password": "v3priv-secret"},
                       "oidc": {"client_secret": "oidc-secret"}, "push": {"url": "https://push/secret"},
                       "branch": {"token": "branch-secret"}})
        view = repr(settings.public_view())
        for secret in ("smtp-secret", "sk-ant-secret", "tg-secret", "v3auth-secret", "v3priv-secret",
                       "oidc-secret", "push/secret", "branch-secret"):
            self.assertNotIn(secret, view)

    def test_masked_value_never_overwrites(self):
        settings.reset()
        settings.save({"telegram": {"token": "real-token"}})
        patch = settings.drop_masked({"telegram": {"token": settings.MASK, "token_set": True, "enabled": True}})
        settings.save(patch)
        self.assertEqual(settings.get("telegram")["token"], "real-token")
        self.assertTrue(settings.get("telegram")["enabled"])


if __name__ == "__main__":
    unittest.main()
