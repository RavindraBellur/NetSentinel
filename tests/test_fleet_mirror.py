"""Head-office update mirror, end to end: a real hub console publishes a signed release, a branch copy
installs it through the hub with its branch token - and nothing unsigned or tampered gets through."""
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
import http.cookiejar

from tests import _env
from tests import test_updater as _tu

Ed25519PrivateKey, bump = _tu.Ed25519PrivateKey, _tu.bump


def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


@unittest.skipIf(Ed25519PrivateKey is None, "cryptography not installed")
class HubMirror(_tu.SignedUpdates):
    """Re-uses the signed-release builder and the throw-away app copy from test_updater."""

    def start_hub(self):
        self.hub_home = tempfile.mkdtemp(prefix="ns-hub-")
        self.hub_port = free_port()
        # the hub verifies with the same throw-away key (accepted only for a localhost source)
        env = dict(self.env, HOME=self.hub_home, USERPROFILE=self.hub_home)
        out = subprocess.run([sys.executable, "netsentinel.py", "--new-branch-token", "Udaipur"], cwd=_env.ROOT,
                             env=env, capture_output=True, text=True, timeout=60).stdout
        self.token = next(w for w in out.split() if w.startswith("nsb_") or len(w) > 30 and "_" in w)
        subprocess.run([sys.executable, "netsentinel.py", "--set-password", "Hub-pass-123"], cwd=_env.ROOT,
                       env=env, capture_output=True, timeout=60)
        self.hub_log = open(os.path.join(self.hub_home, "hub.log"), "w")
        self.hub = subprocess.Popen([sys.executable, "netsentinel.py", "--serve", "--no-browser", "--no-capture",
                                     "--no-monitor", "--rescan-every", "0", "--port", str(self.hub_port)],
                                    cwd=_env.ROOT, env=env, stdout=self.hub_log, stderr=subprocess.STDOUT)
        self.addCleanup(self.stop_hub)
        self.jar = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        for _ in range(120):
            try:
                urllib.request.urlopen(self.url("/login"), timeout=3).read()
                break
            except Exception:
                time.sleep(0.5)
        self.jar.open(self.url("/login"), data=urllib.parse.urlencode(
            {"username": "admin", "password": "Hub-pass-123"}).encode(), timeout=30)

    def stop_hub(self):
        self.hub.terminate()
        try:
            self.hub.wait(15)
        except subprocess.TimeoutExpired:
            self.hub.kill()
        self.hub_log.close()

    def url(self, path):
        return f"http://127.0.0.1:{self.hub_port}{path}"

    def publish(self, folder):
        req = urllib.request.Request(self.url("/api/fleet/publish"), data=json.dumps({"folder": folder}).encode(),
                                     method="POST", headers={"Content-Type": "application/json", "X-NS": "1"})
        return json.load(self.jar.open(req, timeout=60))

    def fetch(self, name, token=None):
        req = urllib.request.Request(self.url("/fleet/update/" + name),
                                     headers={"X-Branch-Token": token} if token else {})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, b""

    def branch_install(self):
        code = ("from netscan import updater as u; x=u.Updater(lambda:{})\n"
                f"src={{'base': '{self.url('/fleet/update')}', 'headers': {{'X-Branch-Token': '{self.token}'}}}}\n"
                "print(x.check_once(install=True, source=src), x.status, x.error)")
        return self.py(code)

    # -- the tests
    def test_publish_serve_and_branch_install(self):
        self.start_hub()
        self.release(bump(7))                         # signed release in self.rel
        result = self.publish(self.rel)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["version"], bump(7))

        self.assertEqual(self.fetch("latest.json")[0], 403)                  # no token
        self.assertEqual(self.fetch("latest.json", "nsb_wrong")[0], 403)     # wrong token
        self.assertEqual(self.fetch("../settings.json", self.token)[0], 404)  # nothing but the release
        self.assertEqual(self.fetch("latest.json", self.token)[0], 200)

        out = self.branch_install()
        self.assertIn("True restarting", out)
        self.assertEqual(self.version(), bump(7))

        # the hub now tells older branches to use its mirror ...
        hub_env = dict(self.env, HOME=self.hub_home, USERPROFILE=self.hub_home)
        offer = subprocess.run([sys.executable, "-c", "from netscan import upgrade; print(upgrade.hub_reply('1.0.0'))"],
                               cwd=_env.ROOT, env=hub_env, capture_output=True, text=True).stdout
        self.assertIn("'mirror': True", offer)

    def test_branch_uses_the_mirror_with_its_token(self):
        # ... and a branch that gets that offer asks its updater to install from the hub, with its token
        out = self.py("from netscan import upgrade, updater as u\n"
                      "calls=[]\n"
                      "class Fake: mode='source'\n"
                      "Fake.check_now=lambda self, install=False, source=None: calls.append((install, source))\n"
                      "u.CURRENT=Fake()\n"
                      "upgrade.pending_update({'update': {'version': '999.0.0', 'mirror': True}}, "
                      "'http://hub.local:8777', log=lambda m: None, token='ns_abc')\n"
                      "print(calls)")
        self.assertIn("'base': 'http://hub.local:8777/fleet/update'", out)
        self.assertIn("'X-Branch-Token': 'ns_abc'", out)
        self.assertIn("(True,", out)

    def test_hub_refuses_unsigned_or_tampered_release(self):
        self.start_hub()
        self.release(bump(8), foreign_key=True)
        self.assertFalse(self.publish(self.rel)["ok"])
        self.release(bump(8), tamper=True)
        r = self.publish(self.rel)
        self.assertFalse(r["ok"])
        self.assertIn("checksum", r["message"])

    def test_branch_refuses_a_file_changed_on_the_hub(self):
        self.start_hub()
        self.release(bump(9))
        self.assertTrue(self.publish(self.rel)["ok"])
        # someone with access to the hub PC swaps the mirrored app zip
        mirror_dir = os.path.join(self.hub_home, ".netsentinel", "update-mirror", bump(9))
        with open(os.path.join(mirror_dir, "Prahari-app.zip"), "ab") as fh:
            fh.write(b"evil")
        out = self.branch_install()
        self.assertIn("does not match", out)
        self.assertEqual(self.version(), _current())


def _current():
    import re
    with open(os.path.join(_env.ROOT, "netscan", "__init__.py"), encoding="utf-8") as fh:
        return re.search(r'__version__ = "([^"]+)"', fh.read()).group(1)


# don't re-run the inherited updater tests from this module
for _name in [n for n in dir(_tu.SignedUpdates) if n.startswith("test_")]:
    setattr(HubMirror, _name, None)

if __name__ == "__main__":
    unittest.main()
