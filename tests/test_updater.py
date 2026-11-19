"""Signed auto-update, end to end, against a local signed 'release' and a throw-away copy of the app.

Covers: wrong signature, tampered file, path traversal, --check-update, install, the hand-over
watchdog rolling back a broken release, the start-count rollback, healthy clean-up, and the hub
fleet update. Needs the `cryptography` package (it is what verifies real updates too).
"""
import base64
import hashlib
import http.server
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
import zipfile

from tests import _env

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ImportError:  # pragma: no cover
    Ed25519PrivateKey = None

ROOT = _env.ROOT
TOP = ["netscan", "netsentinel.py", "requirements.txt", "README.md", "EULA.txt", "sbom.json"]
with open(os.path.join(ROOT, "netscan", "__init__.py"), encoding="utf-8") as _fh:
    CURRENT = re.search(r'__version__ = "([^"]+)"', _fh.read()).group(1)


def bump(n):
    parts = [int(x) for x in CURRENT.split(".")]
    parts[-1] += n
    return ".".join(str(x) for x in parts)


@unittest.skipIf(Ed25519PrivateKey is None, "cryptography not installed")
class SignedUpdates(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = tempfile.mkdtemp(prefix="ns-update-")
        cls.rel = os.path.join(cls.work, "release")
        os.makedirs(cls.rel)
        cls.key = Ed25519PrivateKey.generate()
        pub = cls.key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        cls.pub = base64.b64encode(pub).decode()

        rel = cls.rel

        class Quiet(http.server.SimpleHTTPRequestHandler):
            def __init__(self, *a, **k):
                super().__init__(*a, directory=rel, **k)

            def log_message(self, *a):
                pass

        cls.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Quiet)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.srv.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def setUp(self):
        self.app = os.path.join(self.work, "app")
        self.home = os.path.join(self.work, "home")
        shutil.rmtree(self.app, ignore_errors=True)
        shutil.rmtree(self.home, ignore_errors=True)
        os.makedirs(self.home)
        shutil.copytree(ROOT, self.app, ignore=shutil.ignore_patterns(
            ".git", "dist", "build", "__pycache__", "*.png", "tests", ".venv"))
        self.env = dict(os.environ, HOME=self.home, USERPROFILE=self.home, PYTHONDONTWRITEBYTECODE="1",
                        NETSENTINEL_UPDATE_BASE=self.base, NETSENTINEL_UPDATE_TEST_KEY=self.pub,
                        PYTHONPATH=os.pathsep.join(p for p in sys.path if "site-packages" in p))
        self.update_dir = os.path.join(self.home, ".netsentinel", "update")

    # -- helpers
    def release(self, version, broken=False, tamper=False, foreign_key=False, extra=None):
        for f in os.listdir(self.rel):
            os.remove(os.path.join(self.rel, f))
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            for t in TOP:
                src = os.path.join(ROOT, t)
                for r, _d, fs in (os.walk(src) if os.path.isdir(src) else [(ROOT, [], [t])]):
                    if "__pycache__" in r:
                        continue
                    for f in fs:
                        p = os.path.join(r, f)
                        rel = os.path.relpath(p, ROOT).replace(os.sep, "/")
                        with open(p, "rb") as fh:
                            data = fh.read()
                        if rel == "netscan/__init__.py":
                            data = data.replace(f'"{CURRENT}"'.encode(), f'"{version}"'.encode())
                        if broken and rel == "netsentinel.py":
                            data = b"import sys\nsys.exit(3)\n"
                        z.writestr(rel, data)
            z.writestr("netscan/marker_" + version.replace(".", "_") + ".txt", "new")
            for name, data in (extra or {}).items():
                z.writestr(name, data)
        app = buf.getvalue()
        with open(os.path.join(self.rel, "Prahari-app.zip"), "wb") as fh:
            fh.write(app + (b"x" if tamper else b""))
        manifest = json.dumps({"version": version, "tag": "v" + version,
                               "assets": {"app": {"file": "Prahari-app.zip",
                                                  "sha256": hashlib.sha256(app).hexdigest(),
                                                  "size": len(app)}}}, sort_keys=True)
        key = Ed25519PrivateKey.generate() if foreign_key else self.key
        with open(os.path.join(self.rel, "latest.json"), "w") as fh:
            json.dump({"manifest": manifest, "sig": base64.b64encode(key.sign(manifest.encode())).decode()}, fh)

    def py(self, code, timeout=120):
        r = subprocess.run([sys.executable, "-c", code], cwd=self.app, env=self.env,
                           capture_output=True, text=True, timeout=timeout)
        return (r.stdout + r.stderr).strip()

    def version(self):
        return self.py("import netscan; print(netscan.__version__)")

    def install(self):
        return self.py("from netscan import updater as u; x=u.Updater(lambda:{}); "
                       "print(x.check_once(install=True), x.status, x.error)")

    # -- tests
    def test_wrong_signature_refused(self):
        self.release(bump(1), foreign_key=True)
        self.assertIn("not valid", self.install())
        self.assertEqual(self.version(), CURRENT)

    def test_tampered_file_refused(self):
        self.release(bump(1), tamper=True)
        self.assertIn("does not match", self.install())
        self.assertEqual(self.version(), CURRENT)

    def test_path_traversal_refused(self):
        self.release(bump(1), extra={"../evil.py": "x"})
        self.assertIn("unexpected file", self.install())
        self.assertFalse(os.path.exists(os.path.join(self.work, "evil.py")))

    def test_cli_check_does_not_install(self):
        self.release(bump(1))
        r = subprocess.run([sys.executable, "netsentinel.py", "--check-update"], cwd=self.app, env=self.env,
                           capture_output=True, text=True, timeout=120)
        self.assertIn("available", r.stdout)
        self.assertEqual(self.version(), CURRENT)

    def test_install_and_healthy_cleanup(self):
        self.release(bump(1))
        self.assertIn("True restarting", self.install())
        self.assertEqual(self.version(), bump(1))
        self.assertTrue(os.path.exists(os.path.join(self.app, "netscan", f"marker_{bump(1).replace('.', '_')}.txt")))
        out = self.py("import time; from netscan import updater as u\nu.HEALTHY_AFTER=1\n"
                      "u.boot_check(lambda m: None)\nx=u.Updater(lambda:{}, log=print); x.mark_healthy_later(); time.sleep(2)")
        self.assertIn("running fine", out)
        self.assertFalse(os.path.exists(os.path.join(self.update_dir, "pending.json")))

    def test_handover_watchdog_rolls_back_broken_release(self):
        self.release(bump(2), broken=True)
        out = self.py("import subprocess\nfrom netscan import updater as u\nu.HANDOFF_WATCH=8\n"
                      "calls=[]\n"
                      "def fake(cmd):\n calls.append(cmd)\n return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, "
                      "stderr=subprocess.DEVNULL) if len(calls)==1 else None\n"
                      "u.spawn=fake\nx=u.Updater(lambda:{})\nprint('installed', x.check_once(install=True))\n"
                      "print('rc', x.handoff()); print('restarted-old', len(calls)==2)")
        self.assertIn("rc 1", out)
        self.assertIn("restarted-old True", out)
        self.assertEqual(self.version(), CURRENT)
        self.assertFalse(os.path.exists(os.path.join(self.app, "netscan", f"marker_{bump(2).replace('.', '_')}.txt")))
        with open(os.path.join(self.update_dir, "bad.json")) as fh:
            self.assertEqual(json.load(fh), [bump(2)])
        # and it is not installed again automatically
        self.assertIn("False available", self.py("from netscan import updater as u; x=u.Updater(lambda:{}); "
                                                 "print(x.check_once(), x.status)"))

    def test_start_count_rollback(self):
        self.release(bump(3))
        self.install()
        self.assertEqual(self.version(), bump(3))
        results = [self.py("from netscan import updater as u; print(u.boot_check(lambda m: None))") for _ in range(4)]
        self.assertEqual(results, ["False", "False", "False", "True"])
        self.assertEqual(self.version(), CURRENT)

    def test_hub_fleet_update_installs_signed_release_only(self):
        self.release(bump(5))
        out = self.py("from netscan import settings, upgrade, updater as u\n"
                      f"settings.save({{'fleet_update': {{'version': '{bump(5)}'}}, 'update': {{'auto_install': False}}}})\n"
                      f"print('offer', upgrade.hub_reply('{CURRENT}'), upgrade.hub_reply('{bump(5)}'))\n"
                      "x=u.Updater(lambda: settings.get('update'), log=print); u.CURRENT=x\n"
                      "print('timer', x.check_once(), x.status)\n"
                      f"print('msg', upgrade.pending_update({{'update': {{'version': '{bump(5)}', "
                      "'url': 'http://evil/x.zip', 'sha256': 'ab'}}, log=print))\n"
                      f"print('again', upgrade.pending_update({{'update': {{'version': '{bump(5)}'}}}}, log=print))\n"
                      "print('installed', x.check_once(install=True if x._install_now else None))")
        self.assertIn(f"offer {{'version': '{bump(5)}'}} None", out)
        self.assertIn("timer False available", out)
        self.assertIn(f"msg installing {bump(5)}", out)
        self.assertIn("again None", out)
        self.assertIn("installed True", out)
        self.assertEqual(self.version(), bump(5))

    def test_test_key_ignored_for_remote_mirror(self):
        out = subprocess.run([sys.executable, "-c", "from netscan import updater as u; print(u.PUBLIC_KEY)"],
                             cwd=self.app, capture_output=True, text=True,
                             env=dict(self.env, NETSENTINEL_UPDATE_BASE="https://evil.example.com/x")).stdout.strip()
        self.assertNotEqual(out, self.pub)


if __name__ == "__main__":
    unittest.main()
