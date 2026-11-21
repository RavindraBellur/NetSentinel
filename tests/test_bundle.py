"""The all-in-one .pyz: builds, unpacks, and serves the whole dashboard straight from the file."""
import http.cookiejar
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.parse
import urllib.request
import zipfile

from tests import _env


def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


class AllInOne(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, os.path.join(_env.ROOT, "tools"))
        import make_bundle
        cls.pyz, cls.full = make_bundle.build()
        cls.home = tempfile.mkdtemp(prefix="ns-pyz-")
        cls.env = dict(os.environ, HOME=cls.home, USERPROFILE=cls.home, PYTHONDONTWRITEBYTECODE="1")
        cls.run_dir = tempfile.mkdtemp(prefix="ns-pyz-run-")     # not the source tree
        subprocess.run([sys.executable, cls.pyz, "--set-password", "Test-pass-123"], cwd=cls.run_dir,
                       env=cls.env, check=True, timeout=60, capture_output=True)
        cls.port = free_port()
        cls.proc = subprocess.Popen([sys.executable, cls.pyz, "--serve", "--no-browser", "--no-capture",
                                     "--no-monitor", "--rescan-every", "0", "--port", str(cls.port)],
                                    cwd=cls.run_dir, env=cls.env, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL)
        for _ in range(120):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{cls.port}/login", timeout=5).read()
                break
            except Exception:
                time.sleep(0.5)
        cls.jar = http.cookiejar.CookieJar()
        cls.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cls.jar))
        cls.op.open(f"http://127.0.0.1:{cls.port}/login", timeout=30, data=urllib.parse.urlencode(
            {"username": "admin", "password": "Test-pass-123"}).encode())

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        cls.proc.wait(timeout=20)

    def get(self, path):
        with self.op.open(f"http://127.0.0.1:{self.port}{path}", timeout=20) as r:
            return r.status, r.read()

    def test_runs_and_serves_everything_from_the_file(self):
        import netscan
        self.assertEqual(json.loads(self.get("/api/state")[1])["version"], netscan.__version__)
        self.assertIn(b"Prahari", self.get("/manifest.json")[1])
        self.assertTrue(self.get("/static/icon-192.png")[1].startswith(b"\x89PNG"))
        self.assertIn(b"SHELL", self.get("/sw.js")[1])
        self.assertIn(b"Security review", self.get("/limits.md")[1])

    def test_unpack_writes_docs_and_scripts(self):
        out = tempfile.mkdtemp(prefix="ns-unpack-")
        subprocess.run([sys.executable, self.pyz, "--unpack", out], env=self.env, check=True,
                       timeout=60, capture_output=True)
        for rel in ("START-HERE.txt", "Prahari/README.md", "Prahari/LIMITS.md", "Prahari/run.bat",
                    "Prahari/install-mac.sh"):
            self.assertTrue(os.path.isfile(os.path.join(out, rel)), rel)

    def test_complete_zip_has_the_app_and_no_publisher_tools(self):
        names = zipfile.ZipFile(self.full).namelist()
        self.assertIn("Prahari/netsentinel.py", names)
        self.assertIn("Prahari/netscan/webui.py", names)
        self.assertIn("START-HERE.txt", names)
        self.assertFalse([n for n in names if "sign_release" in n or n.endswith(".pem")])
        self.assertFalse([n for n in names if "__pycache__" in n])
