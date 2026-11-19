"""Start the real console and exercise it over HTTP."""
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request

from tests import _env


def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


class Console(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.home = tempfile.mkdtemp(prefix="ns-console-")
        cls.port = free_port()
        env = dict(os.environ, HOME=cls.home, USERPROFILE=cls.home, PYTHONDONTWRITEBYTECODE="1")
        # secrets that must never come back out of the API
        subprocess.run([sys.executable, "-c",
                        "from netscan import settings; settings.save({'telegram': {'token': 'tg-SECRET'},"
                        "'snmp_v3': {'auth_password': 'v3-SECRET'}, 'ai': {'api_key': 'sk-ant-SECRET'}})"],
                       cwd=_env.ROOT, env=env, check=True, timeout=60)
        cls.log = open(os.path.join(cls.home, "console.log"), "w")
        cls.proc = subprocess.Popen([sys.executable, "netsentinel.py", "--serve", "--no-browser", "--no-capture",
                                     "--no-monitor", "--rescan-every", "0", "--port", str(cls.port)],
                                    cwd=_env.ROOT, env=env, stdout=cls.log, stderr=subprocess.STDOUT)
        for _ in range(120):
            try:
                cls.get("/api/state")
                return
            except Exception:
                time.sleep(0.5)
        raise RuntimeError("console did not start")

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        try:
            cls.proc.wait(15)
        except subprocess.TimeoutExpired:
            cls.proc.kill()
        cls.log.close()

    @classmethod
    def get(cls, path):
        with urllib.request.urlopen(f"http://127.0.0.1:{cls.port}{path}", timeout=10) as r:
            return r.read()

    def post(self, path, body=None, csrf=True):
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", data=json.dumps(body or {}).encode(),
                                     method="POST", headers={"Content-Type": "application/json",
                                                             **({"X-NS": "1"} if csrf else {})})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    def test_state_has_version_update_ai_and_no_secrets(self):
        raw = self.get("/api/state").decode()
        state = json.loads(raw)
        import netscan
        self.assertEqual(state["version"], netscan.__version__)
        self.assertIn("update", state)
        self.assertIn("ai", state)
        for secret in ("tg-SECRET", "v3-SECRET", "sk-ant-SECRET"):
            self.assertNotIn(secret, raw)

    def test_dashboard_javascript_is_valid(self):
        page = self.get("/").decode()
        self.assertIn("NetSentinel", page)
        node = shutil.which("node")
        if not node:
            self.skipTest("node not installed")
        js = "\n".join(re.findall(r"<script>([\s\S]*?)</script>", page))
        path = os.path.join(self.home, "page.js")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(js)
        r = subprocess.run([node, "--check", path], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_post_without_csrf_header_refused(self):
        code, _ = self.post("/api/scan", csrf=False)
        self.assertEqual(code, 400)

    def test_ask_ai_when_off_explains(self):
        code, body = self.post("/api/ai/ask", {"question": "is anything down?"})
        self.assertEqual(code, 200)
        self.assertEqual(body["source"], "off")
        self.assertIn("Settings", body["answer"])

    def test_password_check_refused_until_confirmed(self):
        code, body = self.post("/api/defaults/check")
        self.assertEqual(body.get("state"), "refused")

    def test_pwa_files_served(self):
        self.assertIn(b"NetSentinel", self.get("/manifest.json"))
        self.assertIn(b"SHELL", self.get("/sw.js"))


if __name__ == "__main__":
    unittest.main()
