"""CI only (Windows runner): prove the built NetSentinel.exe can update itself in place.

1. Copy dist/NetSentinel.exe into a fresh folder - that is the "installed" copy.
2. Publish the same exe as a newer, signed release from a web server on this machine
   (signed with a throw-away key the exe accepts only from 127.0.0.1).
3. Run the installed exe with --update-now: while running, it must download the release,
   verify signature + checksum, rename itself to NetSentinel.exe.old and put the new exe in place.
4. Start the replaced exe to show it runs.

Usage: python tools/ci_exe_update_test.py dist/NetSentinel.exe
"""
import base64
import hashlib
import http.server
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def main():
    built = os.path.abspath(sys.argv[1])
    work = tempfile.mkdtemp(prefix="ns-exe-update-")
    installed_dir, rel = os.path.join(work, "installed"), os.path.join(work, "release")
    home = os.path.join(work, "home")
    for d in (installed_dir, rel, home):
        os.makedirs(d)
    exe = os.path.join(installed_dir, "NetSentinel.exe")
    shutil.copy2(built, exe)
    shutil.copy2(built, os.path.join(rel, "NetSentinel.exe"))
    data = open(built, "rb").read()

    key = Ed25519PrivateKey.generate()
    pub = base64.b64encode(key.public_key().public_bytes(serialization.Encoding.Raw,
                                                         serialization.PublicFormat.Raw)).decode()
    manifest = json.dumps({"version": "999.0.0", "tag": "v999.0.0", "assets": {
        "exe": {"file": "NetSentinel.exe", "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}}},
        sort_keys=True)
    with open(os.path.join(rel, "latest.json"), "w") as fh:
        json.dump({"manifest": manifest, "sig": base64.b64encode(key.sign(manifest.encode())).decode()}, fh)

    class Quiet(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *a, **k):
            super().__init__(*a, directory=rel, **k)

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Quiet)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    env = dict(os.environ, USERPROFILE=home, HOME=home,
               NETSENTINEL_UPDATE_BASE=f"http://127.0.0.1:{srv.server_port}",
               NETSENTINEL_UPDATE_TEST_KEY=pub)

    r = subprocess.run([exe, "--update-now"], env=env, capture_output=True, text=True, timeout=300)
    print(r.stdout, r.stderr)
    checks = {
        "update reported installed": "installed 999.0.0" in r.stdout,
        "old exe kept as NetSentinel.exe.old": os.path.exists(exe + ".old"),
        "new exe in place": os.path.exists(exe) and os.path.getsize(exe) == len(data),
        "pending marker written": os.path.exists(os.path.join(home, ".netsentinel", "update", "pending.json")),
    }
    r2 = subprocess.run([exe, "--selftest-update"], env=env, capture_output=True, text=True, timeout=120)
    print(r2.stdout, r2.stderr)
    checks["replaced exe runs"] = r2.returncode == 0

    # a tampered release must be refused by the exe itself
    with open(os.path.join(rel, "NetSentinel.exe"), "ab") as fh:
        fh.write(b"tampered")
    os.remove(exe + ".old")
    r3 = subprocess.run([exe, "--update-now"], env=env, capture_output=True, text=True, timeout=300)
    print(r3.stdout, r3.stderr)
    checks["tampered release refused"] = "does not match" in r3.stdout and not os.path.exists(exe + ".old")

    srv.shutdown()
    for name, ok in checks.items():
        print(("PASS " if ok else "FAIL ") + name)
    return 0 if all(checks.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
