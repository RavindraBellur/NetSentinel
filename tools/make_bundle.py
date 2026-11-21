#!/usr/bin/env python3
"""Build the two download files for people who run Prahari with Python instead of the exe.

    python3 tools/make_bundle.py            -> dist/Prahari-<ver>-all-in-one.pyz
                                               dist/Prahari-<ver>-complete.zip

all-in-one.pyz   one file; runs straight away with any Python 3.9+ on Windows, macOS or Linux:
                     python3 Prahari-<ver>-all-in-one.pyz
                 and carries the docs, screenshots and scripts inside:
                     python3 Prahari-<ver>-all-in-one.pyz --unpack ~/Prahari

complete.zip     the same, already unpacked: Prahari/ (the app and its scripts), screenshots/,
                 START-HERE.txt.

The Windows exe stays the main download - it needs no Python. These two are for Macs, Linux
boxes and anyone who wants to read what they run. Same code as the exe of the same version.
"""

import io
import os
import re
import sys
import zipfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DIST = os.path.join(HERE, "dist")

APP = ["netscan", "netsentinel.py"]
SCRIPTS = ["run.bat", "install.bat", "open_dashboard.bat", "dashboard_lan.bat", "allow_firewall.bat",
           "autostart_install.bat", "autostart_remove.bat", "enable_rdp.bat", "install-mac.sh",
           "run-mac.command", "requirements.txt", "build_exe.bat", "netsentinel.spec", "netsentinel.ico"]
DOCS = ["README.md", "LIMITS.md", "EULA.txt", "sbom.json"]
SKIP_DIRS = {"__pycache__"}

MAIN = '''"""Prahari __VER__ - everything in one file.

    python3 Prahari-__VER__-all-in-one.pyz                  scan, then open the dashboard
    python3 Prahari-__VER__-all-in-one.pyz --lan            dashboard reachable from the LAN
    python3 Prahari-__VER__-all-in-one.pyz --help           every option
    python3 Prahari-__VER__-all-in-one.pyz --unpack DIR     write the docs, screenshots and scripts to DIR

The app runs straight out of this file - no install, no pip, no unzip.
"""
import os
import runpy
import sys
import zipfile


def unpack(target):
    archive = sys.argv[0]
    target = os.path.abspath(os.path.expanduser(target))
    n = 0
    with zipfile.ZipFile(archive) as zf:
        for name in zf.namelist():
            if not name.startswith("extras/") or name.endswith("/"):
                continue
            rel = name[len("extras/"):]
            dest = os.path.abspath(os.path.join(target, rel))
            if not dest.startswith(target + os.sep):
                continue
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(dest, "wb") as fh:
                fh.write(zf.read(name))
            n += 1
    print(f"wrote {n} files to {target}")


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "--unpack":
        unpack(sys.argv[2] if len(sys.argv) > 2 else os.path.join("~", "Prahari-__VER__"))
        sys.exit(0)
    sys.argv[0] = sys.argv[0] or "Prahari.pyz"
    runpy.run_module("netsentinel", run_name="__main__", alter_sys=True)
'''

START = '''PRAHARI (प्रहरी) - your network's 24x7 guard                version __VER__
=====================================================================

THE EASY WAY (Windows)
  Download Prahari.exe from the Prahari portal and double-click it. No Python needed.

WITH PYTHON 3.9+ (Windows, macOS, Linux)
  python3 Prahari-__VER__-all-in-one.pyz            runs it, opens the dashboard
  macOS   : cd Prahari && ./install-mac.sh && ./run-mac.command
  Windows : Prahari\\install.bat once, then Prahari\\run.bat

  Optional extras (better certificates, Claude diagnosis, this PC's CPU/memory):
  pip install -r Prahari/requirements.txt

CONNECT TO THE PORTAL
  On first start Prahari asks for your organisation key and a location name.
  The key is on the Prahari portal next to Download.

WHAT IS IN HERE
  Prahari/README.md     what is new in each version
  Prahari/LIMITS.md     what is proven, what is not, and the security review
  Prahari/EULA.txt      the licence
  screenshots/          how it looks

One Prahari per network. Updates come from the portal (Update / Update all) and are signed.
'''


def version():
    text = open(os.path.join(HERE, "netscan", "__init__.py"), encoding="utf-8").read()
    return re.search(r'__version__\s*=\s*"([^"]+)"', text).group(1)


def files(paths):
    """(source path, path inside the archive) for files and whole folders."""
    for p in paths:
        src = os.path.join(HERE, p)
        if os.path.isdir(src):
            for root, dirs, names in os.walk(src):
                dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
                for n in sorted(names):
                    if n.endswith(".pyc"):
                        continue
                    full = os.path.join(root, n)
                    yield full, os.path.relpath(full, HERE).replace(os.sep, "/")
        elif os.path.exists(src):
            yield src, p


def screenshots():
    for n in sorted(os.listdir(HERE)):
        if n.startswith("screenshot") and n.endswith(".png"):
            yield os.path.join(HERE, n), n


def build():
    ver = version()
    os.makedirs(DIST, exist_ok=True)
    start = START.replace("__VER__", ver)

    pyz = os.path.join(DIST, f"Prahari-{ver}-all-in-one.pyz")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("__main__.py", MAIN.replace("__VER__", ver))
        for src, arc in files(APP):
            z.write(src, arc)
        for src, arc in files(SCRIPTS + DOCS):
            z.write(src, "extras/Prahari/" + arc)
        for src, arc in screenshots():
            z.write(src, "extras/screenshots/" + arc)
        z.writestr("extras/START-HERE.txt", start)
    with open(pyz, "wb") as fh:
        fh.write(b"#!/usr/bin/env python3\n" + buf.getvalue())
    os.chmod(pyz, 0o755)

    full = os.path.join(DIST, f"Prahari-{ver}-complete.zip")
    with zipfile.ZipFile(full, "w", zipfile.ZIP_DEFLATED) as z:
        for src, arc in files(APP + SCRIPTS + DOCS):
            z.write(src, "Prahari/" + arc)
        for src, arc in screenshots():
            z.write(src, "screenshots/" + arc)
        z.writestr("START-HERE.txt", start)
    for path in (pyz, full):
        print(f"built {path} ({os.path.getsize(path) / 1024:.0f} KB)")
    return pyz, full


if __name__ == "__main__":
    build()
    sys.exit(0)
