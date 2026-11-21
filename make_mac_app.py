#!/usr/bin/env python3
"""Build Prahari.app - a double-clickable macOS application bundle.

    python3 make_mac_app.py        ->  dist/Prahari.app

It is a normal .app: a folder with Info.plist, an icon and a launcher that starts the
console and opens the dashboard. No compiler involved, so it can be built anywhere.
"""
import os
import shutil
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "dist", "Prahari.app")

INFO_PLIST = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>Prahari</string>
  <key>CFBundleDisplayName</key><string>Prahari</string>
  <key>CFBundleIdentifier</key><string>in.hotelgroup.netsentinel</string>
  <key>CFBundleVersion</key><string>1.38.2</string>
  <key>CFBundleShortVersionString</key><string>1.38.2</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleExecutable</key><string>Prahari</string>
  <key>CFBundleIconFile</key><string>netsentinel</string>
  <key>LSMinimumSystemVersion</key><string>10.13</string>
  <key>LSUIElement</key><false/>
  <key>NSHighResolutionCapable</key><true/>
  <key>NSHumanReadableCopyright</key><string>Prahari</string>
</dict>
</plist>
"""

LAUNCHER = """#!/bin/bash
# Prahari - macOS launcher
DIR="$(cd "$(dirname "$0")/../Resources/app" && pwd)"
cd "$DIR" || exit 1
if [ ! -x ".venv/bin/python" ]; then
  osascript -e 'display notification "First run: installing, this takes a minute" with title "Prahari"' 2>/dev/null
  ./install-mac.sh >> "$HOME/Library/Logs/Prahari-install.log" 2>&1
fi
if [ ! -x ".venv/bin/python" ]; then
  osascript -e 'display alert "Prahari" message "Setup failed. See ~/Library/Logs/Prahari-install.log"'
  exit 1
fi
exec .venv/bin/python netsentinel.py "$@"
"""


def make_icns(target):
    """ICNS with PNG payloads (ic09 = 512, ic08 = 256, ic07 = 128)."""
    try:
        from PIL import Image, ImageDraw
    except Exception:
        return False
    sizes = {b"ic09": 512, b"ic08": 256, b"ic07": 128}
    chunks = b""
    for tag, size in sizes.items():
        img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        d = ImageDraw.Draw(img)
        pad = size // 10
        d.rounded_rectangle([pad, pad, size - pad, size - pad], radius=size // 5,
                            fill=(23, 94, 55, 255))
        # simple "NS" mark: two vertical bars and a slash
        w = max(4, size // 16)
        d.line([(size * 0.30, size * 0.30), (size * 0.30, size * 0.70)], fill=(190, 240, 205, 255), width=w)
        d.line([(size * 0.70, size * 0.30), (size * 0.70, size * 0.70)], fill=(190, 240, 205, 255), width=w)
        d.line([(size * 0.34, size * 0.70), (size * 0.66, size * 0.30)], fill=(120, 200, 150, 255), width=w)
        import io
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        data = buf.getvalue()
        chunks += tag + struct.pack(">I", len(data) + 8) + data
    with open(target, "wb") as fh:
        fh.write(b"icns" + struct.pack(">I", len(chunks) + 8) + chunks)
    return True


def main():
    if os.path.isdir(OUT):
        shutil.rmtree(OUT)
    macos = os.path.join(OUT, "Contents", "MacOS")
    res = os.path.join(OUT, "Contents", "Resources")
    app = os.path.join(res, "app")
    os.makedirs(macos)
    os.makedirs(res)
    with open(os.path.join(OUT, "Contents", "Info.plist"), "w", encoding="utf-8") as fh:
        fh.write(INFO_PLIST)
    launcher = os.path.join(macos, "Prahari")
    with open(launcher, "w", encoding="utf-8") as fh:
        fh.write(LAUNCHER)
    os.chmod(launcher, 0o755)
    shutil.copytree(HERE, app, ignore=shutil.ignore_patterns(
        "__pycache__", "*.pyc", "dist", "build_pyz", "build", ".venv", ".git", "*.zip"))
    icon = os.path.join(res, "netsentinel.icns")
    print("icon:", "written" if make_icns(icon) else "skipped (Pillow not installed)")
    print(f"built {OUT}")
    print("Open it with:  open dist/Prahari.app    (or double-click in Finder)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
