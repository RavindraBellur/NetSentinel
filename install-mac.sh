#!/bin/bash
# Prahari - installer for macOS
# Double-click "run-mac.command" instead if you just want to start it.
set -e
cd "$(dirname "$0")"
echo "============================================================"
echo "  Prahari - macOS setup"
echo "============================================================"

PY=""
for candidate in python3 /usr/bin/python3 /opt/homebrew/bin/python3 /usr/local/bin/python3; do
  if command -v "$candidate" >/dev/null 2>&1; then
    if "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3,9) else 1)' 2>/dev/null; then
      PY="$candidate"; break
    fi
  fi
done
if [ -z "$PY" ]; then
  echo "  Python 3.9+ was not found."
  echo "  Install it with:  brew install python@3.12"
  echo "  or download it from https://www.python.org/downloads/macos/"
  exit 1
fi
echo "  python      : $PY ($("$PY" -V 2>&1))"

if [ ! -x ".venv/bin/python" ]; then
  echo "  creating a private environment ..."
  "$PY" -m venv .venv
fi
VPY=".venv/bin/python"

echo "  installing the optional extras (cryptography, psutil, scapy) ..."
"$VPY" -m pip install --upgrade pip --quiet --disable-pip-version-check || true
"$VPY" -m pip install -r requirements.txt --quiet --disable-pip-version-check || \
  echo "  (some extras failed - the core still runs on the standard library)"

chmod +x run-mac.command 2>/dev/null || true
echo
echo "  Done. Start it with:  ./run-mac.command"
echo "  Dashboard:            http://127.0.0.1:8777"
echo
