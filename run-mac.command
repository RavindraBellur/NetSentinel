#!/bin/bash
# Double-click this in Finder to start Prahari on macOS.
cd "$(dirname "$0")"
if [ ! -x ".venv/bin/python" ]; then
  echo "First run - setting things up ..."
  ./install-mac.sh || { echo; echo "Setup failed - see the messages above."; read -r -p "Press return to close"; exit 1; }
fi
clear
echo "============================================================"
echo "  Prahari is starting"
echo "  It will scan this network and open the dashboard."
echo "  Keep this window open. Press Ctrl+C to stop."
echo "============================================================"
echo
exec .venv/bin/python netsentinel.py "$@"
