#!/usr/bin/env python3
"""Rebrand Prahari to any other name, in one command.

    python3 rename.py --name "Netra" --devanagari "नेत्र" \
                      --tagline "the eye on your network"

It rewrites the product name in every user-facing string, the UI, the batch files, the
spec, the app bundle and the docs, and renames the entry script. Internal module names
(`netscan`), the data folder (`~/.netsentinel`), the entry script (`netsentinel.py`) and the
GitHub repository the updater reads are left alone on purpose: renaming them would orphan the
database of an existing install or stop installed copies from accepting updates.
"""
import argparse
import os
import re
import sys

OLD = "Prahari"
OLD_LOWER = "netsentinel"
SKIP_DIRS = {"__pycache__", ".venv", "build", "build_pyz", "dist", ".git"}
TEXT_EXT = {".py", ".bat", ".cmd", ".md", ".txt", ".spec", ".yml", ".yaml", ".sh",
            ".command", ".json", ".exclude", ""}
KEEP = {"rename.py"}


def files(root):
    for base, dirs, names in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in names:
            path = os.path.join(base, name)
            ext = os.path.splitext(name)[1].lower()
            if name in KEEP or ext not in TEXT_EXT:
                continue
            if os.path.getsize(path) > 2_000_000:
                continue
            yield path


def rebrand(path, new, dev, tagline):
    with open(path, "rb") as fh:
        raw = fh.read()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return False
    original = text
    protected = "RavindraBellur/NetSentinel"          # the repository installed copies update from
    text = text.replace(protected, "\x00REPO\x00").replace(OLD, new).replace("\x00REPO\x00", protected)
    if dev:
        text = text.replace("प्रहरी", dev)
    if tagline:
        text = text.replace("LAN discovery, monitoring and multi-site network console", tagline)
    if text != original:
        with open(path, "wb") as fh:                   # bytes: keeps Windows line endings in .bat files
            fh.write(text.encode("utf-8"))
        return True
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", required=True)
    ap.add_argument("--devanagari", default="प्रहरी")
    ap.add_argument("--tagline", default="the watchman on your network")
    ap.add_argument("--root", default=os.path.dirname(os.path.abspath(__file__)))
    args = ap.parse_args()

    changed = 0
    for path in files(args.root):
        if rebrand(path, args.name, args.devanagari, args.tagline):
            changed += 1
    print(f"  {changed} files rebranded to {args.name} ({args.devanagari})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
