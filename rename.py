#!/usr/bin/env python3
"""Rebrand NetSentinel to any name, in one command.

    python3 rename.py --name "Prahari" --devanagari "प्रहरी" \
                      --tagline "the watchman on your network"

It rewrites the product name in every user-facing string, the UI, the batch files, the
spec, the app bundle and the docs, and renames the entry script. Internal module names
(`netscan`) and the data folder (`~/.netsentinel`) are left alone on purpose: renaming
them would orphan the database of an existing install.
"""
import argparse
import os
import re
import sys

OLD = "NetSentinel"
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
    with open(path, encoding="utf-8", errors="ignore") as fh:
        text = fh.read()
    original = text
    text = text.replace(OLD, new)
    # keep the CLI/module name lowercase where it is a command
    text = re.sub(r"\bnetsentinel\.py\b", f"{new.lower()}.py", text)
    text = re.sub(r"\bnetsentinel\.spec\b", f"{new.lower()}.spec", text)
    text = text.replace(f"NetSentinel-{''}", new)
    if dev:
        text = text.replace(f"<title>{new} 1.", f"<title>{new} · {dev} 1.")
    if tagline:
        text = text.replace(f"LAN discovery, monitoring and multi-site network console",
                            f"{tagline}")
    if text != original:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        return True
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", default="Prahari")
    ap.add_argument("--devanagari", default="प्रहरी")
    ap.add_argument("--tagline", default="the watchman on your network")
    ap.add_argument("--root", default=os.path.dirname(os.path.abspath(__file__)))
    args = ap.parse_args()

    changed = 0
    for path in files(args.root):
        if rebrand(path, args.name, args.devanagari, args.tagline):
            changed += 1
    # rename the entry script and the spec
    for old_name, new_name in ((f"{OLD_LOWER}.py", f"{args.name.lower()}.py"),
                               (f"{OLD_LOWER}.spec", f"{args.name.lower()}.spec")):
        src = os.path.join(args.root, old_name)
        dst = os.path.join(args.root, new_name)
        if os.path.exists(src):
            os.replace(src, dst)
            print(f"  renamed {old_name} -> {new_name}")
    print(f"  {changed} files rebranded to {args.name} ({args.devanagari})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
