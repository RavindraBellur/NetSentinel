#!/usr/bin/env python3
"""Build Prahari.pyz - one file that runs anywhere Python 3.9+ exists.

    python3 make_pyz.py          ->  dist/Prahari.pyz
    python3 Prahari.pyz --help

No compiler, no PyInstaller, works on macOS, Linux and Windows (with Python installed).
"""
import os
import shutil
import subprocess
import sys
import zipapp

HERE = os.path.dirname(os.path.abspath(__file__))
BUILD = os.path.join(HERE, "build_pyz")
OUT = os.path.join(HERE, "dist", "Prahari.pyz")

MAIN = '''"""Prahari single-file entry point."""
import runpy
import sys

if __name__ == "__main__":
    sys.argv[0] = "Prahari.pyz"
    runpy.run_module("netsentinel", run_name="__main__")
'''


def main():
    if os.path.isdir(BUILD):
        shutil.rmtree(BUILD)
    os.makedirs(BUILD)
    shutil.copytree(os.path.join(HERE, "netscan"), os.path.join(BUILD, "netscan"),
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    shutil.copy(os.path.join(HERE, "netsentinel.py"), BUILD)
    with open(os.path.join(BUILD, "__main__.py"), "w", encoding="utf-8") as fh:
        fh.write(MAIN)
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    zipapp.create_archive(BUILD, OUT, interpreter="/usr/bin/env python3", compressed=True)
    size = os.path.getsize(OUT) / 1024
    print(f"built {OUT} ({size:.0f} KB)")
    print("run it with:  python3 Prahari.pyz --help")
    return 0


if __name__ == "__main__":
    sys.exit(main())
