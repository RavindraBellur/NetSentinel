#!/usr/bin/env python3
"""Prahari - start the console. (The program file is netsentinel.py, kept under that name so
installed copies keep accepting signed updates; this launcher is the friendlier name.)"""
import os
import runpy
import sys

if __name__ == "__main__":
    here = os.path.dirname(os.path.abspath(__file__))
    sys.argv[0] = os.path.join(here, "netsentinel.py")
    runpy.run_path(sys.argv[0], run_name="__main__")
