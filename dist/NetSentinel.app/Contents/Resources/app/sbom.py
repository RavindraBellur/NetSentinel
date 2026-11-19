#!/usr/bin/env python3
"""Generate sbom.json - a software bill of materials for this build.

Lists the Python runtime, every standard-library module NetSentinel imports, and the
optional third-party packages, with versions, licences and where they come from.
Run it in the build:  python sbom.py
"""
from __future__ import annotations

import datetime
import glob
import hashlib
import json
import os
import platform
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

OPTIONAL = {
    "scapy": ("GPL-2.0", "passive per-device traffic capture (optional)"),
    "psutil": ("BSD-3-Clause", "throughput of this PC's network cards (optional)"),
    "cryptography": ("Apache-2.0 OR BSD-3-Clause", "TLS certificate creation and OIDC token verification"),
}


def version_of(name):
    try:
        mod = __import__(name)
        return getattr(mod, "__version__", "") or ""
    except Exception:
        return ""


def main():
    import netscan

    files = sorted(glob.glob(os.path.join(HERE, "netscan", "*.py")))
    digest = hashlib.sha256()
    for path in files:
        with open(path, "rb") as fh:
            digest.update(fh.read())

    stdlib = set()
    third = set()
    for path in files:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                m = re.match(r"\s*(?:from|import)\s+([a-zA-Z_][\w]*)", line)
                if not m:
                    continue
                name = m.group(1)
                if name in ("netscan",):
                    continue
                if name in OPTIONAL:
                    third.add(name)
                elif name not in ("__future__",):
                    stdlib.add(name)

    components = [{
        "type": "application", "name": "NetSentinel", "version": netscan.__version__,
        "licence": "proprietary", "hash_sha256": digest.hexdigest(),
        "files": len(files),
    }, {
        "type": "platform", "name": "CPython", "version": platform.python_version(),
        "licence": "PSF-2.0", "note": "standard library only for the core",
    }]
    for name in sorted(stdlib):
        components.append({"type": "library", "name": "python:" + name,
                           "version": platform.python_version(), "licence": "PSF-2.0",
                           "scope": "standard library"})
    for name in sorted(third):
        licence, why = OPTIONAL[name]
        components.append({"type": "library", "name": name, "version": version_of(name) or "not installed",
                           "licence": licence, "scope": "optional", "purpose": why})

    doc = {
        "bomFormat": "CycloneDX-like",
        "specVersion": "1.5 (subset)",
        "serialNumber": "urn:uuid:" + digest.hexdigest()[:32],
        "metadata": {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "component": {"name": "NetSentinel", "version": netscan.__version__},
            "tools": [{"name": "sbom.py"}],
        },
        "components": components,
        "notes": ("Generated from the source tree. NetSentinel runs on the Python standard "
                  "library; the optional packages are used only for the features named in "
                  "'purpose'."),
    }
    out = os.path.join(HERE, "sbom.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2)
    print(f"wrote {out}: {len(components)} components, {len(stdlib)} stdlib modules, "
          f"{len(third)} optional")


if __name__ == "__main__":
    main()
