#!/usr/bin/env python3
"""Sign and publish a Prahari release so every installed copy updates itself.

    python3 tools/sign_release.py v1.18.0

Run it on the publisher's Mac after GitHub Actions has built the tag and created the DRAFT release.
It downloads Prahari.exe and Prahari-app.zip from the draft, checks that the code inside says
the same version as the tag, writes latest.json (manifest + Ed25519 signature), uploads it and publishes
the release. Installed copies only ever read the newest *published* release, and install nothing whose
signature or checksum doesn't match.

The private key lives at ~/.config/netsentinel-release/update-signing-key.pem and must never be committed
or copied to an install. Keep a backup of it somewhere safe (password manager): without it no future
update can be signed, and every installed copy would need a manual reinstall with a new key.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import zipfile

REPO = "RavindraBellur/NetSentinel"
KEY = os.path.expanduser("~/.config/netsentinel-release/update-signing-key.pem")
ASSETS = {"exe": "Prahari.exe", "app": "Prahari-app.zip"}


def gh(*args, capture=False):
    res = subprocess.run(["gh", *args, "-R", REPO], text=True,
                         stdout=subprocess.PIPE if capture else None)
    if res.returncode:
        sys.exit(f"gh {' '.join(args)} failed")
    return res.stdout


def main():
    if len(sys.argv) != 2 or not re.fullmatch(r"v\d+(\.\d+)*", sys.argv[1]):
        sys.exit("usage: python3 tools/sign_release.py vX.Y.Z")
    tag = sys.argv[1]
    version = tag[1:]
    if not os.path.exists(KEY):
        sys.exit(f"signing key not found at {KEY}")
    from cryptography.hazmat.primitives import serialization

    info = json.loads(gh("release", "view", tag, "--json", "isDraft,assets", capture=True))
    names = {a["name"] for a in info["assets"]}
    missing = [f for f in ASSETS.values() if f not in names]
    if missing:
        sys.exit(f"release {tag} is missing {', '.join(missing)} - has the GitHub build finished?")

    with tempfile.TemporaryDirectory() as tmp:
        for f in ASSETS.values():
            gh("release", "download", tag, "-p", f, "-D", tmp, "--clobber")
        with zipfile.ZipFile(os.path.join(tmp, ASSETS["app"])) as zf:
            init = zf.read("netscan/__init__.py").decode("utf-8")
        found = re.search(r'__version__\s*=\s*"([^"]+)"', init)
        if not found or found.group(1) != version:
            sys.exit(f"the code in the release says {found.group(1) if found else '?'}, the tag says {version}")

        assets = {}
        for key, f in ASSETS.items():
            data = open(os.path.join(tmp, f), "rb").read()
            assets[key] = {"file": f, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
        manifest = json.dumps({"version": version, "tag": tag, "assets": assets}, sort_keys=True)
        private = serialization.load_pem_private_key(open(KEY, "rb").read(), None)
        sig = base64.b64encode(private.sign(manifest.encode("utf-8"))).decode()
        latest = os.path.join(tmp, "latest.json")
        with open(latest, "w", encoding="utf-8") as fh:
            json.dump({"manifest": manifest, "sig": sig}, fh)

        # prove the file verifies with the key built into the app before anyone downloads it
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from netscan import updater
        updater.verify(json.load(open(latest)))

        gh("release", "upload", tag, latest, "--clobber")
    gh("release", "edit", tag, "--draft=false", "--latest")
    print(f"published {tag}: exe {assets['exe']['size'] // 1024} KB, app {assets['app']['size'] // 1024} KB")
    print("installed copies will pick it up at their next check (within 6 hours, or Settings -> Updates -> Check now)")


if __name__ == "__main__":
    main()
