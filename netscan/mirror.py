"""Head-office update mirror: publish a signed release to the branches from the hub itself.

Branches only talk outwards to the hub, and some hotels cannot (or should not) reach GitHub. So the
hub keeps a copy of a signed release and serves it to its branches:

    Settings -> Fleet update -> "Publish to branches"
        1. the hub fetches latest.json + the files of the newest release from GitHub, or reads them
           from a folder you point it at (an offline head office copies the release there)
        2. it VERIFIES the Ed25519 signature and every SHA-256 before publishing anything
        3. it stores that exact copy and tells every older branch to update from it
    Each branch then downloads from the hub (authenticated with its branch token) and verifies the
    signature and checksums AGAIN with the key built into Prahari before installing.

So the hub decides when and serves the bytes, but cannot change what gets installed: a file that is
not the signed release fails on every branch. Unlike the unsigned "publish a zip" of the parallel
copy, compromising the hub does not let anyone run code on the hotels.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import time

from . import settings, updater
from .settings import CONFIG_DIR

MIRROR_DIR = os.path.join(CONFIG_DIR, "update-mirror")
CURRENT = os.path.join(MIRROR_DIR, "current.json")


def _read_json(path, default=None):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return default


def status():
    cur = _read_json(CURRENT, {}) or {}
    return {"version": cur.get("version", ""), "published": cur.get("published", 0),
            "source": cur.get("source", ""), "files": cur.get("files", []),
            "bytes": cur.get("bytes", 0)}


def publish(folder="", fetch=None):
    """Mirror and verify a signed release, then roll the fleet out to it.

    folder: a directory holding latest.json and the release files (offline head office);
            empty = download the newest release from GitHub.
    Returns {"ok": bool, "message": str, "version": str}."""
    fetch = fetch or updater._get
    try:
        if folder:
            folder = os.path.abspath(os.path.expanduser(folder.strip().strip('"')))
            latest_raw = open(os.path.join(folder, "latest.json"), "rb").read()
        else:
            latest_raw = fetch(updater.LATEST_URL, timeout=30, limit=64 * 1024)
        latest = json.loads(latest_raw)
        manifest = updater.verify(latest)          # raises unless signed with the Prahari key
    except FileNotFoundError:
        return {"ok": False, "message": "that folder has no latest.json - copy the whole release into it"}
    except Exception as exc:
        return {"ok": False, "message": f"not published: {str(exc)[:160]}"}

    version = manifest["version"]
    tag = manifest.get("tag") or "v" + version
    target = os.path.join(MIRROR_DIR, version)
    tmp = target + ".partial"
    shutil.rmtree(tmp, ignore_errors=True)
    os.makedirs(tmp)
    files, total = ["latest.json"], 0
    try:
        for asset in (manifest.get("assets") or {}).values():
            name = os.path.basename(asset["file"])
            if folder:
                data = open(os.path.join(folder, name), "rb").read()
            else:
                data = fetch(updater.ASSET_URL.format(tag=tag, file=name))
            if hashlib.sha256(data).hexdigest() != asset["sha256"]:
                raise ValueError(f"{name} does not match the signed checksum")
            with open(os.path.join(tmp, name), "wb") as fh:
                fh.write(data)
            files.append(name)
            total += len(data)
        with open(os.path.join(tmp, "latest.json"), "wb") as fh:
            fh.write(latest_raw)
    except FileNotFoundError as exc:
        shutil.rmtree(tmp, ignore_errors=True)
        return {"ok": False, "message": f"not published: {os.path.basename(str(exc.filename))} is missing"}
    except Exception as exc:
        shutil.rmtree(tmp, ignore_errors=True)
        return {"ok": False, "message": f"not published: {str(exc)[:160]}"}

    shutil.rmtree(target, ignore_errors=True)
    os.replace(tmp, target)
    cur = {"version": version, "published": int(time.time()), "dir": target, "files": files,
           "bytes": total, "source": folder or "GitHub"}
    with open(CURRENT + ".tmp", "w", encoding="utf-8") as fh:
        json.dump(cur, fh)
    os.replace(CURRENT + ".tmp", CURRENT)
    # keep only this release and the newest one before it (for a quick roll-back)
    older = sorted((d for d in os.listdir(MIRROR_DIR)
                    if os.path.isdir(os.path.join(MIRROR_DIR, d)) and d != version
                    and not d.endswith(".partial")), key=updater.vtuple)
    for name in older[:-1]:
        shutil.rmtree(os.path.join(MIRROR_DIR, name), ignore_errors=True)
    settings.save({"fleet_update": {"version": version, "mirror": True}})
    return {"ok": True, "version": version,
            "message": f"published {version} ({total // 1024} KB, signature verified) - every older "
                       "branch installs it on its next report"}


def file_for(name):
    """Path of a published file, or None. Only the exact files of the current release are served."""
    cur = _read_json(CURRENT, {}) or {}
    name = os.path.basename(name or "")
    if not name or name not in (cur.get("files") or []):
        return None
    path = os.path.join(cur.get("dir") or "", name)
    return path if os.path.isfile(path) else None
