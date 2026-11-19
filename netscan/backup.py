"""Nightly backup of the database, with rotation and an integrity check.

One SQLite file holds everything worth keeping: devices, history, incidents, users,
tokens. It is small (a few MB), so a plain copy is the right backup - taken with SQLite's
own backup API so it is consistent while the console is running.
"""

from __future__ import annotations

import os
import sqlite3
import threading
import time

from . import settings, store

BACKUP_DIR = os.path.join(os.path.dirname(store.DB_PATH), "backups")
KEEP_DAILY = 7
KEEP_WEEKLY = 4


def _stamp(ts=None):
    return time.strftime("%Y%m%d-%H%M%S", time.localtime(ts or time.time()))


def make(keep_daily=KEEP_DAILY, keep_weekly=KEEP_WEEKLY):
    """Copy the live database safely and rotate old copies. Returns (path, size)."""
    os.makedirs(BACKUP_DIR, exist_ok=True)
    target = os.path.join(BACKUP_DIR, f"netsentinel-{_stamp()}.db")
    src = sqlite3.connect(store.DB_PATH, timeout=15)
    dst = sqlite3.connect(target)
    try:
        with dst:
            src.backup(dst)          # consistent even while the console is writing
    finally:
        src.close()
        dst.close()

    # integrity check on the copy, not on the live file
    ok = True
    try:
        chk = sqlite3.connect(target)
        ok = chk.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        chk.close()
    except Exception:
        ok = False
    if not ok:
        try:
            os.remove(target)
        except OSError:
            pass
        raise RuntimeError("the backup copy failed its integrity check and was discarded")

    rotate(keep_daily, keep_weekly)
    return target, os.path.getsize(target)


def rotate(keep_daily=KEEP_DAILY, keep_weekly=KEEP_WEEKLY):
    """Keep the last N daily copies plus one per week for the last M weeks."""
    try:
        files = sorted(f for f in os.listdir(BACKUP_DIR)
                       if f.startswith("netsentinel-") and f.endswith(".db"))
    except FileNotFoundError:
        return []
    keep = set(files[-keep_daily:]) if keep_daily else set()
    weekly = {}
    for name in files:
        try:
            day = name.split("-")[1][:8]
        except IndexError:
            continue
        weekly.setdefault(day, name)
    for day in sorted(weekly)[-keep_weekly:]:
        keep.add(weekly[day])
    removed = []
    for name in files:
        if name not in keep:
            try:
                os.remove(os.path.join(BACKUP_DIR, name))
                removed.append(name)
            except OSError:
                pass
    return removed


def listing(limit=20):
    try:
        names = sorted(os.listdir(BACKUP_DIR), reverse=True)[:limit]
    except FileNotFoundError:
        return []
    out = []
    for name in names:
        path = os.path.join(BACKUP_DIR, name)
        try:
            out.append({"name": name, "bytes": os.path.getsize(path),
                        "when": os.path.getmtime(path)})
        except OSError:
            continue
    return out


def status():
    cfg = settings.load()
    b = cfg.get("backup") or {}
    items = listing(5)
    return {"enabled": bool(b.get("enabled", True)),
            "every_hours": int(b.get("every_hours") or 24),
            "keep_daily": int(b.get("keep_daily") or KEEP_DAILY),
            "keep_weekly": int(b.get("keep_weekly") or KEEP_WEEKLY),
            "last": items[0] if items else None,
            "count": len(listing(999))}


class BackupThread(threading.Thread):
    """Runs a backup on start-up and then every N hours."""

    def __init__(self, log=None):
        super().__init__(daemon=True, name="backup")
        self.log = log or (lambda m: None)
        self._stop = threading.Event()
        self.last_error = ""
        self.last_path = ""

    def stop(self):
        self._stop.set()

    def run(self):
        self._stop.wait(120)                      # let the console settle first
        while not self._stop.is_set():
            cfg = settings.load()
            b = cfg.get("backup") or {}
            if b.get("enabled", True):
                try:
                    path, size = make(int(b.get("keep_daily") or KEEP_DAILY),
                                      int(b.get("keep_weekly") or KEEP_WEEKLY))
                    self.last_path = path
                    self.last_error = ""
                    self.log(f"backup written: {os.path.basename(path)} ({size / 1024:.0f} KB)")
                except Exception as exc:
                    self.last_error = f"{exc.__class__.__name__}: {exc}"
                    self.log(f"backup failed: {self.last_error}")
            hours = int(b.get("every_hours") or 24)
            self._stop.wait(max(3600, hours * 3600))
