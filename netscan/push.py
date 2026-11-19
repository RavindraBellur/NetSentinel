"""Instant alerts on your phone - free, no account, no SMS bill.

Uses ntfy.sh: you pick a topic name (a long random string is your secret), subscribe to it
in the ntfy app, and Prahari POSTs to it. Nothing else is needed, and the same code can post
to any custom JSON webhook instead.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request

NTFY = "https://ntfy.sh"
PRIORITY = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
TAGS = {"critical": "rotating_light", "high": "warning", "medium": "eyes",
        "low": "information_source", "info": "white_check_mark"}


def ready(cfg):
    p = cfg.get("push") or {}
    if not p.get("enabled"):
        return False, "push is off"
    if (p.get("provider") or "ntfy") == "ntfy":
        if not (p.get("topic") or "").strip():
            return False, "no ntfy topic set"
    elif not (p.get("url") or "").strip():
        return False, "no webhook URL set"
    return True, ""


def send(cfg, title, body, severity="high", url=None):
    """One push. Returns (ok, message)."""
    ok, why = ready(cfg)
    if not ok:
        return False, why
    p = cfg.get("push") or {}
    provider = (p.get("provider") or "ntfy").lower()
    severity = (severity or "high").lower()
    try:
        if provider == "ntfy":
            base = (p.get("server") or NTFY).rstrip("/")
            topic = (p.get("topic") or "").strip()
            target = f"{base}/{topic}"
            data = (body or "").encode("utf-8")
            req = urllib.request.Request(target, data=data, method="POST", headers={
                "Title": (title or "Prahari")[:120],
                "Priority": str(PRIORITY.get(severity, 4)),
                "Tags": TAGS.get(severity, "warning"),
                "Content-Type": "text/plain; charset=utf-8",
            })
        else:
            target = (p.get("url") or "").strip()
            payload = json.dumps({"title": title, "text": body, "severity": severity,
                                  "site": cfg.get("site_name") or ""}).encode()
            req = urllib.request.Request(target, data=payload, method="POST",
                                         headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=12) as resp:
            return (200 <= resp.status < 300), f"HTTP {resp.status}"
    except urllib.error.HTTPError as exc:
        return False, f"HTTP {exc.code} {exc.read(160).decode('utf-8', 'replace')[:120]}"
    except Exception as exc:
        return False, f"{exc.__class__.__name__}: {exc}"[:140]
