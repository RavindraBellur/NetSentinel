"""Sign-in, sessions and lockout for the dashboard.

Off by default on a localhost-only install, on automatically when the dashboard is
shared on the LAN. Passwords are PBKDF2-SHA256 with a per-user salt, sessions are
random tokens held in memory with an expiry, and five wrong attempts lock that
client address out for ten minutes.
"""

from __future__ import annotations

import secrets
import threading
import time

from . import store

_sessions = {}
_pending = {}   # short-lived tokens between password and 2FA step
_failures = {}
_lock = threading.RLock()

LOCK_AFTER = 5
LOCK_SECONDS = 600

# What each role may do. "viewer" watches, "engineer" fixes, "admin" configures.
ROLE_ACTIONS = {
    "viewer": {"read"},
    "engineer": {"read", "scan", "remote", "incident", "label", "report"},
    "admin": {"read", "scan", "remote", "incident", "label", "report",
              "settings", "users", "alerts"},
}


def can(role, action):
    return action in ROLE_ACTIONS.get((role or "viewer").lower(), {"read"})


def role_label(role):
    return {"viewer": "Viewer (read only)",
            "engineer": "Engineer (operate)",
            "admin": "Administrator"}.get((role or "").lower(), role or "unknown")


def _now():
    return time.time()


def locked(ip):
    with _lock:
        rec = _failures.get(ip)
        if not rec:
            return 0
        count, last = rec
        if count < LOCK_AFTER:
            return 0
        remaining = int(LOCK_SECONDS - (_now() - last))
        if remaining <= 0:
            _failures.pop(ip, None)
            return 0
        return remaining


def note_failure(ip):
    with _lock:
        count, _ = _failures.get(ip, (0, 0))
        _failures[ip] = (count + 1, _now())


def clear_failures(ip):
    with _lock:
        _failures.pop(ip, None)


def login(ip, username, password, hours=12):
    wait = locked(ip)
    if wait:
        return None, f"Too many failed attempts. Try again in {wait // 60 + 1} minutes."
    user = store.check_user(username, password)
    if not user:
        note_failure(ip)
        return None, "Wrong user name or password."
    clear_failures(ip)
    token = secrets.token_urlsafe(32)
    with _lock:
        _sessions[token] = {"user": user["username"], "role": user["role"],
                            "expires": _now() + hours * 3600}
    return token, ""


def start_second_factor(username, minutes=5):
    """Token that proves the password was accepted, for the TOTP step."""
    token = secrets.token_urlsafe(24)
    with _lock:
        _pending[token] = {"user": username, "expires": _now() + minutes * 60}
    return token


def second_factor_user(token):
    with _lock:
        rec = _pending.get(token or "")
        if not rec or rec["expires"] < _now():
            _pending.pop(token or "", None)
            return ""
        return rec["user"]


def finish_second_factor(token):
    with _lock:
        rec = _pending.pop(token or "", None)
        return rec["user"] if rec else ""


def login_sso(username, role, hours=12, provider=""):
    """Create a session for a user already authenticated by the identity provider."""
    token = secrets.token_urlsafe(32)
    with _lock:
        _sessions[token] = {"user": username, "role": role,
                            "expires": _now() + hours * 3600, "provider": provider}
    return token


def logout(token):
    with _lock:
        _sessions.pop(token, None)


def session(token):
    if not token:
        return None
    with _lock:
        rec = _sessions.get(token)
        if not rec:
            return None
        if rec["expires"] < _now():
            _sessions.pop(token, None)
            return None
        return dict(rec)


def active_sessions():
    with _lock:
        return sum(1 for r in _sessions.values() if r["expires"] >= _now())


def ensure_admin():
    """Create the first admin with a random password. Returns (username, password) or None."""
    if store.user_count():
        return None
    password = secrets.token_urlsafe(9)
    if store.create_user("admin", password, "admin"):
        return "admin", password
    return None
