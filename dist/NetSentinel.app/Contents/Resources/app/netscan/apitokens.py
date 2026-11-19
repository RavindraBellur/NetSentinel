"""API tokens for automation (scripts, CI, a SIEM poller, a monitoring aggregator).

Tokens are shown once, stored as SHA-256 hashes, and carry a scope:
  read  - GET only
  write - read plus acknowledging incidents
Every use is recorded (last_used) so a token can be identified and revoked.
"""

from __future__ import annotations

import hashlib
import secrets
import time

from . import store

SCOPES = ("read", "write")


def _hash(token):
    return hashlib.sha256((token or "").encode("utf-8")).hexdigest()


def create(name, scope="read"):
    scope = (scope or "read").lower()
    if scope not in SCOPES:
        raise ValueError("scope must be read or write")
    token = "nsk_" + secrets.token_urlsafe(30)
    ok = store.save_api_token(name[:48] or "api", _hash(token), scope)
    if not ok:
        raise RuntimeError("could not store the token")
    return token


def check(token, need="read"):
    """Return the token record when valid and permitted, else None."""
    if not token:
        return None
    rec = store.api_token_by_hash(_hash(token))
    if not rec:
        return None
    scope = (rec.get("scope") or "read").lower()
    if need == "write" and scope != "write":
        return None
    store.touch_api_token(rec["id"])
    return rec


def revoke(name_or_id):
    return store.delete_api_token(name_or_id)


def listing():
    return store.api_tokens()
