"""TOTP (RFC 6238) for local accounts, so break-glass access is not one password.

Compatible with Google Authenticator, Microsoft Authenticator, Authy, 1Password and any
other RFC 6238 app. Secrets are 160-bit base32, codes are 6 digits / 30 s, and a small
window is accepted to allow for clock drift. Ten single-use backup codes are issued at
enrolment and stored only as SHA-256 hashes.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time

DIGITS = 6
STEP = 30
WINDOW = 1          # accept one step either side
BACKUP_CODES = 10


def new_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _key(secret):
    pad = "=" * (-len(secret) % 8)
    return base64.b32decode(secret.upper() + pad)


def code(secret, at=None, step=STEP, digits=DIGITS):
    """The 6-digit code for a moment in time."""
    counter = int((at if at is not None else time.time()) // step)
    digest = hmac.new(_key(secret), struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % (10 ** digits)).zfill(digits)


def verify(secret, submitted, at=None, window=WINDOW):
    """True when the submitted code is valid for this secret (with drift allowance)."""
    submitted = (submitted or "").strip().replace(" ", "")
    if not secret or not submitted.isdigit():
        return False
    now = at if at is not None else time.time()
    for offset in range(-window, window + 1):
        if hmac.compare_digest(code(secret, now + offset * STEP), submitted):
            return True
    return False


def provisioning_uri(secret, account, issuer="Prahari"):
    """otpauth:// URI for a QR code."""
    from urllib.parse import quote

    label = quote(f"{issuer}:{account}")
    return (f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer)}"
            f"&algorithm=SHA1&digits={DIGITS}&period={STEP}")


def new_backup_codes(count=BACKUP_CODES):
    """Return (plain codes, hashed codes) - store only the hashes."""
    plain = [f"{secrets.token_hex(2)}-{secrets.token_hex(2)}" for _ in range(count)]
    return plain, [hash_backup(c) for c in plain]


def hash_backup(value):
    return hashlib.sha256((value or "").strip().lower().encode("utf-8")).hexdigest()


def use_backup(hashes, submitted):
    """Consume a backup code: returns (ok, remaining_hashes)."""
    if not submitted:
        return False, hashes or []
    want = hash_backup(submitted)
    remaining = []
    matched = False
    for item in hashes or []:
        if not matched and hmac.compare_digest(item, want):
            matched = True
            continue
        remaining.append(item)
    return matched, remaining
