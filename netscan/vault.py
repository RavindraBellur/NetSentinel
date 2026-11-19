"""Encrypt the secrets in config.json at rest.

config.json holds the SMTP password, the Telegram token and the SNMPv3 keys in clear text,
which means anyone who copies the file has them. This wraps those values with AES-GCM using
a key kept beside the database with owner-only permissions.

Values are stored as `enc:v1:<base64>`; anything without that prefix is read as-is, so an
existing config keeps working and a value written by hand still loads.

If the `cryptography` package is missing, nothing is encrypted and `status()` says so - it
does not pretend. That package is also what SNMPv3 privacy needs, so install it once and
both features light up.
"""

from __future__ import annotations

import base64
import json
import os

from . import store

PREFIX = "enc:v1:"
KEY_PATH = os.path.join(os.path.dirname(store.DB_PATH), "vault.key")
SECRET_PATHS = (
    ("email", "password"),
    ("telegram", "token"),
    ("snmp_v3", "auth_password"),
    ("snmp_v3", "priv_password"),
    ("oidc", "client_secret"),
    ("push", "url"),
    ("ai", "api_key"),
)


def _crypto():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        return AESGCM
    except Exception:
        return None


def available():
    return _crypto() is not None


def _key():
    AESGCM = _crypto()
    if AESGCM is None:
        return None
    try:
        os.makedirs(os.path.dirname(KEY_PATH), exist_ok=True)
        if not os.path.exists(KEY_PATH):
            with open(KEY_PATH, "wb") as fh:
                fh.write(os.urandom(32))
            try:
                os.chmod(KEY_PATH, 0o600)
            except OSError:
                pass
        with open(KEY_PATH, "rb") as fh:
            data = fh.read()
        if len(data) < 32:
            return None
        return data[:32]
    except OSError:
        return None


def encrypt_value(text):
    if not text or text.startswith(PREFIX):
        return text
    AESGCM = _crypto()
    key = _key()
    if AESGCM is None or key is None:
        return text
    nonce = os.urandom(12)
    blob = AESGCM(key).encrypt(nonce, str(text).encode("utf-8"), None)
    return PREFIX + base64.b64encode(nonce + blob).decode()


def decrypt_value(text):
    if not isinstance(text, str) or not text.startswith(PREFIX):
        return text
    AESGCM = _crypto()
    key = _key()
    if AESGCM is None or key is None:
        return ""
    try:
        raw = base64.b64decode(text[len(PREFIX):])
        return AESGCM(key).decrypt(raw[:12], raw[12:], None).decode("utf-8")
    except Exception:
        return ""


def seal(cfg):
    """Return a copy of cfg with the secret paths encrypted."""
    if not available():
        return cfg
    out = json.loads(json.dumps(cfg))
    for section, key in SECRET_PATHS:
        block = out.get(section)
        if isinstance(block, dict) and block.get(key):
            block[key] = encrypt_value(block[key])
    return out


def open_secrets(cfg):
    """Return a copy of cfg with the secret paths decrypted."""
    out = json.loads(json.dumps(cfg))
    for section, key in SECRET_PATHS:
        block = out.get(section)
        if isinstance(block, dict) and block.get(key):
            block[key] = decrypt_value(block[key])
    return out


def status():
    AESGCM = _crypto()
    return {"available": AESGCM is not None,
            "key_file": os.path.exists(KEY_PATH),
            "protected": [f"{s}.{k}" for s, k in SECRET_PATHS],
            "note": ("secrets are encrypted with AES-GCM" if AESGCM else
                     "the 'cryptography' package is not installed, so secrets are stored "
                     "in clear text - install it to encrypt them")}
