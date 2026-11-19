"""Single sign-on with an OpenID Connect provider (Microsoft Entra ID, Okta, Keycloak,
Google Workspace, Auth0, ADFS via OIDC).

Authorisation-code flow with PKCE, state and nonce. The ID token signature is verified
against the provider's published JWKS with RS256 - if the `cryptography` package is not
installed, SSO refuses to start rather than accepting unverified tokens (fail closed).

Role mapping: a claim (default `groups`) is matched against `role_map`; anything else
falls back to `default_role` (viewer). Only addresses in `allowed_domains` may sign in.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request

_META_CACHE = {}
_JWKS_CACHE = {}


# ----------------------------------------------------------------- helpers --

def b64url_decode(data):
    if isinstance(data, str):
        data = data.encode("ascii")
    pad = b"=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def b64url_encode(data):
    if isinstance(data, str):
        data = data.encode("ascii")
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _get_json(url, timeout=10, headers=None):
    req = urllib.request.Request(url, headers=headers or {"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read(262144).decode("utf-8"))


def _post_form(url, fields, timeout=15):
    data = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read(262144).decode("utf-8"))


def have_crypto():
    try:
        import cryptography  # noqa: F401
        return True
    except Exception:
        return False


# ------------------------------------------------------------------ client --

class OIDCError(Exception):
    pass


class OIDCClient:
    def __init__(self, cfg):
        self.cfg = cfg or {}
        self.issuer = (self.cfg.get("issuer") or "").rstrip("/")
        self.client_id = self.cfg.get("client_id") or ""
        self.client_secret = self.cfg.get("client_secret") or ""
        self.redirect_uri = self.cfg.get("redirect_uri") or ""
        self.scopes = self.cfg.get("scopes") or "openid profile email"
        self.role_claim = self.cfg.get("role_claim") or "groups"
        self.role_map = self.cfg.get("role_map") or {}
        self.default_role = (self.cfg.get("default_role") or "viewer").lower()
        self.allowed_domains = [d.lower().lstrip("@") for d in (self.cfg.get("allowed_domains") or [])]
        self._pending = {}   # state -> {"verifier", "nonce", "created"}

    # -- configuration ---------------------------------------------------
    def ready(self):
        missing = [k for k in ("issuer", "client_id", "redirect_uri") if not self.cfg.get(k)]
        if missing:
            return False, "missing " + ", ".join(missing)
        if not have_crypto():
            return False, "the 'cryptography' package is required for token signature checks"
        return True, ""

    def metadata(self):
        if self.issuer in _META_CACHE:
            return _META_CACHE[self.issuer]
        url = self.issuer + "/.well-known/openid-configuration"
        try:
            meta = _get_json(url)
        except Exception as exc:
            raise OIDCError(f"could not read {url}: {exc}")
        for key in ("authorization_endpoint", "token_endpoint", "jwks_uri", "issuer"):
            if not meta.get(key):
                raise OIDCError(f"provider metadata is missing {key}")
        _META_CACHE[self.issuer] = meta
        return meta

    # -- flow -------------------------------------------------------------
    def start(self):
        """Return (authorize_url, state)."""
        meta = self.metadata()
        state = secrets.token_urlsafe(24)
        nonce = secrets.token_urlsafe(16)
        verifier = secrets.token_urlsafe(48)
        challenge = b64url_encode(hashlib.sha256(verifier.encode("ascii")).digest())
        self._pending[state] = {"verifier": verifier, "nonce": nonce, "created": time.time()}
        self._prune()
        params = {
            "client_id": self.client_id,
            "response_type": "code",
            "redirect_uri": self.redirect_uri,
            "scope": self.scopes,
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "response_mode": "query",
        }
        return meta["authorization_endpoint"] + "?" + urllib.parse.urlencode(params), state

    def _prune(self, max_age=600):
        cutoff = time.time() - max_age
        for key in [k for k, v in self._pending.items() if v["created"] < cutoff]:
            self._pending.pop(key, None)

    def finish(self, code, state):
        """Exchange the code and return verified claims."""
        pending = self._pending.pop(state or "", None)
        if not pending:
            raise OIDCError("sign-in state is unknown or expired - start again")
        meta = self.metadata()
        fields = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.redirect_uri,
            "client_id": self.client_id,
            "code_verifier": pending["verifier"],
        }
        if self.client_secret:
            fields["client_secret"] = self.client_secret
        try:
            tokens = _post_form(meta["token_endpoint"], fields)
        except urllib.error.HTTPError as exc:
            detail = exc.read(400).decode("utf-8", "replace")
            raise OIDCError(f"token request refused: HTTP {exc.code} {detail[:160]}")
        except Exception as exc:
            raise OIDCError(f"token request failed: {exc}")
        id_token = tokens.get("id_token")
        if not id_token:
            raise OIDCError("the provider did not return an id_token")
        claims = self.verify(id_token, pending["nonce"])
        self.authorize(claims)
        return claims

    # -- verification -----------------------------------------------------
    def jwks(self):
        meta = self.metadata()
        uri = meta["jwks_uri"]
        cached = _JWKS_CACHE.get(uri)
        if cached and time.time() - cached[0] < 3600:
            return cached[1]
        keys = _get_json(uri).get("keys") or []
        _JWKS_CACHE[uri] = (time.time(), keys)
        return keys

    def verify(self, token, nonce=None):
        if not have_crypto():
            raise OIDCError("cannot verify token signatures without the 'cryptography' package")
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding, rsa

        parts = token.split(".")
        if len(parts) != 3:
            raise OIDCError("malformed id_token")
        header = json.loads(b64url_decode(parts[0]))
        claims = json.loads(b64url_decode(parts[1]))
        signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
        signature = b64url_decode(parts[2])

        alg = header.get("alg", "")
        if alg not in ("RS256", "RS384", "RS512"):
            raise OIDCError(f"unsupported token algorithm {alg!r} (RS256 is required)")
        kids = [k for k in self.jwks() if k.get("kid") == header.get("kid")] or self.jwks()
        verified = False
        for jwk in kids:
            if jwk.get("kty") != "RSA":
                continue
            try:
                n = int.from_bytes(b64url_decode(jwk["n"]), "big")
                e = int.from_bytes(b64url_decode(jwk["e"]), "big")
                pub = rsa.RSAPublicNumbers(e, n).public_key()
                pub.verify(signature, signing_input,
                           padding.PKCS1v15(), getattr(hashes, "SHA" + alg[2:])())
                verified = True
                break
            except (InvalidSignature, ValueError, KeyError):
                continue
        if not verified:
            raise OIDCError("id_token signature did not verify against the provider JWKS")

        now = int(time.time())
        if claims.get("exp") and int(claims["exp"]) < now - 60:
            raise OIDCError("id_token has expired")
        if claims.get("iat") and int(claims["iat"]) > now + 300:
            raise OIDCError("id_token is issued in the future")
        aud = claims.get("aud")
        auds = aud if isinstance(aud, list) else [aud]
        if self.client_id not in [a for a in auds if a]:
            raise OIDCError("id_token audience does not include this client")
        if nonce and claims.get("nonce") and claims["nonce"] != nonce:
            raise OIDCError("id_token nonce does not match this sign-in attempt")
        return claims

    # -- policy -----------------------------------------------------------
    def identity(self, claims):
        email = (claims.get("email") or claims.get("preferred_username")
                 or claims.get("upn") or claims.get("name") or "").strip()
        if not email:
            raise OIDCError("the provider did not send an email or user name claim")
        return email

    def authorize(self, claims):
        email = self.identity(claims)
        if self.allowed_domains:
            domain = email.split("@")[-1].lower()
            if domain not in self.allowed_domains:
                raise OIDCError(f"{email} is not in an allowed domain ({', '.join(self.allowed_domains)})")
        if claims.get("email_verified") is False:
            raise OIDCError("the provider reports this address as unverified")
        return email

    def role_for(self, claims):
        values = claims.get(self.role_claim)
        if isinstance(values, str):
            values = [values]
        if not isinstance(values, list):
            values = []
        lowered = {}
        for key, role in (self.role_map or {}).items():
            lowered[str(key).lower()] = (role or "").lower()
        best = ""
        rank = {"viewer": 1, "engineer": 2, "admin": 3}
        for value in values:
            role = lowered.get(str(value).lower())
            if role and rank.get(role, 0) > rank.get(best, 0):
                best = role
        if best:
            return best
        # some providers put roles in a flat "roles" claim
        for value in claims.get("roles") or []:
            role = lowered.get(str(value).lower())
            if role and rank.get(role, 0) > rank.get(best, 0):
                best = role
        return best or self.default_role

    def end_session_url(self):
        try:
            meta = self.metadata()
        except Exception:
            return ""
        return meta.get("end_session_endpoint") or ""
