"""Access control for an internet-facing console: trusted proxies and IP allow-lists.

When NetSentinel sits behind nginx/Caddy/IIS/Cloudflare, the connection comes from the
proxy, so the real client address is in `X-Forwarded-For`. Trusting that header from
anyone would let a client spoof its address, so it is only honoured when the direct peer
is in `access.trusted_proxies`.

The allow-list is checked on every request, so a console published through a tunnel or a
port-forward can be limited to known networks even before sign-in happens.
"""

from __future__ import annotations

import ipaddress

DEFAULT_PROXIES = ["127.0.0.1", "::1"]


def _parse_cidrs(values):
    out = []
    for value in values or []:
        value = str(value).strip()
        if not value:
            continue
        try:
            out.append(ipaddress.ip_network(value, strict=False))
        except ValueError:
            continue
    return out


def client_ip(peer, headers, trusted_proxies=None):
    """Real client address, using X-Forwarded-For only from a trusted proxy."""
    peer = (peer or "").strip()
    trusted = _parse_cidrs(trusted_proxies or DEFAULT_PROXIES)
    peer_ip = None
    try:
        peer_ip = ipaddress.ip_address(peer)
    except ValueError:
        peer_ip = None
    if peer_ip is not None and any(peer_ip in net for net in trusted):
        forwarded = ""
        for key in ("X-Forwarded-For", "X-Real-IP"):
            value = headers.get(key) if hasattr(headers, "get") else None
            if value:
                forwarded = value
                break
        if forwarded:
            first = forwarded.split(",")[0].strip()
            try:
                return str(ipaddress.ip_address(first))
            except ValueError:
                pass
    return peer


def scheme(headers, tls_active=False):
    """Was the browser talking HTTPS? (TLS here, or a proxy that says so.)"""
    if tls_active:
        return "https"
    value = (headers.get("X-Forwarded-Proto") if hasattr(headers, "get") else "") or ""
    return "https" if value.lower() == "https" else "http"


def allowed(ip, allow_cidrs=None, deny_cidrs=None):
    """(ok, reason) for one client address."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False, "unparseable client address"
    deny = _parse_cidrs(deny_cidrs)
    if deny and any(addr in net for net in deny):
        return False, "address is on the deny list"
    allow = _parse_cidrs(allow_cidrs)
    if allow and not any(addr in net for net in allow):
        return False, "address is not in the allow list"
    return True, ""


def describe(cfg):
    """Short human summary for the console banner."""
    access = cfg or {}
    allow = access.get("allow_cidrs") or []
    proxies = access.get("trusted_proxies") or []
    parts = []
    parts.append("allow " + ", ".join(allow) if allow else "allow: any address")
    if proxies:
        parts.append("trusting proxy headers from " + ", ".join(proxies))
    return " | ".join(parts)
