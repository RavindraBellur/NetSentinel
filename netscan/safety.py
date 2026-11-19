"""Shared guards for the two features that act on devices instead of only watching them:
the factory-password check (defaults.py) and PoE power-cycling (remediation.py).

Rules that hold whatever the settings say:
  * Only private, on-premises addresses (RFC 1918, RFC 4193, link-local). A public address on
    an allow-list is refused - these features are for your own LAN, never the internet.
  * Switching either feature into a mode that touches devices records who did it and when
    (settings + the Events log), so there is always an accountable person.
"""

from __future__ import annotations

import ipaddress
import time


LAN_RANGES = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",   # RFC 1918
    "169.254.0.0/16",                                   # IPv4 link-local
    "fc00::/7", "fe80::/10",                            # IPv6 unique-local, link-local
))


def private_target(ip):
    """(ok, reason): is this an on-premises address these features may touch?"""
    try:
        addr = ipaddress.ip_address(str(ip or "").strip())
    except ValueError:
        return False, f"{ip!r} is not an IP address"
    if any(addr in net for net in LAN_RANGES if net.version == addr.version):
        return True, "private LAN address"
    return False, f"{addr} is not a private LAN address - only devices on your own LAN may be tested"


def record_acknowledgements(old_cfg, patch, who, add_event=None):
    """Stamp who enabled an active feature, inside the settings patch itself. Returns the notes made."""
    notes = []
    now = int(time.time())
    stamp = time.strftime("%d/%m/%Y %H:%M")
    dc_new = (patch or {}).get("defaults_check")
    dc_old = (old_cfg or {}).get("defaults_check") or {}
    if isinstance(dc_new, dict) and dc_new.get("i_own_this_network") and not dc_old.get("i_own_this_network"):
        dc_new["acknowledged_by"], dc_new["acknowledged_at"] = who, now
        notes.append(f"{who} confirmed they own this network and may test its devices ({stamp})")
    rem_new = (patch or {}).get("remediation")
    rem_old = (old_cfg or {}).get("remediation") or {}
    if isinstance(rem_new, dict) and rem_new.get("dry_run") is False and rem_old.get("dry_run", True) is not False:
        rem_new["live_enabled_by"], rem_new["live_enabled_at"] = who, now
        notes.append(f"{who} switched remediation from dry-run to LIVE ({stamp})")
    for note in notes:
        if add_event:
            add_event("safety", "medium", note)
    return notes
