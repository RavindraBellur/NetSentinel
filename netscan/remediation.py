"""Guarded automatic fixes.

An automatic action is only acceptable when it is bounded, visible and reversible-ish. This
module therefore refuses to do anything unless ALL of these are true:

  * remediation is switched on in Settings, and the device is on the allow-list
  * the action is in the small set of known-safe actions below
  * we are inside the configured time window (default 01:00-06:00, so guests are not
    disturbed and a mistake is found by staff in the morning, not at dinner)
  * the same device has not already been touched more than N times in an hour
  * it is not a dry run (a dry run only records what it would have done)

Every attempt - refused, dry or executed - is written to the audit log, so the console can
show exactly what the software did and when.

Actions implemented:
  poe_bounce   power-cycle the switch port an access point or camera hangs off (SNMP SET)
  nothing else. Rebooting a device, changing a config or touching a server is deliberately
  left to a human.
"""

from __future__ import annotations

import datetime
import time

from . import settings, store

SAFE_ACTIONS = {"poe_bounce"}
# PethPsePortAdminEnable / pethPsePortPowerPairsControlAbility are vendor specific; the
# widely implemented one is POWER-ETHERNET-MIB pethPsePortAdminEnable
OID_POE_ADMIN_ENABLE = "1.3.6.1.2.1.105.1.1.1.1.3"


def _window(cfg):
    window = (cfg.get("remediation") or {}).get("window") or "01:00-06:00"
    try:
        start, end = window.split("-")
        sh, sm = (int(x) for x in start.split(":"))
        eh, em = (int(x) for x in end.split(":"))
        return sh * 60 + sm, eh * 60 + em
    except Exception:
        return 60, 360


def allowed_now(cfg, when=None):
    """Are we inside the maintenance window?"""
    now = when or datetime.datetime.now()
    minutes = now.hour * 60 + now.minute
    start, end = _window(cfg)
    if start <= end:
        return start <= minutes <= end
    return minutes >= start or minutes <= end      # window crosses midnight


def _recent_attempts(ip, minutes=60):
    since = int(time.time()) - minutes * 60
    rows = store._exec("SELECT COUNT(*) AS n FROM events WHERE source LIKE ? AND ts>=?",
                       (f"remediation {ip}%", since), fetch=True)
    return (rows[0]["n"] if rows else 0) or 0


def decide(cfg, ip, action, dry_run=None):
    """Should this action run? Returns (allowed, reason)."""
    rem = cfg.get("remediation") or {}
    if not rem.get("enabled"):
        return False, "remediation is off"
    if action not in SAFE_ACTIONS:
        return False, f"{action} is not an approved action"
    allow = [x.strip() for x in (rem.get("allow_ips") or []) if x.strip()]
    if allow and ip not in allow:
        return False, f"{ip} is not on the allow-list"
    if not allow:
        return False, "the allow-list is empty (add the device IPs first)"
    from .safety import private_target
    ok, why = private_target(ip)
    if not ok:
        return False, why
    if not allowed_now(cfg):
        return False, "outside the maintenance window"
    limit = int(rem.get("max_per_hour") or 2)
    if _recent_attempts(ip) >= limit:
        return False, f"already tried {limit} time(s) this hour"
    if rem.get("dry_run", True) if dry_run is None else dry_run:   # dry-run unless explicitly off
        return True, "dry run: would run"
    return True, "allowed"


def poe_bounce(ip, port_index="1", community="private", off_seconds=10, log=None):
    """Switch the PoE port off, wait, switch it back on."""
    from . import snmp
    off = snmp.set(ip, OID_POE_ADMIN_ENABLE, 2, port_index, community)  # 2 = disabled
    time.sleep(max(3, off_seconds))
    on = snmp.set(ip, OID_POE_ADMIN_ENABLE, 1, port_index, community)   # 1 = enabled
    if log:
        log(f"poe bounce {ip} port {port_index}: off={off} on={on}")
    return bool(off and on)


def run(cfg, ip, action="poe_bounce", port_index="1", community="private", log=None):
    """Check, act, audit. Returns a dict describing what happened."""
    ok, reason = decide(cfg, ip, action)
    stamp = time.strftime("%d/%m/%Y %H:%M:%S")
    store.add_event(f"remediation {ip}", "medium" if ok else "info",
                    f"{action}: {reason} at {stamp}")
    if not ok:
        if log:
            log(f"remediation refused for {ip}: {reason}")
        return {"ok": False, "reason": reason}
    dry = bool((cfg.get("remediation") or {}).get("dry_run", True))
    if dry:
        return {"ok": True, "dry_run": True, "reason": "dry run: nothing was changed"}
    done = poe_bounce(ip, port_index, community, log=log)
    store.add_event(f"remediation {ip}", "high",
                    f"{action} executed on port {port_index}: {'ok' if done else 'failed'}")
    return {"ok": done, "dry_run": False,
            "reason": "port power-cycled" if done else "the switch refused the SNMP set"}


def status():
    cfg = settings.load()
    rem = cfg.get("remediation") or {}
    return {"enabled": bool(rem.get("enabled")), "dry_run": bool(rem.get("dry_run", True)),
            "window": rem.get("window") or "01:00-06:00",
            "allow_ips": rem.get("allow_ips") or [],
            "inside_window": allowed_now(cfg),
            "actions": sorted(SAFE_ACTIONS)}
