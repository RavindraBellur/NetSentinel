"""Fleet update: the head-office hub decides WHEN branches upgrade; the signature decides WHAT they install.

Branches only ever talk outwards, so the hub cannot push to them. Instead the hub answers every
branch report with the version it wants the fleet on (Settings -> Fleet update). A branch that is
older asks its own updater to install the newest *signed* release from GitHub right away, even if
automatic installs are switched off on that branch. The hub never supplies code, a URL or a hash:
whoever controls the hub can only make branches install a release you signed.

(Up to 1.21 the hub supplied a download URL and SHA-256 itself; that path is gone because it let
anyone with access to the hub run code on every branch.)
"""

from __future__ import annotations

import time

from . import settings

_last_request = {"version": None, "at": 0.0}
RETRY_AFTER = 30 * 60  # don't re-trigger the same version more often than this


def current_version():
    import netscan
    return getattr(netscan, "__version__", "0")


def hub_reply(branch_version):
    """Hub side: the `update` block to add to a branch-report reply, or None."""
    target = str((settings.get("fleet_update") or {}).get("version") or "").strip()
    if not target:
        return None
    from .updater import vtuple
    if vtuple(branch_version or "0") >= vtuple(target):
        return None
    return {"version": target}


def pending_update(response, hub_url="", log=print):
    """Branch side: act on an `update` block in a hub reply. Returns a message or None."""
    if not isinstance(response, dict):
        return None
    offer = response.get("update") or {}
    target = str(offer.get("version") or "").strip()
    if not target:
        return None
    from . import updater
    if updater.vtuple(target) <= updater.vtuple(current_version()):
        return None
    if not (settings.get("branch") or {}).get("auto_update", True):
        log(f"hub asks for {target} but fleet updates are off on this branch")
        return None
    upd = updater.CURRENT
    if upd is None or upd.mode == "notify":
        return None
    now = time.time()
    if _last_request["version"] == target and now - _last_request["at"] < RETRY_AFTER:
        return None
    _last_request.update(version=target, at=now)
    log(f"hub asks for {target} - installing the newest signed release")
    upd.check_now(install=True)
    return f"installing {target}"
