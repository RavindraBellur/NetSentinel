"""Roll-out helper: one folder of per-hotel setup files for a chain.

Given the hub address and the hotel names, this issues one token per site and writes,
for each site, a one-click `setup-<site>.cmd` plus a short checklist the local person can
follow. Tokens are stored on the hub as SHA-256 hashes only.
"""

from __future__ import annotations

import json
import os
import re
import time

from . import settings, sites, store, tailnet


def slug(name):
    return re.sub(r"[^a-z0-9]+", "-", (name or "site").lower()).strip("-")[:32] or "site"


SETUP_CMD = """@echo off
rem ===========================================================================
rem  NetSentinel - one-click setup for {name}
rem  Run this on the always-on PC at {name}. It installs if needed, then joins
rem  this site to the head office console.
rem ===========================================================================
setlocal
cd /d "%~dp0"
title NetSentinel - {name}

if not exist ".venv\\Scripts\\python.exe" (
  echo   First run - installing, please wait ...
  call install.bat
)

{ts_block}echo   Joining {name} to the head office console ...
".venv\\Scripts\\python.exe" netsentinel.py ^
  --site-name "{name}" ^
  --branch {hub} ^
  --token {token} ^{hb_arg}
  --lan --tls --allow-cidr {lan}
rem  (the allow-list above covers this PC and your Tailscale network only;
rem   add the hotel LAN, e.g. 192.168.1.0/24, if local staff should open it)

echo.
echo   Done. This PC is now site "{name}" and reports to {hub}
echo   Dashboard on this PC: https://127.0.0.1:8777
echo.
pause
"""

CHECKLIST = """NetSentinel - setup checklist for {name}
=====================================================

On the always-on PC (a mini PC on a UPS, wired to the core switch - not a guest AP):

[ ] 1. Copy the NetSentinel folder to C:\\NetSentinel and run setup-{slug}.cmd
       (it installs Python if needed, then Tailscale, then joins this site)
[ ] 2. Run setup-{slug}.cmd  (installs, then joins this site to head office)
[ ] 3. Right-click autostart_install.bat -> Run as administrator
       (so it comes back after a power cut)
[ ] 4. allow_firewall.bat as administrator (only needed for LAN browsing)

On the hotel router / firewall:

[ ] 5. Enable SNMP v2c with community "public" (read-only), allow this PC
[ ] 6. Enable NetFlow v9 export to this PC UDP 2055
       (MikroTik: /ip traffic-flow set enabled=yes; /ip traffic-flow target add
        address=<this-pc>:2055 version=9)
       (UniFi: Settings > Traffic & Security > Flow)
[ ] 7. Point syslog at this PC UDP 5514, if the router supports it
[ ] 8. Note the router make/model and the ISP plan in the site notes

Optional but recommended:

[ ] 9. Join this PC to your Tailscale network (so you can open its console from
       anywhere without opening a port)
[ ] 10. Put the router, switch and this PC on the same UPS
[ ] 11. Add the billing/PMS server as an agent:
        run.bat --agent --console https://<head-office>:8777 --token <agent token>

Who is emailed when this site goes offline
------------------------------------------
{who}

Dead-man's switch
-----------------
{hb_line}

Site details
------------
Site name : {name}
Hub       : {hub}
Token     : {token}
           (stored on the hub as a SHA-256 hash - keep this paper copy safe)
Issued    : {when}
"""


def read_csv(path):
    """Read 'name,region,email' rows (header optional) for a large roll-out."""
    import csv
    out = []
    with open(path, newline="", encoding="utf-8-sig") as fh:
        for row in csv.reader(fh):
            if not row or not row[0].strip():
                continue
            name = row[0].strip()
            if name.lower() in ("name", "site", "hotel"):
                continue
            region = row[1].strip() if len(row) > 1 else ""
            emails = [e.strip() for cell in row[2:]
                      for e in cell.replace(";", ",").split(",") if "@" in e]
            if region:
                name = f"{name} - {region}"
            out.append({"name": name, "email": emails})
    return out


def parse_emails(text):
    """'Udaipur=a@x,b@y;Goa=c@z' -> {'Udaipur': ['a@x','b@y'], 'Goa': ['c@z']}"""
    out = {}
    for block in (text or "").split(";"):
        if "=" not in block:
            continue
        name, emails = block.split("=", 1)
        found = [e.strip() for e in emails.replace(";", ",").split(",") if "@" in e]
        if name.strip():
            out[name.strip()] = found
    return out


def build(names, hub_url, out_dir, lan_hint="100.64.0.0/10,127.0.0.1", ts_key="", emails=None,
          site_rows=None):
    """site_rows: optional [{'name','email'}] from a CSV, instead of a plain name list."""
    """Write the per-site files and register the tokens on this (hub) machine.

    hub_url may be "auto": the Tailscale address of this PC is used, which needs no
    public IP, no domain and no money.
    """
    if (hub_url or "").strip().lower() in ("auto", "tailscale", "tailnet"):
        hub_url = tailnet.best_url(8777) or ""
        if not hub_url:
            raise RuntimeError(
                "could not find a Tailscale address on this PC. Install Tailscale "
                "(free) and run 'tailscale up', or give the hub address explicitly.")
    os.makedirs(out_dir, exist_ok=True)
    cfg = settings.load()
    hub = dict(cfg.get("hub") or {})
    hub["enabled"] = True
    rows = list(hub.get("sites") or [])
    emails = dict(emails or {})
    hb_map = {e.get("name"): e.get("heartbeat_url")
              for e in (hub.get("sites") or []) if e.get("heartbeat_url")}
    if site_rows:
        names = [r["name"] for r in site_rows]
        for r in site_rows:
            if r.get("email"):
                emails[r["name"]] = r["email"]
    made = []
    for name in names:
        name = name.strip()
        if not name:
            continue
        token = sites.new_token()
        rows = [r for r in rows if r.get("name") != name]
        rows.append({"name": name, "token_hash": sites.token_hash(token),
                     "email": emails.get(name) or emails.get(name.strip()) or [],
                     "heartbeat_url": hb_map.get(name, ""),
                     "created_ts": int(time.time())})
        s = slug(name)
        cmd_path = os.path.join(out_dir, f"setup-{s}.cmd")
        with open(cmd_path, "w", encoding="utf-8", newline="\r\n") as fh:
            if ts_key:
                ts_block = (
                    'echo   Installing Tailscale and joining the private network ...\n'
                    f'".venv\\Scripts\\python.exe" netsentinel.py --install-tailscale '
                    f'--tailscale-key {ts_key} --tailscale-name {s}-pc\n'
                    'echo.\n')
            else:
                ts_block = ""
            hb_url = hb_map.get(name, "")
            hb_arg = (f'\n  --heartbeat-url {hb_url} ^' if hb_url else "")
            fh.write(SETUP_CMD.format(name=name, hub=hub_url.rstrip("/"), token=token,
                                      lan=lan_hint, ts_block=ts_block, hb_arg=hb_arg))
        chk_path = os.path.join(out_dir, f"CHECKLIST-{s}.txt")
        with open(chk_path, "w", encoding="utf-8", newline="\r\n") as fh:
            who = ", ".join(emails.get(name) or []) or "the head office alert list (set one)"
            hb_line = hb_map.get(name, "")
            hb_line = hb_line or ("none yet - run on the hub: run.bat --heartbeat-provision <healthchecks API key> "
                                  "then regenerate this file, or leave it to the hub's own check")
            fh.write(CHECKLIST.format(name=name, hub=hub_url.rstrip("/"), token=token,
                                      slug=s, who=who, hb_line=hb_line,
                                      when=time.strftime("%d/%m/%Y")))
        made.append({"name": name, "token": token, "cmd": cmd_path, "checklist": chk_path})
    hub["sites"] = rows
    settings.save({"hub": hub})
    summary = os.path.join(out_dir, "FLEET-SUMMARY.json")
    with open(summary, "w", encoding="utf-8") as fh:
        json.dump({"hub": hub_url, "issued": time.strftime("%Y-%m-%d %H:%M:%S"),
                   "sites": [{"name": m["name"], "token": m["token"]} for m in made]},
                  fh, indent=2)
    return made, summary
