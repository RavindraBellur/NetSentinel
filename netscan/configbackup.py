"""Configuration backup and change alerts for switches, routers and firewalls.

The most common way a network changes without anyone noticing is a config edit nobody wrote
down. This pulls each listed device's running configuration over SSH, keeps dated copies, and
compares every new copy with the previous one: a change raises an event and an alert, and the
exact lines that moved are kept so you can see who has to explain what.

Deliberately limited:

  * **Only the devices you list.** Settings -> Configuration backup holds lines like
    "192.168.1.2 cisco Core switch". Nothing is guessed, and only private LAN addresses are
    accepted.
  * **Key-based SSH only.** No password is stored or typed into a prompt (BatchMode=yes).
  * **Read-only commands from a fixed table.** There is no way to send any other command.
  * It uses the `ssh` client built into Windows 10/11, macOS and Linux - no extra library.

Sophos firewalls are not in the table: their SSH login opens a numbered menu, not a command
line, so there is no single read-only command to run. Use Sophos's own scheduled backup
(Backup & firmware -> Backup) for those.
"""

from __future__ import annotations

import difflib
import os
import re
import subprocess
import time

from . import settings, store

BACKUP_DIR = os.path.join(os.path.dirname(store.DB_PATH), "configs")

# device kind -> the one read-only command that prints its running configuration
COMMANDS = {
    "cisco": "show running-config",
    "aruba": "show running-config",
    "hp": "show running-config",
    "dlink": "show running-config",
    "tplink": "show running-config",
    "juniper": "show configuration | display set",
    "mikrotik": "/export terse",
    "ubiquiti": "cat /config/config.boot",
    "fortinet": "show full-configuration",
    "pfsense": "cat /conf/config.xml",
    "linux": "cat /etc/network/interfaces",
}

# lines that change on every read without anybody changing anything
NOISE = (
    re.compile(r"^\s*!\s*(Last configuration change|NVRAM config last updated|Time:)", re.I),
    re.compile(r"^\s*ntp clock-period", re.I),
    re.compile(r"^\s*#\s*\w{3}/\d{2}/\d{4} .* by RouterOS", re.I),      # MikroTik header
    re.compile(r"^\s*#\s*(\d{4}-\d{2}-\d{2}|\w{3} \w{3} +\d+) .*\d{2}:\d{2}:\d{2}"),
    re.compile(r"^\s*Current configuration\s*:\s*\d+ bytes", re.I),
    re.compile(r"^\s*Building configuration", re.I),
    re.compile(r"^\s*<revision>.*?<time>\d+</time>", re.I),
)


def parse_devices(raw):
    """Settings text or list -> [{ip, kind, name}]; rows that are not usable are reported."""
    from .safety import private_target
    rows = raw if isinstance(raw, list) else str(raw or "").replace(";", "\n").splitlines()
    devices, problems = [], []
    for row in rows:
        if isinstance(row, dict):
            ip, kind, name = (row.get("ip") or "").strip(), (row.get("kind") or "").strip(), \
                (row.get("name") or "").strip()
        else:
            parts = str(row).replace(",", " ").split()
            if not parts:
                continue
            ip = parts[0]
            kind = parts[1] if len(parts) > 1 else ""
            name = " ".join(parts[2:])
        kind = kind.lower()
        ok, why = private_target(ip)
        if not ok:
            problems.append(why)
            continue
        if kind not in COMMANDS:
            problems.append(f"{ip}: unknown kind '{kind}' - use one of {', '.join(COMMANDS)}")
            continue
        devices.append({"ip": ip, "kind": kind, "name": name or ip})
    return devices, problems


def normalise(text):
    """Drop the lines that change by themselves, and trailing spaces."""
    out = []
    for line in (text or "").replace("\r\n", "\n").split("\n"):
        if any(p.search(line) for p in NOISE):
            continue
        out.append(line.rstrip())
    while out and not out[-1]:
        out.pop()
    return "\n".join(out) + "\n"


def ssh_command(host, user, command, key, timeout=25):
    args = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new",
            "-o", f"ConnectTimeout={min(15, int(timeout))}", "-o", "LogLevel=ERROR",
            "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no"]
    if key:
        args += ["-i", os.path.expanduser(key)]
    args += [f"{user}@{host}", command]
    return args


def _ssh(host, user, command, key, timeout=25):
    """Run the one command. Returns (ok, output-or-reason)."""
    if not user:
        return False, "no SSH user set"
    try:
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        proc = subprocess.run(ssh_command(host, user, command, key, timeout),
                              capture_output=True, text=True, timeout=timeout,
                              stdin=subprocess.DEVNULL, creationflags=flags)
    except FileNotFoundError:
        return False, "no ssh client on this PC (Windows: Settings -> Optional features -> OpenSSH Client)"
    except subprocess.TimeoutExpired:
        return False, f"no answer within {timeout} s"
    except Exception as exc:
        return False, f"{exc.__class__.__name__}: {exc}"
    if proc.returncode != 0:
        return False, (proc.stderr or proc.stdout or "ssh failed").strip().splitlines()[-1][:200]
    return True, proc.stdout


def _dir_for(host):
    safe = "".join(c if c.isalnum() or c in ".-" else "_" for c in str(host))
    path = os.path.join(BACKUP_DIR, safe)
    os.makedirs(path, exist_ok=True)
    return path


def versions(host):
    """Stored copies for one device, newest first."""
    try:
        d = _dir_for(host)
        names = sorted((n for n in os.listdir(d) if n.endswith(".conf")), reverse=True)
    except OSError:
        return []
    return [os.path.join(d, n) for n in names]


def _read(path):
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def save_and_compare(host, output, keep=30, now=None):
    """Store a copy if it differs from the last one. Returns (changed, first_run, diff, path)."""
    now = now or time.time()
    current = normalise(output)
    previous_paths = versions(host)
    previous = _read(previous_paths[0]) if previous_paths else ""
    if previous and normalise(previous) == current:
        return False, False, "", previous_paths[0]
    stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime(now))
    path = os.path.join(_dir_for(host), f"{stamp}.conf")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(output)
    for old in versions(host)[max(1, int(keep)):]:
        try:
            os.remove(old)
        except OSError:
            pass
    if not previous:
        return False, True, "", path
    diff = "\n".join(difflib.unified_diff(
        normalise(previous).splitlines(), current.splitlines(),
        fromfile="previous", tofile="now", lineterm="", n=1))
    return True, False, diff[:6000], path


def fetch(device, conf):
    host, kind = device["ip"], device["kind"]
    ok, output = _ssh(host, (conf.get("user") or "").strip(), COMMANDS[kind],
                      (conf.get("key") or "").strip(), int(conf.get("timeout") or 30))
    base = {"host": host, "name": device.get("name") or host, "kind": kind,
            "ts": int(time.time())}
    if not ok:
        return dict(base, ok=False, reason=output)
    if len(output.strip()) < 20:
        return dict(base, ok=False, reason="the device returned almost nothing")
    changed, first, diff, path = save_and_compare(host, output, conf.get("keep") or 30)
    if changed:
        added = sum(1 for x in diff.splitlines() if x.startswith("+") and not x.startswith("+++"))
        removed = sum(1 for x in diff.splitlines() if x.startswith("-") and not x.startswith("---"))
        store.add_event("config", "high",
                        f"{base['name']} ({host}): configuration changed - "
                        f"{added} line(s) added, {removed} removed")
    return dict(base, ok=True, changed=changed, first_run=first, diff=diff,
                bytes=len(output), file=os.path.basename(path))


def run(cfg=None, log=None):
    cfg = cfg or settings.load()
    conf = cfg.get("config_backup") or {}
    if not conf.get("enabled"):
        return []
    devices, problems = parse_devices(conf.get("devices") or [])
    out = [{"host": p.split(":")[0], "ok": False, "reason": p, "ts": int(time.time())}
           for p in problems]
    for device in devices:
        result = fetch(device, conf)
        out.append(result)
        if log:
            if result.get("ok"):
                state = ("first copy saved" if result.get("first_run")
                         else "CHANGED" if result.get("changed") else "unchanged")
                log(f"config backup {result['name']}: {state}")
            else:
                log(f"config backup {result['name']}: {result.get('reason')}")
    return out


def notify_change(cfg, result, log=None):
    """Email / phone alert for a changed configuration."""
    from . import alerts, push
    site = (cfg.get("site_name") or "").strip()
    title = f"[Prahari] Configuration changed: {result.get('name')} ({result.get('host')})"
    if site:
        title += f" - {site}"
    body = (f"The running configuration of {result.get('name')} ({result.get('host')}, "
            f"{result.get('kind')}) is different from the last copy.\n\n"
            f"If nobody planned this change, find out who made it.\n\n"
            f"What changed (- old line, + new line):\n\n{result.get('diff') or '(see Prahari)'}")
    if alerts._email_ready(cfg):
        ok, msg = alerts.send_email(cfg, title, body)
        if log:
            log(f"config change email {'sent' if ok else 'failed'}: {msg}")
    try:
        ok, why = push.ready(cfg)
        if ok:
            push.send(cfg, title, body[:900], "high")
    except Exception:
        pass


def listing():
    out = []
    try:
        hosts = sorted(os.listdir(BACKUP_DIR))
    except OSError:
        return out
    for host in hosts:
        files = versions(host)
        if files:
            out.append({"host": host, "copies": len(files),
                        "latest": os.path.basename(files[0]),
                        "when": int(os.path.getmtime(files[0]))})
    return out


def diff_latest(host):
    """The last stored change for a device, for the dashboard."""
    files = versions(host)
    if len(files) < 2:
        return ""
    return "\n".join(difflib.unified_diff(
        normalise(_read(files[1])).splitlines(), normalise(_read(files[0])).splitlines(),
        fromfile=os.path.basename(files[1]), tofile=os.path.basename(files[0]),
        lineterm="", n=1))[:20000]


def status(results=None, cfg=None):
    cfg = cfg if cfg is not None else settings.load()
    conf = cfg.get("config_backup") or {}
    devices, problems = parse_devices(conf.get("devices") or [])
    return {"enabled": bool(conf.get("enabled")), "user": conf.get("user") or "",
            "key_set": bool(conf.get("key")), "devices": devices, "problems": problems,
            "every_hours": conf.get("every_hours") or 24,
            "results": [{k: v for k, v in r.items() if k != "diff"} for r in (results or [])],
            "stored": listing(), "kinds": list(COMMANDS)}
