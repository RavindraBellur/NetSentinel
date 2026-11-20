"""Zero-cost remote access: find this PC on a Tailscale tailnet.

Tailscale is free for a small number of users and devices, works through CGNAT and needs
no port-forward, no public IP and no domain. If it is installed, Prahari can print the
address to open from anywhere, and the fleet generator can use it as the hub address
instead of you hunting for an IP.

Everything here is optional: if Tailscale is not installed, nothing changes.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time

TIMEOUT = 6
IS_WINDOWS = os.name == "nt"
MSI_URL = "https://pkgs.tailscale.com/stable/tailscale-setup-latest-amd64.msi"
EXE_CANDIDATES = (r"C:\Program Files\Tailscale\tailscale.exe",
                  r"C:\Program Files (x86)\Tailscale\tailscale.exe")


def _run(args, timeout=TIMEOUT):
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                              errors="ignore")
        return proc.returncode, ((proc.stdout or "") + (proc.stderr or "")).strip()
    except Exception as exc:
        return 1, str(exc)


def exe_path():
    found = shutil.which("tailscale") or shutil.which("tailscale.exe")
    if found:
        return found
    for candidate in EXE_CANDIDATES:
        if os.path.exists(candidate):
            return candidate
    return ""


def _download(url, target, log=print):
    """curl first (Windows 10+), PowerShell as the fallback."""
    if shutil.which("curl"):
        code, _out = _run(["curl", "-L", "--fail", "--silent", "--show-error",
                           "-o", target, url], timeout=600)
        if code == 0 and os.path.exists(target) and os.path.getsize(target) > 100000:
            return True
    if shutil.which("powershell"):
        script = (f"try {{ Invoke-WebRequest -Uri '{url}' -OutFile '{target}' "
                  f"-UseBasicParsing; exit 0 }} catch {{ exit 1 }}")
        code, _out = _run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                           "-Command", script], timeout=600)
        if code == 0 and os.path.exists(target) and os.path.getsize(target) > 100000:
            return True
    return False


def install(log=print):
    """Download and install Tailscale silently. Needs Administrator on Windows."""
    if not IS_WINDOWS:
        return False, "automatic install is implemented for Windows only"
    if exe_path():
        return True, "Tailscale is already installed"
    target = os.path.join(tempfile.gettempdir(), "tailscale-setup-amd64.msi")
    log("  downloading Tailscale ...")
    if not _download(MSI_URL, target, log):
        return False, "could not download the Tailscale installer"
    log("  installing Tailscale silently ...")
    code, out = _run(["msiexec", "/i", target, "/quiet", "/norestart"], timeout=900)
    try:
        os.remove(target)
    except OSError:
        pass
    for _ in range(30):
        if exe_path():
            return True, "Tailscale installed"
        time.sleep(1)
    return False, f"msiexec returned {code}: {out[-200:]}"


def join(authkey, hostname="", log=print, routes=""):
    """Join the tailnet with an auth key - no browser, no clicking. routes: this office's subnet
    (e.g. 192.168.0.0/24) to share, so its devices can be opened from anywhere on the tailnet."""
    exe = exe_path()
    if not exe:
        return False, "Tailscale is not installed"
    if not authkey:
        return False, "an auth key is required (Tailscale admin console > Settings > Keys)"
    args = [exe, "up", f"--authkey={authkey}", "--accept-routes=false",
            "--accept-dns=true"]
    if hostname:
        args.append(f"--hostname={hostname}")
    if routes:
        args.append(f"--advertise-routes={routes}")
    log(f"  joining the tailnet as '{hostname or 'this-pc'}' ...")
    code, out = _run(args, timeout=120)
    if code != 0:
        return False, f"tailscale up failed: {out[-300:]}"
    info = detect()
    if info.get("running"):
        url = best_url()
        return True, (f"joined the tailnet{f' - {url}' if url else ''}")
    return False, "tailscale up ran but the connection is not up yet"


def detect():
    """{'installed', 'running', 'dns_name', 'ipv4', 'self_online'} - never raises."""
    info = {"installed": False, "running": False, "dns_name": "", "ipv4": [], "self_online": False}
    exe = shutil.which("tailscale") or shutil.which("tailscale.exe")
    if not exe:
        for candidate in (r"C:\Program Files\Tailscale\tailscale.exe",
                          r"C:\Program Files (x86)\Tailscale\tailscale.exe"):
            if os.path.exists(candidate):
                exe = candidate
                break
    if not exe:
        return info
    info["installed"] = True
    code, out = _run([exe, "status", "--json"])
    if code != 0 or not out:
        return info
    try:
        data = json.loads(out)
    except ValueError:
        return info
    info["running"] = data.get("BackendState") == "Running"
    self_node = data.get("Self") or {}
    info["dns_name"] = (self_node.get("DNSName") or "").rstrip(".")
    info["self_online"] = bool(self_node.get("Online"))
    for addr in self_node.get("TailscaleIPs") or []:
        if ":" not in addr:
            info["ipv4"].append(addr)
    return info


_STATE = {"at": 0.0, "info": None}


def cached_detect(max_age=300):
    """detect() at most every 5 minutes - it is called with every portal report."""
    if _STATE["info"] is None or time.time() - _STATE["at"] > max_age:
        _STATE["info"], _STATE["at"] = detect(), time.time()
    return _STATE["info"]


def setup_for_portal(authkey, hostname, routes, log=print):
    """Install Tailscale if needed and join with the organisation's key, sharing this office's subnet.
    Runs in the background copy of Prahari (SYSTEM), so the installer needs no prompt."""
    if not IS_WINDOWS:
        return False, "automatic Tailscale setup is for Windows"
    if not exe_path():
        ok, msg = install(log=log)
        if not ok:
            return False, msg
    ok, msg = join(authkey, hostname=hostname, log=log, routes=routes)
    _STATE["info"] = None
    return ok, msg


def best_url(port=8777, prefer="dns"):
    """The address another device on the tailnet should use, or ''."""
    info = detect()
    if not info["running"]:
        return ""
    if prefer == "dns" and info["dns_name"]:
        return f"https://{info['dns_name']}:{port}"
    if info["ipv4"]:
        return f"http://{info['ipv4'][0]}:{port}"
    if info["dns_name"]:
        return f"https://{info['dns_name']}:{port}"
    return ""


def summary():
    """One line for the console banner."""
    info = detect()
    if not info["installed"]:
        return ""
    if not info["running"]:
        return "Tailscale is installed but not connected (run: tailscale up)"
    url = best_url()
    if url:
        return f"Tailscale: {url}  (free remote access, no port-forward)"
    return "Tailscale: connected, no address found"
