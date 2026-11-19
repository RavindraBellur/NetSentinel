"""Optional agent: deep host metrics for the machines you actually care about.

Reachability tells you a server is answering. It does not tell you its CPU is pinned
at 100%, the C: drive has 400 MB left, or the "Spooler" service died - which is what
usually breaks the KOT printer. Run this on a server or a critical PC:

    run.bat --agent --console https://netsentinel.yourco.com:8777 --token nsk_...

It POSTs a small JSON report every 60 s to /api/v1/agent/report. The token needs the
`write` scope. Nothing is installed as a service, nothing listens on the host, and it
sends only the fields listed in `collect()` - no file names, no process command lines,
no user data.
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

REPORT_PATH = "/api/v1/agent/report"

try:
    import psutil  # type: ignore
except Exception:
    psutil = None


def _run(cmd, timeout=6):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, errors="ignore")
        return (p.stdout or "") + (p.stderr or "")
    except Exception:
        return ""


def _windows_services():
    """Service name + state, without psutil."""
    out = []
    for line in _run(["sc", "query", "type=", "service", "state=", "all"]).splitlines():
        line = line.strip()
        if line.startswith("SERVICE_NAME:"):
            out.append({"name": line.split(":", 1)[1].strip(), "state": ""})
        elif line.startswith("STATE") and out:
            parts = line.split()
            if len(parts) >= 4:
                out[-1]["state"] = parts[3]
    # only the ones that matter, to keep the payload small
    keep = ("spooler", "dnscache", "lanmanserver", "lanmanworkstation", "w32time",
            "eventlog", "termservice", "bits", "wuauserv", "sql", "mssql", "apache",
            "nginx", "w3svc", "dhcp", "dns", "netlogon")
    picked = [s for s in out if any(k in s["name"].lower() for k in keep)]
    return picked[:25]


def collect(extra_disks=True):
    """Everything the console receives from one host."""
    host = socket.gethostname()
    data = {
        "host": host,
        "ip": "",
        "os": platform.system() + " " + platform.release(),
        "version": platform.version()[:60],
        "ts": int(time.time()),
        "cpu_pct": None, "mem_pct": None, "mem_used_mb": None, "mem_total_mb": None,
        "disks": [], "services": [], "top": [], "uptime_hours": None,
    }
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.4)
        s.connect(("8.8.8.8", 53))
        data["ip"] = s.getsockname()[0]
        s.close()
    except Exception:
        pass

    if psutil:
        try:
            data["cpu_pct"] = round(psutil.cpu_percent(interval=0.6), 1)
            vm = psutil.virtual_memory()
            data["mem_pct"] = round(vm.percent, 1)
            data["mem_used_mb"] = round(vm.used / 1048576)
            data["mem_total_mb"] = round(vm.total / 1048576)
            data["uptime_hours"] = round((time.time() - psutil.boot_time()) / 3600, 1)
            if extra_disks:
                for part in psutil.disk_partitions(all=False):
                    try:
                        usage = psutil.disk_usage(part.mountpoint)
                    except Exception:
                        continue
                    data["disks"].append({
                        "mount": part.mountpoint[:24],
                        "used_pct": round(usage.percent, 1),
                        "free_gb": round(usage.free / 1073741824, 1),
                        "total_gb": round(usage.total / 1073741824, 1),
                    })
            procs = []
            for proc in psutil.process_iter(["name", "cpu_percent", "memory_percent"]):
                try:
                    info = proc.info
                    procs.append({"name": (info.get("name") or "?")[:40],
                                  "cpu": round(info.get("cpu_percent") or 0, 1),
                                  "mem": round(info.get("memory_percent") or 0, 1)})
                except Exception:
                    continue
            procs.sort(key=lambda p: (-(p["cpu"] or 0), -(p["mem"] or 0)))
            data["top"] = procs[:5]
            if hasattr(psutil, "win_service_iter") and os.name == "nt":
                try:
                    data["services"] = [{"name": s.name(), "state": s.status()}
                                        for s in psutil.win_service_iter()][:40]
                except Exception:
                    data["services"] = _windows_services()
        except Exception as exc:
            data["error"] = str(exc)[:120]
    else:
        # no psutil: still useful on Windows without extra packages
        if os.name == "nt":
            out = _run(["wmic", "cpu", "get", "loadpercentage", "/value"])
            for line in out.splitlines():
                if "=" in line and "LoadPercentage" in line:
                    try:
                        data["cpu_pct"] = float(line.split("=")[1].strip())
                    except Exception:
                        pass
            data["services"] = _windows_services()
        try:
            total, used, free = shutil.disk_usage(os.path.abspath(os.sep))
            data["disks"] = [{"mount": os.path.abspath(os.sep)[:24],
                              "used_pct": round(100.0 * used / total, 1),
                              "free_gb": round(free / 1073741824, 1),
                              "total_gb": round(total / 1073741824, 1)}]
        except Exception:
            pass
    return data


class Agent(threading.Thread):
    def __init__(self, console, token, interval=60, log=print, verify_tls=True):
        super().__init__(daemon=True, name="agent")
        self.console = (console or "").rstrip("/")
        self.token = token or ""
        self.interval = max(20, int(interval))
        self.log = log
        self._stop = threading.Event()
        self.sent = 0
        self.last_error = ""
        self.verify_tls = verify_tls

    def stop(self):
        self._stop.set()

    def push(self):
        if not self.console or not self.token:
            self.last_error = "agent needs --console and --token"
            return False
        payload = json.dumps(collect()).encode("utf-8")
        req = urllib.request.Request(
            self.console + REPORT_PATH, data=payload, method="POST",
            headers={"Content-Type": "application/json",
                     "Authorization": "Bearer " + self.token,
                     "User-Agent": "NetSentinel-agent/1.7"})
        try:
            ctx = None
            if self.console.startswith("https://"):
                import ssl
                ctx = ssl.create_default_context()
                if not self.verify_tls:
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
                ok = 200 <= resp.status < 300
        except urllib.error.HTTPError as exc:
            self.last_error = f"console refused the report: HTTP {exc.code}"
            return False
        except Exception as exc:
            self.last_error = f"{exc.__class__.__name__}: {exc}"[:160]
            return False
        if ok:
            self.sent += 1
            self.last_error = ""
        return ok

    def run(self):
        self._stop.wait(2)
        while not self._stop.is_set():
            try:
                self.push()
            except Exception as exc:
                self.last_error = str(exc)[:160]
            self._stop.wait(self.interval)
