"""Public (WAN) IP tracking, ISP lookup and dual-WAN detection.

A firewall with two internet lines load-balances connections, so different services
can see different public addresses. Asking several of them at once therefore shows
*both* lines - which is how a silent failover gets noticed: the moment the public IP
or ISP changes, the main line has probably failed and the backup took over.

Nothing is sent anywhere except to the IP-echo services themselves.
"""

from __future__ import annotations

import json
import re
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from . import alerts, settings, store

IP_RX = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
TRACE_RX = re.compile(r"^ip=(\S+)$", re.M)

SOURCES = (
    ("ipinfo.io", "https://ipinfo.io/json", "json"),
    ("ipify", "https://api.ipify.org?format=json", "json"),
    ("icanhazip", "https://icanhazip.com", "text"),
    ("aws-checkip", "https://checkip.amazonaws.com", "text"),
    ("cloudflare", "https://1.1.1.1/cdn-cgi/trace", "trace"),
)


def _fetch(url, kind, timeout=6):
    req = urllib.request.Request(url, headers={"User-Agent": "NetSentinel/1.4",
                                              "Accept": "application/json,text/plain,*/*"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read(65536).decode("utf-8", "replace")
    if kind == "json":
        data = json.loads(raw)
        ip = data.get("ip") or data.get("ip_addr") or ""
        return ip, {
            "isp": re.sub(r"^AS\d+\s+", "", (data.get("org") or "")).strip(),
            "city": data.get("city") or "",
            "country": data.get("country") or "",
        }
    if kind == "trace":
        m = TRACE_RX.search(raw)
        return (m.group(1) if m else ""), {}
    return raw.strip(), {}


def probe(timeout=6):
    """Return {"ips": [..], "isp": "", "city": "", "sources": {name: ip}}."""
    found = {}
    info = {}
    with ThreadPoolExecutor(max_workers=len(SOURCES)) as pool:
        futures = {pool.submit(_fetch, url, kind, timeout): name for name, url, kind in SOURCES}
        for future, name in futures.items():
            try:
                ip, extra = future.result()
            except Exception:
                continue
            if ip and IP_RX.match(ip):
                found[name] = ip
                if extra and extra.get("isp") and not info:
                    info = extra
    ips = []
    for ip in found.values():
        if ip not in ips:
            ips.append(ip)
    if not info and ips:
        info = _isp_for(ips[0], timeout)
    return {"ips": ips, "isp": info.get("isp", ""), "city": info.get("city", ""),
            "country": info.get("country", ""), "sources": found,
            "dual": len(ips) > 1, "ts": int(time.time())}


def _isp_for(ip, timeout=6):
    try:
        with urllib.request.urlopen(
            urllib.request.Request(f"https://ipinfo.io/{ip}/json",
                                   headers={"User-Agent": "NetSentinel/1.4"}),
            timeout=timeout,
        ) as resp:
            data = json.loads(resp.read(65536).decode("utf-8", "replace"))
        return {"isp": re.sub(r"^AS\d+\s+", "", (data.get("org") or "")).strip(),
                "city": data.get("city") or "", "country": data.get("country") or ""}
    except Exception:
        return {}


def _notify(cfg, title, body, severity="high"):
    """Send a line-change alert through whatever channel is configured."""
    results = {}
    try:
        ok, msg = alerts.send_email(cfg, f"[NetSentinel] {title}", body)
        if (cfg.get("email") or {}).get("enabled"):
            results["email"] = msg
    except Exception as exc:
        results["email"] = str(exc)[:120]
    try:
        if (cfg.get("webhook") or {}).get("enabled"):
            ok, msg = alerts.send_webhook(cfg, {"text": f"{title}\n{body}",
                                                "severity": severity, "kind": "wan"})
            results["webhook"] = msg
    except Exception as exc:
        results["webhook"] = str(exc)[:120]
    return results


class WanWatcher(threading.Thread):
    """Checks the public IP from several services and reports changes."""

    def __init__(self, scanner, log=None):
        super().__init__(daemon=True, name="wan-watcher")
        self.scanner = scanner
        self.log = log or (lambda m: None)
        self._stop = threading.Event()
        self.state = {"ips": [], "isp": "", "city": "", "country": "", "dual": False,
                      "sources": {}, "ts": 0, "changes": [], "error": ""}

    def stop(self):
        self._stop.set()

    def snapshot(self):
        with self.scanner.lock:
            return dict(self.state, changes=list(self.state.get("changes", []))[-20:])

    def check(self):
        cfg = settings.load()
        previous = list(self.state.get("ips") or [])
        result = probe()
        if not result["ips"]:
            self.state["error"] = "could not reach any IP-echo service"
            return self.state
        self.state.update(result, error="")
        if previous and set(previous) != set(result["ips"]):
            change = {
                "ts": int(time.time()),
                "from": previous,
                "to": result["ips"],
                "isp": result["isp"],
                "text": f"Public IP changed from {', '.join(previous)} to {', '.join(result['ips'])}"
                        + (f" ({result['isp']})" if result["isp"] else ""),
            }
            self.state["changes"].append(change)
            store.add_event("wan", "high", change["text"])
            self.log(change["text"])
            body = (f"The internet address of this site changed.\n\n"
                    f"Before : {', '.join(previous)}\n"
                    f"Now    : {', '.join(result['ips'])}\n"
                    f"ISP    : {result['isp'] or 'unknown'}\n"
                    f"City   : {result['city'] or 'unknown'}\n\n"
                    "This usually means the main line failed and a backup took over, or the ISP "
                    "re-assigned the address. If you publish services on this address, check DNS.")
            if result["dual"]:
                body += ("\n\nTwo public addresses are in use at the same time, so the firewall is "
                         "load-balancing two internet lines.")
            _notify(cfg, "Public IP changed", body)
        if result["dual"] and not self.state.get("dual_reported"):
            self.state["dual_reported"] = True
            store.add_event("wan", "medium",
                            f"Two public IPs in use: {', '.join(result['ips'])} "
                            f"({result['isp'] or 'unknown ISP'}) - dual-WAN load balancing")
        return self.state

    def run(self):
        self._stop.wait(3)
        while not self._stop.is_set():
            try:
                self.check()
            except Exception as exc:
                self.state["error"] = str(exc)[:160]
            interval = int((settings.get("wan") or {}).get("interval_seconds") or 600)
            self._stop.wait(max(120, interval))
