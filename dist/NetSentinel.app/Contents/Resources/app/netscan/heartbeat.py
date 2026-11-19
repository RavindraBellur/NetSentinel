"""Dead-man's switch: prove to an outside service that this site is alive.

A console inside the hotel cannot tell you the hotel's internet died - it has no path
out. So every few minutes NetSentinel pings a URL on the internet (healthchecks.io,
UptimeRobot push, your own endpoint). When the pings stop, that service emails you.

    heartbeat.url = https://hc-ping.com/<uuid>          (one UUID per site)

The hub watches its branches, so a branch only needs this if it should also survive the
hub being down; the hub itself should always have one.
"""

from __future__ import annotations

import socket
import threading
import time
import urllib.parse
import urllib.request

from . import settings, store


HC_API = "https://healthchecks.io/api/v3"


def provision(api_key, names, timeout=900, grace=300, base=HC_API):
    """Create one check per site at healthchecks.io. Returns {site: ping_url}.

    Free accounts allow 20 checks; the hub-only model needs just one, so this is for the
    sites you care most about (or a paid account).
    """
    import json as _json
    made = {}
    for name in names:
        body = _json.dumps({"name": name, "tags": "netsentinel", "timeout": timeout,
                            "grace": grace, "channels": "*"}).encode()
        req = urllib.request.Request(base + "/checks/", data=body, method="POST",
                                     headers={"X-Api-Key": api_key,
                                              "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = _json.loads(resp.read().decode())
            url = data.get("ping_url") or ""
            if url:
                made[name] = url
        except urllib.error.HTTPError as exc:
            detail = exc.read(200).decode("utf-8", "replace")
            raise RuntimeError(f"healthchecks.io refused {name}: HTTP {exc.code} {detail[:160]}")
        except Exception as exc:
            raise RuntimeError(f"could not reach healthchecks.io: {exc}")
    return made


class Heartbeat(threading.Thread):
    def __init__(self, log=None):
        super().__init__(daemon=True, name="heartbeat")
        self.log = log or (lambda m: None)
        self._stop = threading.Event()
        hb = settings.get("heartbeat") or {}
        self.state = {"enabled": bool(hb.get("enabled")), "sent": 0, "failures": 0,
                      "last_ok": 0, "last_error": "", "url": (hb.get("url") or "").split("?")[0],
                      "interval": int(hb.get("interval_seconds") or 300)}

    def stop(self):
        self._stop.set()

    def _url(self, cfg):
        hb = cfg.get("heartbeat") or {}
        url = (hb.get("url") or "").strip()
        if not url:
            return ""
        site = (cfg.get("site_name") or socket.gethostname()).strip()
        sep = "&" if "?" in url else "?"
        return url + sep + urllib.parse.urlencode({"site": site})

    def ping(self):
        cfg = settings.load()
        hb = cfg.get("heartbeat") or {}
        if not hb.get("enabled"):
            self.state["enabled"] = False
            return False
        url = self._url(cfg)
        if not url:
            self.state.update(enabled=True, last_error="no heartbeat URL configured")
            return False
        self.state.update(enabled=True, url=url.split("?")[0])
        req = urllib.request.Request(url, headers={"User-Agent": "NetSentinel-heartbeat/1.9"})
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                ok = 200 <= resp.status < 400
        except Exception as exc:
            self.state["failures"] += 1
            self.state["last_error"] = f"{exc.__class__.__name__}: {exc}"[:140]
            if self.state["failures"] in (3, 12, 60):
                store.add_event("heartbeat", "high",
                                f"heartbeat to {self.state['url']} failing "
                                f"({self.state['failures']} in a row): {self.state['last_error']}")
            return False
        if ok:
            self.state["sent"] += 1
            self.state["failures"] = 0
            self.state["last_ok"] = int(time.time())
            self.state["last_error"] = ""
        return ok

    def run(self):
        self._stop.wait(2)
        while not self._stop.is_set():
            try:
                self.ping()
            except Exception as exc:
                self.state["last_error"] = str(exc)[:140]
            interval = int((settings.get("heartbeat") or {}).get("interval_seconds") or 300)
            self._stop.wait(max(60, interval))
