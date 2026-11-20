"""Multi-site: branches report to a head-office hub.

Every branch runs Prahari with `--branch http://hub:8777 --token <token>`.
Every 30 s it POSTs a compact summary (health, devices, open incidents, internet
line, top talkers) to the hub, authenticated by a per-site token that the hub
stores as a SHA-256 hash. The hub shows an "All locations" view, and raises an
alert when a branch stops reporting for longer than it should.

The hub never needs to reach the branch: reporting is outbound only, so it works
across a VPN, a port-forward, or a public hub with HTTPS in front of it.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import threading
import time
import urllib.error
import urllib.request

from . import alerts, diagnose, settings, store

REPORT_PATH = "/api/branch/report"
LIST_EVERY = 300          # seconds: send the full device list at least this often (and whenever it changes)

# A Prahari portal key needs no hub address: the portal is the hub. pok_ = the organisation key (one for every
# site; the portal tells sites apart by their site name), psk_ = a token made for one site.
PORTAL_URL = "https://prahari.essensai.workers.dev"


def connect_portal(token, site_name=""):
    """Save a Prahari portal token (and optionally this site's name). Returns (ok, message)."""
    token = (token or "").strip().strip('"').strip("'")
    if not re.fullmatch(r"(psk|pok)_[A-Za-z0-9_-]{16,80}", token):
        return False, "That is not a Prahari portal key - it starts with pok_ (copy it from the portal, next to Download)."
    name = (site_name or "").strip()[:64]
    if token.startswith("pok_") and not (name or settings.get("site_name")):
        return False, "Give this site a name (e.g. Corporate Office) - the portal lists it under that name."
    patch = {"branch": {"token": token, "hub_url": ""}, "portal": {"asked": True}}
    if name:
        patch["site_name"] = name
    settings.save(patch)
    return True, "saved"


def branch_target():
    """(hub_url, token) this site reports to, or ("", "") when it is not set up."""
    branch = settings.get("branch") or {}
    token = (branch.get("token") or "").strip()
    url = (branch.get("hub_url") or "").strip().rstrip("/")
    if not url and token.startswith(("psk_", "pok_")):
        url = PORTAL_URL
    return (url, token) if url and token else ("", "")


def token_hash(token):
    return hashlib.sha256((token or "").encode("utf-8")).hexdigest()


def new_token():
    return "ns_" + secrets.token_urlsafe(24)


def site_for_token(cfg, token):
    """Resolve a branch token to its site name (tokens are stored hashed).

    Re-reads config.json so a token added a moment ago works immediately.
    """
    if not token:
        return ""
    try:
        cfg = settings.reload()
    except Exception:
        pass
    want = token_hash(token)
    for site in (cfg.get("hub") or {}).get("sites") or []:
        if site.get("token_hash") and secrets.compare_digest(site["token_hash"], want):
            return site.get("name") or "branch"
        if site.get("token") and secrets.compare_digest(site["token"], token):
            return site.get("name") or "branch"
    return ""


def summary(scanner):
    """The compact state a branch sends to the hub."""
    snap = scanner.snapshot()
    health = snap.get("health") or {}
    incidents = [i for i in (snap.get("open_incidents") or [])][:50]
    traffic = snap.get("traffic") or {}
    wan = snap.get("wan") or {}
    local = snap.get("local") or {}
    public = snap.get("public") or {}
    payload = {
        "site": settings.get("site_name") or local.get("ip") or "branch",
        "version": snap.get("version") or __import__("netscan").__version__,
        "ts": int(time.time()),
        "health": health,
        "counts": snap.get("counts") or {},
        "gateway": (snap.get("gateway") or {}).get("state", "unknown"),
        "internet": [{"name": t.get("name"), "state": t.get("state"),
                      "latency": t.get("latency"), "loss": t.get("loss")}
                     for t in (snap.get("internet") or [])],
        "wan": {"lines": _fresh_lines(scanner),
                "ips": wan.get("ips") or ([public["ip"]] if public.get("ip") else []),
                "isp": wan.get("isp") or public.get("isp", ""),
                "dual": bool(wan.get("dual"))},
        "traffic": {"down_bps": traffic.get("total_down_bps", 0),
                    "up_bps": traffic.get("total_up_bps", 0),
                    "top": [{"name": t.get("name"), "ip": t.get("ip"),
                             "down_bps": t.get("down_bps"), "up_bps": t.get("up_bps")}
                            for t in (traffic.get("top") or [])[:10]]},
        "incidents": [{"id": i.get("id"), "title": i.get("title"), "severity": i.get("severity"),
                       "state": i.get("state"), "device_name": i.get("device_name"),
                       "device_ip": i.get("device_ip"), "opened_ts": i.get("opened_ts"),
                       "category": ((i.get("diagnosis") or {}).get("category") or "")}
                      for i in incidents],
        "install_id": install_id(),
        "tailnet": _tailnet_state(snap),
        "network_id": network_id(snap),
        "devices": len(snap.get("devices") or []),
        # every device, compact, so the Prahari portal can show this site's full device list
        "device_list": [_compact_device(d) for d in (snap.get("devices") or [])[:600]],
        "monitored": health.get("monitored", 0),
    }
    try:
        from . import sla as sla_mod
        payload["sla"] = sla_mod.rolling_summary(31)
    except Exception:
        payload["sla"] = {}
    return payload


def _fresh_lines(scanner):
    """Internet lines read from the firewall over SNMP in the last 15 minutes (see monitor.SnmpPoller)."""
    if time.time() - (getattr(scanner, "wan_lines_at", 0) or 0) > 900:
        return []
    return [{"ip": x["ip"], "interface": x["interface"], "up": bool(x["up"])} for x in (getattr(scanner, "wan_lines", None) or [])][:6]


def _tailnet_state(snap):
    """Remote access via Tailscale: installed / connected / which subnet this office shares."""
    try:
        from . import tailnet
        info = tailnet.cached_detect()
    except Exception:
        info = {}
    return {"installed": bool(info.get("installed")), "running": bool(info.get("running")),
            "name": info.get("dns_name") or "", "ip": (info.get("ipv4") or [""])[0],
            "subnet": (snap.get("local") or {}).get("network") or ""}


_ts_try = {"at": 0.0}


def maybe_setup_tailscale(reply, scanner, log=print):
    """The portal hands over the organisation's Tailscale key while this site is not connected yet."""
    key = ((reply or {}).get("tailscale") or {}).get("key") or ""
    if not key or time.time() - _ts_try["at"] < 3600:
        return
    _ts_try["at"] = time.time()
    from . import tailnet
    if tailnet.cached_detect(0).get("running"):
        return
    snap_local = getattr(scanner, "local", {}) or {}
    name = re.sub(r"[^a-z0-9-]+", "-", ("prahari-" + (settings.get("site_name") or "site")).lower()).strip("-")[:60]

    def work():
        ok, msg = tailnet.setup_for_portal(key, name, snap_local.get("network") or "", log=log)
        log(("Tailscale: " if ok else "Tailscale setup failed: ") + msg)
    threading.Thread(target=work, daemon=True, name="tailscale-setup").start()


def install_id():
    """A random id for this installation, so the portal can tell two Praharis using the same name apart."""
    iid = settings.get("install_id")
    if not iid:
        iid = secrets.token_hex(8)
        settings.save({"install_id": iid})
    return iid


def network_id(snap):
    """A fingerprint of the network this Prahari watches, so the portal allows only one Prahari per network.
    The router's MAC identifies a network exactly; until it is known, use the subnet, router IP and public IP
    together (the subnet alone would match every 192.168.0.x network). Empty when nothing is known yet."""
    devices = snap.get("devices") or []
    gw = [d for d in devices if d.get("is_gateway") and d.get("mac")]
    if gw:
        return "mac:" + hashlib.sha256(gw[0]["mac"].lower().encode()).hexdigest()[:20]
    local = snap.get("local") or {}
    public = (snap.get("public") or {}).get("ip") or ""
    if local.get("network") and local.get("gateway") and public:
        raw = f'{local["network"]}|{local["gateway"]}|{public}'
        return "net:" + hashlib.sha256(raw.encode()).hexdigest()[:20]
    return ""


def _compact_device(d):
    ports = []
    for p in (d.get("ports") or [])[:24]:
        if isinstance(p, dict):
            p = p.get("port")
        if isinstance(p, int):
            ports.append(p)
    num = lambda v: round(v, 1) if isinstance(v, (int, float)) else None
    return {"ip": d.get("ip") or "", "mac": d.get("mac") or "",
            "name": (d.get("label") or d.get("hostname") or "")[:80], "vendor": (d.get("vendor") or "")[:60],
            "type": (d.get("type_label") or d.get("type") or "")[:40], "state": d.get("state") or "",
            "lat": num(d.get("latency_ms")), "loss": num(d.get("loss_pct")), "ports": ports,
            "gw": bool(d.get("is_gateway"))}


class BranchReporter(threading.Thread):
    """Runs on a branch: pushes the summary to the hub."""

    def __init__(self, scanner, log=None):
        super().__init__(daemon=True, name="branch-reporter")
        self.scanner = scanner
        self.log = log or (lambda m: None)
        self._stop = threading.Event()
        self.last_ok = 0.0
        self.last_error = ""
        self.sent = 0
        self._list_sig = None      # device list last sent: its fingerprint and when
        self._list_at = 0.0

    def stop(self):
        self._stop.set()

    def config(self):
        branch = settings.get("branch") or {}
        url, token = branch_target()
        interval = int(branch.get("interval_seconds") or 30)
        return url, token, max(10, interval)

    def push(self):
        url, token, _interval = self.config()
        if not url or not token:
            self.last_error = "branch mode needs a hub URL and a token"
            return False
        rep = summary(self.scanner)
        # The full device list is large: send it when a device appears, disappears or changes state,
        # and at least every 5 minutes. Other reports carry only the totals (the portal keeps the last list).
        devs = rep.get("device_list") or []
        sig = hashlib.sha256(json.dumps([(d["ip"], d["state"], d["name"]) for d in devs]).encode()).hexdigest()
        full = sig != self._list_sig or time.time() - self._list_at >= LIST_EVERY
        if not full:
            rep.pop("device_list", None)
        payload = json.dumps(rep).encode("utf-8")
        req = urllib.request.Request(
            url + REPORT_PATH, data=payload, method="POST",
            headers={"Content-Type": "application/json", "X-NS": "1",
                     "X-Branch-Token": token, "User-Agent": "Prahari-branch/1.5"},
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                ok = 200 <= resp.status < 300
                body = resp.read(4000).decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            portal = url == PORTAL_URL
            if exc.code == 409:
                try:
                    reply = json.loads(exc.read(4000).decode("utf-8", "replace") or "{}")
                except Exception:
                    reply = {}
                if reply.get("standby"):
                    msg = reply.get("error") or "Another Prahari already watches this network."
                    if not getattr(self.scanner, "standby", ""):
                        print("\n  STANDBY: " + msg + "\n")
                        self.log("standby: " + msg)
                    self.scanner.standby = msg
                    self.last_error = msg
                    return False
            if portal and exc.code == 401:
                self.last_error = "the Prahari portal did not accept the organisation key - copy it again from the portal"
            elif portal and exc.code == 403:
                self.last_error = "the Prahari portal refused this location (limit reached?)"
            else:
                self.last_error = f"{'the Prahari portal' if portal else 'the hub'} refused the report: HTTP {exc.code}"
            return False
        except Exception as exc:
            self.last_error = f"{exc.__class__.__name__}: {exc}"[:160]
            return False
        if ok and full:
            self._list_sig, self._list_at = sig, time.time()
        if ok:
            if getattr(self.scanner, "standby", ""):
                print("\n  This Prahari is now the one watching this network - monitoring resumed.\n")
                self.log("standby ended: this copy now watches the network")
            self.scanner.standby = ""
            self.last_ok = time.time()
            self.sent += 1
            self.last_error = ""
            try:
                import json as _json
                from . import upgrade as upgrade_mod
                reply = _json.loads(body or "{}")
                maybe_setup_tailscale(reply, self.scanner, log=self.log)
                upgrade_mod.pending_update(reply, url, log=self.log, token=token)
            except Exception as exc:
                self.last_error = f"update check failed: {exc}"[:140]
        else:
            self.last_error = body[:160]
        return ok

    def run(self):
        self._stop.wait(8)
        while not self._stop.is_set():
            try:
                self.push()
            except Exception as exc:
                self.last_error = str(exc)[:160]
            _url, _token, interval = self.config()
            self._stop.wait(interval)

    def status(self):
        return {"sent": self.sent, "last_ok": self.last_ok, "error": self.last_error,
                "standby": getattr(self.scanner, "standby", ""),
                "age": (time.time() - self.last_ok) if self.last_ok else None}


class LostContactWatcher(threading.Thread):
    """Runs on the hub: alerts when a branch stops reporting."""

    def __init__(self, scanner, log=None):
        super().__init__(daemon=True, name="lost-contact")
        self.scanner = scanner
        self.log = log or (lambda m: None)
        self._stop = threading.Event()
        self.state = {}   # site -> "up" | "lost"

    def stop(self):
        self._stop.set()

    def check(self):
        cfg = settings.load()
        expect = int((cfg.get("hub") or {}).get("expect_minutes") or 5) * 60
        now = time.time()
        lost_now, back_now = [], []
        for branch in store.branches():
            site = branch["name"]
            age = now - (branch.get("last_ts") or 0)
            previous = self.state.get(site, "up")
            if age > expect and previous != "lost":
                self.state[site] = "lost"
                minutes = int(age // 60)
                store.add_event("hub", "high",
                                f"Lost contact with {site} - no report for {minutes} min")
                self.log(f"lost contact with {site}")
                lost_now.append(site)
                # one mail per site, unless several go at once (see the digest below)
                if len(lost_now) <= 3:
                    _alert(cfg, f"Lost contact with {site}",
                           f"The {site} branch has not reported for {minutes} minutes.\n\n"
                           "Usually this means its internet link is down, the PC is off, or the "
                           "VPN to head office dropped. The dashboard will show it back when it "
                           "reports again.", site=site)
            elif age <= expect and previous == "lost":
                self.state[site] = "up"
                store.add_event("hub", "info", f"{site} is reporting again")
                back_now.append(site)
                _alert(cfg, f"{site} is back", f"The {site} branch is reporting again.",
                       site=site, severity="info")

        # a wave of sites going quiet is one problem, not twenty - send one digest
        if len(lost_now) > 3:
            listing = "\n".join("  - " + s for s in sorted(lost_now))
            _alert(cfg, f"{len(lost_now)} sites lost contact",
                   "These sites stopped reporting at the same time:\n\n" + listing +
                   "\n\nWhen many sites drop together the cause is usually at head office "
                   "(this PC, its internet link, or the VPN hub) rather than at the hotels.")
        return {"lost": lost_now, "back": back_now}

    def run(self):
        self._stop.wait(30)
        while not self._stop.is_set():
            try:
                self.check()
            except Exception as exc:
                self.log(f"lost-contact check failed: {exc}")
            self._stop.wait(60)


def site_recipients(cfg, site):
    """The IT managers assigned to one property (falls back to the global list)."""
    for entry in (cfg.get("hub") or {}).get("sites") or []:
        if entry.get("name") == site:
            emails = entry.get("email") or []
            if isinstance(emails, str):
                emails = [x.strip() for x in emails.replace(";", ",").split(",") if x.strip()]
            return [x for x in emails if "@" in x]
    return []


def _alert(cfg, title, body, site="", severity="high"):
    try:
        if (cfg.get("email") or {}).get("enabled"):
            to = site_recipients(cfg, site) if site else []
            alerts.send_email(cfg, f"[Prahari] {title}", body, to=to or None)
        if (cfg.get("webhook") or {}).get("enabled"):
            alerts.send_webhook(cfg, {"text": f"{title}\n{body}", "severity": severity,
                                      "kind": "site", "site": site})
    except Exception:
        pass


_OVERVIEW_CACHE = {"ts": 0.0, "rows": None}


def hub_overview(scanner=None):
    """Everything the Locations view needs: the corporate office plus every branch."""
    cfg = settings.load()
    expect = int((cfg.get("hub") or {}).get("expect_minutes") or 5) * 60
    now = time.time()
    import time as _t
    fresh = _t.time()
    rows = []
    cached = _OVERVIEW_CACHE["rows"]
    use_cache = cached is not None and fresh - _OVERVIEW_CACHE["ts"] < 4
    if use_cache:
        rows = [dict(r) for r in cached]
        branches_iter = []
    else:
        branches_iter = store.branches()
    for branch in branches_iter:
        payload = branch.get("payload") or {}
        health = payload.get("health") or {}
        age = now - (branch.get("last_ts") or 0)
        rows.append({
            "name": branch["name"],
            "age": int(age),
            "online": age <= expect,
            "version": payload.get("version", ""),
            "health": health,
            "devices": payload.get("devices", 0),
            "monitored": payload.get("monitored", 0),
            "gateway": payload.get("gateway", "unknown"),
            "wan": payload.get("wan") or {},
            "traffic": payload.get("traffic") or {},
            "incidents": payload.get("incidents") or [],
            "sla": payload.get("sla") or {},
            "internet": payload.get("internet") or [],
        })
    if not use_cache:
        _OVERVIEW_CACHE["rows"] = [dict(r) for r in rows]
        _OVERVIEW_CACHE["ts"] = fresh

    # the corporate office (this PC) is a location too, so the table reads
    # "Corporate Office + 6 hotels" instead of only the branches
    if scanner is not None:
        try:
            snap = scanner.corp_summary()
            health = snap.get("health") or {}
            wan = snap.get("wan") or {}
            traffic = snap.get("traffic") or {}
            rows.append({
                "name": cfg.get("site_name") or "Corporate Office",
                "kind": "corp",
                "age": 0,
                "online": True,
                "version": snap.get("version", ""),
                "health": health,
                "devices": snap.get("devices", 0),
                "monitored": health.get("monitored", 0),
                "gateway": (snap.get("gateway") or {}).get("state", "unknown"),
                "wan": {"ips": wan.get("ips") or [], "isp": wan.get("isp", ""),
                        "dual": bool(wan.get("dual"))},
                "traffic": {"down_bps": traffic.get("total_down_bps", 0),
                            "up_bps": traffic.get("total_up_bps", 0), "top": []},
                "incidents": [{"id": i.get("id"), "title": i.get("title"),
                               "severity": i.get("severity"), "state": i.get("state"),
                               "device_name": i.get("device_name"),
                               "device_ip": i.get("device_ip"),
                               "opened_ts": i.get("opened_ts")}
                              for i in (snap.get("open_incidents") or [])],
                "internet": snap.get("internet") or [],
                "local": True,
            })
        except Exception:
            pass
    for row in rows:
        row.setdefault("kind", "hotel")

    rows.sort(key=lambda r: (0 if r.get("kind") == "corp" else 1,
                             r["online"] is False, r["name"].lower()))
    totals = {
        "sites": len(rows),
        "hotels": sum(1 for r in rows if r.get("kind") == "hotel"),
        "online": sum(1 for r in rows if r["online"]),
        "devices": sum(r["devices"] or 0 for r in rows),
        "incidents": sum(len(r["incidents"]) for r in rows),
        "critical": sum(1 for r in rows for i in r["incidents"] if i.get("severity") == "critical"),
        "down_links": sum(1 for r in rows if r["gateway"] == "down"),
    }
    return {"branches": rows, "totals": totals, "expect_minutes": expect // 60,
            "enabled": bool((cfg.get("hub") or {}).get("enabled")),
            "is_hub": bool((cfg.get("hub") or {}).get("enabled"))}


def ingest(payload):
    """Store one branch report (already authenticated)."""
    name = (payload.get("site") or "").strip()[:64] or "branch"
    store.save_branch(name, payload)
    return name
