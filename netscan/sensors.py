"""User-defined checks - the PRTG idea that a ping is not a service check.

A device can be perfectly reachable while the booking engine returns 500, the certificate
expired last week, or DNS answers with the wrong address. These are the checks a hotel
actually cares about, and they are defined as data, not code:

    http     GET a URL, expect a status and optionally a word on the page
    tcp      a port answers
    dns      a name resolves, optionally to a specific address
    cert     how many days until the certificate expires
    snmp     an OID returns a number, compared with a threshold (UPS battery, temperature)
    ping     the host answers
    service  a Windows service / systemd unit is running
    proc     a process is running
    wmi      a Windows performance counter or WMI count (free disk, CPU) - Windows only
    sqlite   one read-only query against a SQLite file (e.g. invoices in the last hour)

TEMPLATES holds ready-made sensors for the checks a hotel usually wants first.

Each sensor has its own interval and its own warning/critical limits, keeps a short history,
and raises an event (and an alert) only when its state changes - so a dead page does not mail
you every minute.

Two noise controls live here too:

  * maintenance windows - silence a device or a sensor for a period, on purpose
  * dependencies         - do not alert about the printer when its switch is down
"""

from __future__ import annotations

import datetime
import hashlib
import os
import socket
import ssl
import time
import urllib.error
import urllib.request

from . import settings, store

UP, WARN, DOWN = "up", "warn", "down"
KINDS = ("http", "tcp", "dns", "cert", "snmp", "ping", "service", "proc", "wmi", "sqlite")


# ----------------------------------------------------------------- helpers --
TEMPLATES = {
    "booking": {
        "label": "Booking engine page",
        "ask": "URL of the booking page",
        "sensor": {"type": "http", "target": "https://www.example.com/booking",
                   "expect_status": 200, "expect_text": "Book", "interval": 300},
        "why": "The page guests actually use - a 500 here is lost revenue."},
    "pms": {
        "label": "PMS port on the server",
        "ask": "IP of the PMS server (set the port too)",
        "sensor": {"type": "tcp", "target": "192.168.1.10", "port": 8080, "interval": 60},
        "why": "If the property management system's port closes, reception is blind."},
    "portal": {
        "label": "Guest Wi-Fi portal certificate",
        "ask": "host name of the captive portal",
        "sensor": {"type": "cert", "target": "portal.example.com", "port": 443,
                   "warn_value": 21, "crit_value": 7, "interval": 3600},
        "why": "An expired captive-portal certificate locks every guest out."},
    "ups": {
        "label": "UPS battery capacity",
        "ask": "IP of the UPS network card (SNMP)",
        "sensor": {"type": "snmp", "target": "192.168.1.20",
                   "oid": "1.3.6.1.2.1.33.1.2.4.0", "operator": "<",
                   "warn_value": 60, "crit_value": 30, "interval": 300},
        "why": "Battery below 60% means the next power cut takes the network with it."},
    "disk": {
        "label": "Server free disk space (C:)",
        "ask": "counter (default: C: on this PC)",
        "sensor": {"type": "wmi", "target": "\\LogicalDisk(C:)\\% Free Space",
                   "operator": "<", "warn_value": 15, "crit_value": 5, "interval": 900},
        "why": "A full C: stops the billing database and the backups with it."},
    "switch_ping": {
        "label": "Core switch answers",
        "ask": "IP of the switch",
        "sensor": {"type": "ping", "target": "192.168.1.2", "interval": 60},
        "why": "The switch every floor access point hangs off."},
    "invoice_rows": {
        "label": "Invoices created in the last hour",
        "ask": "path of the billing SQLite file (edit the query to match your tables)",
        "sensor": {"type": "sqlite", "target": "C:\\Billing\\billing.db",
                   "query": "SELECT COUNT(*) FROM invoices WHERE created > "
                            "datetime('now','-1 hour')",
                   "operator": "<", "warn_value": 1, "crit_value": 1, "interval": 3600},
        "why": "No invoices for an hour during service means the till chain is broken."},
}


def templates():
    """The library as the dashboard shows it."""
    return [{"key": k, "label": t["label"], "ask": t["ask"], "why": t["why"],
             "sensor": dict(t["sensor"])} for k, t in TEMPLATES.items()]


def from_template(name, target=None, **overrides):
    """A ready-made sensor from the library, with the target (and anything else) replaced."""
    template = TEMPLATES.get((name or "").strip().lower())
    if not template:
        return None
    sensor = dict(template["sensor"])
    sensor["name"] = template["label"]
    if target:
        sensor["target"] = target
    for key, value in overrides.items():
        if value not in (None, ""):
            sensor[key] = value
    return sensor


def sensor_id(sensor):
    base = f"{sensor.get('type')}|{sensor.get('target')}|{sensor.get('port','')}|{sensor.get('name','')}"
    return "S-" + hashlib.sha1(base.encode()).hexdigest()[:10]


def default_sensors():
    return []


# ------------------------------------------------------------------ checks --
def check_http(sensor):
    url = sensor.get("target") or ""
    want_status = int(sensor.get("expect_status") or 200)
    want_text = (sensor.get("expect_text") or "").strip()
    timeout = float(sensor.get("timeout") or 8)
    started = time.time()
    req = urllib.request.Request(url, headers={"User-Agent": "Prahari-sensor/1.0"})
    ctx = ssl.create_default_context()
    if str(sensor.get("verify", True)).lower() in ("false", "0", "no", "off"):
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE        # device with its own (self-signed) certificate
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(200000).decode("utf-8", "replace")
            elapsed = (time.time() - started) * 1000
            if resp.status != want_status:
                return DOWN, elapsed, f"HTTP {resp.status}, expected {want_status}"
            if want_text and want_text.lower() not in body.lower():
                return DOWN, elapsed, f"HTTP {resp.status} but the page does not contain '{want_text}'"
            return UP, elapsed, f"HTTP {resp.status} in {elapsed:.0f} ms"
    except urllib.error.HTTPError as exc:
        elapsed = (time.time() - started) * 1000
        return DOWN, elapsed, f"HTTP {exc.code}"
    except Exception as exc:
        elapsed = (time.time() - started) * 1000
        return DOWN, elapsed, f"{exc.__class__.__name__}: {str(exc)[:80]}"


def check_tcp(sensor):
    host = sensor.get("target")
    port = int(sensor.get("port") or 0)
    timeout = float(sensor.get("timeout") or 4)
    started = time.time()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            elapsed = (time.time() - started) * 1000
            return UP, elapsed, f"port {port} open in {elapsed:.0f} ms"
    except Exception as exc:
        return DOWN, (time.time() - started) * 1000, f"port {port}: {exc.__class__.__name__}"


def check_dns(sensor):
    name = sensor.get("target") or ""
    expect = (sensor.get("expect_text") or "").strip()
    timeout = float(sensor.get("timeout") or 4)
    started = time.time()
    try:
        answers = socket.getaddrinfo(name, None)
        elapsed = (time.time() - started) * 1000
        addrs = sorted({a[4][0] for a in answers})
        if expect and expect not in addrs:
            return DOWN, elapsed, f"{name} -> {', '.join(addrs)} (expected {expect})"
        return UP, elapsed, f"{name} -> {', '.join(addrs[:3])}"
    except Exception as exc:
        return DOWN, (time.time() - started) * 1000, f"resolve failed: {exc.__class__.__name__}"


def check_cert(sensor):
    host = sensor.get("target")
    port = int(sensor.get("port") or 443)
    warn_days = int(sensor.get("warn_value") or 21)
    crit_days = int(sensor.get("crit_value") or 7)
    timeout = float(sensor.get("timeout") or 6)
    try:
        expires, trusted = _cert_expiry(host, port, timeout)
        days = (expires - time.time()) / 86400
        when = datetime.datetime.fromtimestamp(expires).strftime("%d/%m/%Y")
        note = "" if trusted else " - self-signed / not trusted, expiry read anyway"
        if days <= crit_days:
            return DOWN, days, f"certificate expires {when} ({days:.0f} days){note}"
        if days <= warn_days:
            return WARN, days, f"certificate expires {when} ({days:.0f} days){note}"
        return UP, days, f"certificate valid until {when} ({days:.0f} days){note}"
    except Exception as exc:
        return DOWN, 0, f"{exc.__class__.__name__}: {str(exc)[:80]}"


def _cert_expiry(host, port, timeout):
    """(expiry epoch, trusted). Tries a verified connection first, then reads the raw certificate."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                return ssl.cert_time_to_seconds(tls.getpeercert()["notAfter"]), True
    except ssl.SSLCertVerificationError:
        pass
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
    from cryptography import x509
    cert = x509.load_der_x509_certificate(der)
    after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(
        tzinfo=datetime.timezone.utc)
    return after.timestamp(), False


def check_snmp(sensor):
    from . import snmp
    host = sensor.get("target")
    oid = sensor.get("oid") or ""
    community = sensor.get("community") or "public"
    try:
        rows = snmp.get(host, [oid], community, float(sensor.get("timeout") or 2))
        if not rows:
            return DOWN, 0, "no answer from the OID"
        value = rows[0][2]
        try:
            number = float(value)
        except (TypeError, ValueError):
            return UP, 0, f"{value}"
        warn = _number(sensor.get("warn_value"))
        crit = _number(sensor.get("crit_value"))
        op = sensor.get("operator") or ">"
        if crit is not None and _compare(number, op, crit):
            return DOWN, number, f"{number:g} {op} {crit:g}"
        if warn is not None and _compare(number, op, warn):
            return WARN, number, f"{number:g} {op} {warn:g}"
        return UP, number, f"{number:g}"
    except Exception as exc:
        return DOWN, 0, f"{exc.__class__.__name__}"


def check_ping(sensor):
    from . import discovery
    host = sensor.get("target")
    started = time.time()
    ok = discovery.ping(host, int(float(sensor.get("timeout") or 2) * 1000))
    elapsed = (time.time() - started) * 1000
    return (UP if ok else DOWN), elapsed, (f"answered in {elapsed:.0f} ms" if ok else "no answer")


def check_service(sensor):
    """Is a Windows service (or a systemd unit) running?

    `target` is the service name. Nothing is executed that the operator did not name.
    """
    import subprocess
    import sys
    name = (sensor.get("target") or "").strip()
    if not name:
        return DOWN, 0, "no service name given"
    try:
        if sys.platform == "win32":
            out = subprocess.run(["sc", "query", name], capture_output=True, text=True,
                                 timeout=10).stdout
            if "RUNNING" in out.upper():
                return UP, 0, "service is running"
            if "STOPPED" in out.upper():
                return DOWN, 0, "service is stopped"
            return DOWN, 0, "service not found"
        out = subprocess.run(["systemctl", "is-active", name], capture_output=True,
                             text=True, timeout=10).stdout.strip()
        if out == "active":
            return UP, 0, "unit is active"
        return DOWN, 0, f"unit is {out or 'unknown'}"
    except Exception as exc:
        return DOWN, 0, f"{exc.__class__.__name__}"


def check_proc(sensor):
    """Is a process with this name running?"""
    import subprocess
    import sys
    name = (sensor.get("target") or "").strip().lower()
    if not name:
        return DOWN, 0, "no process name given"
    try:
        try:
            import psutil
            hits = [p for p in psutil.process_iter(["name"])
                    if (p.info.get("name") or "").lower().startswith(name)]
            count = len(hits)
        except ImportError:
            if sys.platform == "win32":
                out = subprocess.run(["tasklist"], capture_output=True, text=True,
                                     timeout=10).stdout.lower()
            else:
                out = subprocess.run(["ps", "-eo", "comm"], capture_output=True, text=True,
                                     timeout=10).stdout.lower()
            count = sum(1 for line in out.splitlines() if name in line)
        if count:
            return UP, count, f"{count} process(es) running"
        return DOWN, 0, "not running"
    except Exception as exc:
        return DOWN, 0, f"{exc.__class__.__name__}"


def _judge(number, sensor):
    """Compare a number with the sensor's warning / critical limits."""
    warn = _number(sensor.get("warn_value"))
    crit = _number(sensor.get("crit_value"))
    op = sensor.get("operator") or ">"
    if crit is not None and _compare(number, op, crit):
        return DOWN, number, f"{number:g} {op} {crit:g}"
    if warn is not None and _compare(number, op, warn):
        return WARN, number, f"{number:g} {op} {warn:g}"
    return UP, number, f"{number:g}"


def _ps_quote(text):
    """A PowerShell single-quoted literal: nothing inside it is interpreted."""
    return "'" + str(text).replace("'", "''") + "'"


def wmi_script(target):
    """The PowerShell for a wmi sensor. The target only ever appears as a quoted literal."""
    target = (target or "").strip()
    if target.lower().startswith("select "):
        return f"@(Get-CimInstance -Query {_ps_quote(target)} -ErrorAction Stop).Count"
    return (f"(Get-Counter -Counter {_ps_quote(target)} -ErrorAction Stop)"
            f".CounterSamples[0].CookedValue")


def check_wmi(sensor):
    """A Windows performance counter (e.g. \\LogicalDisk(C:)\\% Free Space) or the row count
    of a WMI query (SELECT * FROM Win32_Service WHERE State='Stopped' AND StartMode='Auto').

    Reads this PC only. Windows only."""
    import subprocess
    import sys
    if sys.platform != "win32":
        return DOWN, 0, "WMI sensors work on Windows only"
    target = (sensor.get("target") or "").strip()
    if not target:
        return DOWN, 0, "no counter given"
    try:
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        proc = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                               wmi_script(target)], capture_output=True, text=True,
                              timeout=30, creationflags=flags)
        lines = [x for x in (proc.stdout or "").strip().splitlines() if x.strip()]
        if not lines:
            return DOWN, 0, ((proc.stderr or "").strip().splitlines() or ["no output"])[0][:100]
        return _judge(float(lines[-1].strip().replace(",", ".")), sensor)
    except Exception as exc:
        return DOWN, 0, f"{exc.__class__.__name__}: {str(exc)[:60]}"


def check_sqlite(sensor):
    """One read-only query against a SQLite file; the first column of the first row is judged.

    `target` is the file, `query` the SELECT. The file is opened read-only, so even a query
    that tried to write would be refused by SQLite itself."""
    import sqlite3
    path = (sensor.get("target") or "").strip()
    query = (sensor.get("query") or sensor.get("oid") or "").strip().rstrip(";")
    if not path or not query:
        return DOWN, 0, "a database path and a query are required"
    if not query.lower().startswith(("select", "with")) or ";" in query:
        return DOWN, 0, "only a single SELECT is allowed"
    if not os.path.exists(path):
        return DOWN, 0, "database file not found"
    try:
        uri = "file:" + urllib.request.pathname2url(os.path.abspath(path)) + "?mode=ro"
        conn = sqlite3.connect(uri, uri=True, timeout=5)
        try:
            row = conn.execute(query).fetchone()
        finally:
            conn.close()
        value = row[0] if row else 0
        try:
            number = float(value)
        except (TypeError, ValueError):
            return UP, 0, str(value)[:60]
        return _judge(number, sensor)
    except Exception as exc:
        return DOWN, 0, f"{exc.__class__.__name__}: {str(exc)[:60]}"


CHECKS = {"http": check_http, "tcp": check_tcp, "dns": check_dns, "cert": check_cert,
          "snmp": check_snmp, "ping": check_ping, "service": check_service,
          "proc": check_proc, "wmi": check_wmi, "sqlite": check_sqlite}


def _number(value):
    """Thresholds come from a form as text; '' means 'not set'."""
    if value is None or (isinstance(value, str) and not value.strip()):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _compare(value, op, limit):
    return {"<": value < limit, ">": value > limit, "=": value == limit,
            "<=": value <= limit, ">=": value >= limit}.get(op, value > limit)


# ------------------------------------------------------------ maintenance ---
def in_maintenance(cfg, ip=None, sensor=None, now=None):
    """Is this device or sensor silenced right now?"""
    now = now or datetime.datetime.now()
    for window in (cfg.get("maintenance") or []):
        if not window.get("enabled", True):
            continue
        try:
            start = datetime.datetime.strptime(window.get("from") or "", "%Y-%m-%d %H:%M")
            end = datetime.datetime.strptime(window.get("to") or "", "%Y-%m-%d %H:%M")
        except ValueError:
            continue
        if not (start <= now <= end):
            continue
        target = (window.get("match") or "").strip()
        if not target:
            return True, window.get("reason") or "maintenance window"
        if ip and target == ip:
            return True, window.get("reason") or "maintenance window"
        if sensor and target in (sensor.get("id"), sensor.get("name")):
            return True, window.get("reason") or "maintenance window"
    return False, ""


def parent_down(cfg, ip, states):
    """Dependency check: is the parent of this device down?"""
    parent = ((cfg.get("dependencies") or {}).get(ip) or "").strip()
    if not parent:
        return False, ""
    state = (states or {}).get(parent)
    if state and state.get("state") == DOWN:
        return True, f"parent {parent} is down"
    return False, ""


# ------------------------------------------------------------------ runner --
class SensorRunner:
    """Polls the sensors on their own intervals and reports state changes only."""

    def __init__(self, log=None):
        self.log = log or (lambda m: None)
        self.states = {}          # id -> {state, message, ts, value, history}
        self.last_run = {}

    def sensors(self, cfg=None):
        cfg = cfg or settings.load()
        out = []
        for raw in (cfg.get("sensors") or []):
            if not isinstance(raw, dict) or not raw.get("target"):
                continue
            sensor = dict(raw)
            sensor["id"] = sensor.get("id") or sensor_id(sensor)
            if sensor.get("enabled", True):
                out.append(sensor)
        return out

    def run_once(self, cfg=None, now=None):
        """Poll whatever is due. Returns the list of sensors that changed state."""
        cfg = cfg or settings.load()
        now = time.time()
        changed = []
        for sensor in self.sensors(cfg):
            sid = sensor["id"]
            interval = max(15, int(sensor.get("interval") or 60))
            if now - self.last_run.get(sid, 0) < interval:
                continue
            self.last_run[sid] = now
            quiet, reason = in_maintenance(cfg, ip=sensor.get("device_ip"), sensor=sensor)
            check = CHECKS.get(sensor.get("type") or "ping")
            if not check:
                continue
            try:
                state, value, message = check(sensor)
            except Exception as exc:
                state, value, message = DOWN, 0, f"{exc.__class__.__name__}"
            previous = self.states.get(sid) or {}
            entry = {"id": sid, "name": sensor.get("name") or sensor.get("target"),
                     "type": sensor.get("type"), "target": sensor.get("target"),
                     "state": state, "message": message, "value": value, "ts": int(now),
                     "maintenance": quiet, "reason": reason,
                     "since": (previous.get("since") if previous.get("state") == state
                               else int(now)) or int(now),
                     "paged": (previous.get("paged") or []) if previous.get("state") == state
                     else [],
                     "history": (previous.get("history") or [])[-40:]}
            entry["history"].append({"ts": int(now), "state": state, "value": value})
            try:
                store.add_sensor_sample(sid, state, value if isinstance(value, (int, float)) else None)
            except Exception:
                pass
            self.states[sid] = entry
            if quiet:
                continue
            first_bad = not previous.get("state") and state != UP
            if first_bad or (previous.get("state") and previous.get("state") != state):
                changed.append(entry)
                store.add_event(f"sensor {entry['name']}", "high" if state == DOWN else
                                ("medium" if state == WARN else "info"),
                                f"{entry['name']}: {previous.get('state') or 'new'} -> {state} ({message})")
                self.log(f"sensor {entry['name']}: {state} - {message}")
        return changed

    def view(self, cfg=None):
        cfg = cfg or settings.load()
        rows = []
        for sensor in self.sensors(cfg):
            state = self.states.get(sensor["id"]) or {
                "id": sensor["id"], "name": sensor.get("name") or sensor.get("target"),
                "type": sensor.get("type"), "target": sensor.get("target"),
                "state": "unknown", "message": "not polled yet", "value": None,
                "ts": 0, "history": []}
            row = dict(state, interval=sensor.get("interval") or 60,
                       device_ip=sensor.get("device_ip") or "")
            if len(row.get("history") or []) < 5:
                try:
                    stored = store.sensor_history(sensor["id"], 24)[-30:]
                    row["history"] = [{"ts": p["ts"], "state": p["state"],
                                       "value": p["value"]} for p in stored]
                except Exception:
                    pass
            rows.append(row)
        order = {DOWN: 0, WARN: 1, "unknown": 2, UP: 3}
        rows.sort(key=lambda r: order.get(r.get("state"), 9))
        counts = {UP: 0, WARN: 0, DOWN: 0, "unknown": 0}
        for row in rows:
            counts[row.get("state")] = counts.get(row.get("state"), 0) + 1
        return {"sensors": rows, "counts": counts, "total": len(rows), "templates": templates()}
