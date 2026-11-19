"""Persistent storage: devices, labels, health samples, incidents, events, users.

SQLite, one file in %USERPROFILE%\\.netsentinel\\netsentinel.db. Every call is
best-effort: a broken database must never stop monitoring.
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
import os
import secrets
import sqlite3
import threading
import time

DB_DIR = os.path.join(os.path.expanduser("~"), ".netsentinel")
DB_PATH = os.path.join(DB_DIR, "netsentinel.db")
_lock = threading.RLock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    mac TEXT PRIMARY KEY, ip TEXT, label TEXT, first_seen TEXT, last_seen TEXT,
    seen_count INTEGER DEFAULT 1, last_type TEXT
);
CREATE TABLE IF NOT EXISTS samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT, ts INTEGER, latency_ms REAL, loss_pct REAL, state TEXT
);
CREATE INDEX IF NOT EXISTS idx_samples_ip_ts ON samples(ip, ts);
CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY, device_ip TEXT, device_name TEXT, device_type TEXT,
    severity TEXT, state TEXT, title TEXT, opened_ts INTEGER, updated_ts INTEGER,
    closed_ts INTEGER, diagnosis TEXT, timeline TEXT
);
CREATE INDEX IF NOT EXISTS idx_inc_ts ON incidents(opened_ts);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER, source TEXT, severity TEXT, message TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY, salt TEXT, hash TEXT, role TEXT, created_ts INTEGER,
    last_login_ts INTEGER, must_change INTEGER DEFAULT 0,
    totp_secret TEXT, totp_enabled INTEGER DEFAULT 0, backup_codes TEXT, sites TEXT
);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS hosts (
    ip TEXT PRIMARY KEY, host TEXT, payload TEXT, updated_ts INTEGER
);
CREATE TABLE IF NOT EXISTS api_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT, hash TEXT UNIQUE, scope TEXT, created_ts INTEGER, last_used_ts INTEGER
);
CREATE TABLE IF NOT EXISTS outbox (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, kind TEXT, payload TEXT,
    attempts INTEGER DEFAULT 0, last_error TEXT
);
CREATE TABLE IF NOT EXISTS host_samples (
    ts INTEGER, ip TEXT, cpu_pct REAL, mem_pct REAL, disk_pct REAL
);
CREATE INDEX IF NOT EXISTS idx_hostsamples ON host_samples (ip, ts);
CREATE TABLE IF NOT EXISTS sensor_samples (
    id TEXT, ts INTEGER, state TEXT, value REAL
);
CREATE INDEX IF NOT EXISTS idx_sensor_ts ON sensor_samples (id, ts);
CREATE TABLE IF NOT EXISTS branches (
    name TEXT PRIMARY KEY, last_ts INTEGER, payload TEXT
);
"""


_local = threading.local()
_schema_ready = False


def _connect():
    """One connection per thread (WAL), schema created once per process."""
    global _schema_ready
    conn = getattr(_local, "conn", None)
    if conn is not None:
        return conn
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=10000")
    if not _schema_ready:
        conn.executescript(SCHEMA)
        _schema_ready = True
    conn.commit()
    _local.conn = conn
    return conn


def _now():
    """Seconds since the epoch, as the older call sites expect."""
    return int(time.time())


def _now_ts():
    return int(time.time())


def _json(value):
    import json
    try:
        return json.dumps(value, default=str)
    except Exception:
        return "{}"


def _unjson(value):
    import json
    try:
        return json.loads(value) if value else {}
    except Exception:
        return {}


def _exec(sql, params=(), fetch=False):
    """Run one statement on this thread's connection. Never raises."""
    with _lock:
        try:
            conn = _connect()
            cur = conn.execute(sql, params)
            rows = cur.fetchall() if fetch else True
            conn.commit()
            return rows
        except Exception as exc:
            if os.environ.get("NETSENTINEL_DEBUG"):
                print("store error:", exc)
            return [] if fetch else False


# ---------------------------------------------------------------- devices ----

def record(mac, ip, dev_type, label=""):
    if not mac:
        return
    with _lock:
        try:
            conn = _connect()
            try:
                row = conn.execute("SELECT label, seen_count FROM devices WHERE mac=?", (mac,)).fetchone()
                now = _now()
                if row:
                    conn.execute(
                        "UPDATE devices SET ip=?, last_seen=?, seen_count=?, last_type=?, label=? WHERE mac=?",
                        (ip, now, (row["seen_count"] or 0) + 1, dev_type, row["label"] or label, mac),
                    )
                else:
                    conn.execute(
                        "INSERT INTO devices (mac, ip, label, first_seen, last_seen, seen_count, last_type)"
                        " VALUES (?,?,?,?,?,1,?)",
                        (mac, ip, label, now, now, dev_type),
                    )
                conn.commit()
            except Exception:
                raise
        except Exception:
            pass


def set_label(mac, label):
    if not mac:
        return False
    with _lock:
        try:
            conn = _connect()
            try:
                cur = conn.execute("UPDATE devices SET label=? WHERE mac=?", (label[:64], mac))
                if cur.rowcount == 0:
                    now = _now()
                    conn.execute(
                        "INSERT INTO devices (mac, ip, label, first_seen, last_seen) VALUES (?,?,?,?,?)",
                        (mac, "", label[:64], now, now),
                    )
                conn.commit()
                return True
            except Exception:
                raise
        except Exception:
            return False


def labels():
    rows = _exec("SELECT mac, label FROM devices WHERE label IS NOT NULL AND label<>''", fetch=True)
    return {r["mac"]: r["label"] for r in rows or []}


def known_devices(limit=500):
    rows = _exec(
        "SELECT mac, ip, label, first_seen, last_seen, seen_count, last_type FROM devices"
        " ORDER BY last_seen DESC LIMIT ?",
        (limit,), fetch=True,
    )
    return [dict(r) for r in rows or []]


# ---------------------------------------------------------------- samples ----

def add_sample(ip, latency_ms, loss_pct, state):
    ts = _now_ts()
    _exec(
        "INSERT INTO samples (ip, ts, latency_ms, loss_pct, state) VALUES (?,?,?,?,?)",
        (ip, ts, latency_ms, loss_pct, state),
    )


def history(ip, minutes=120):
    cutoff = _now_ts() - minutes * 60
    rows = _exec(
        "SELECT ts, latency_ms, loss_pct, state FROM samples WHERE ip=? AND ts>=? ORDER BY ts",
        (ip, cutoff), fetch=True,
    )
    return [dict(r) for r in rows or []]


def prune(days=14):
    cutoff = _now_ts() - days * 86400
    _exec("DELETE FROM samples WHERE ts<?", (cutoff,))
    _exec("DELETE FROM events WHERE ts<?", (cutoff,))
    _exec("DELETE FROM incidents WHERE closed_ts IS NOT NULL AND closed_ts<?", (cutoff,))


# -------------------------------------------------------------- incidents ----

def save_incident(inc):
    _exec(
        "INSERT OR REPLACE INTO incidents (id, device_ip, device_name, device_type, severity, state,"
        " title, opened_ts, updated_ts, closed_ts, diagnosis, timeline) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            inc.get("id"), inc.get("device_ip"), inc.get("device_name"), inc.get("device_type"),
            inc.get("severity"), inc.get("state"), inc.get("title"),
            inc.get("opened_ts"), inc.get("updated_ts"), inc.get("closed_ts"),
            _json(inc.get("diagnosis")), _json(inc.get("timeline")),
        ),
    )


def incidents(limit=100, open_only=False):
    sql = "SELECT * FROM incidents"
    if open_only:
        sql += " WHERE state<>'resolved'"
    sql += " ORDER BY opened_ts DESC LIMIT ?"
    rows = _exec(sql, (limit,), fetch=True)
    out = []
    for r in rows or []:
        d = dict(r)
        d["diagnosis"] = _unjson(d.get("diagnosis")) or {}
        d["timeline"] = _unjson(d.get("timeline")) or []
        out.append(d)
    return out


# ----------------------------------------------------------------- events ----

def add_event(source, severity, message):
    ts = _now_ts()
    _exec("INSERT INTO events (ts, source, severity, message) VALUES (?,?,?,?)",
          (ts, source, severity, message[:600]))
    return ts


def events(limit=200):
    rows = _exec("SELECT ts, source, severity, message FROM events ORDER BY ts DESC LIMIT ?",
                 (limit,), fetch=True)
    return [dict(r) for r in rows or []]


# ------------------------------------------------------------------ users ----

def _hash(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), 200_000).hex()


def create_user(username, password, role="admin", sites=None):
    import json
    _ensure_columns()
    salt = secrets.token_hex(16)
    ok = _exec(
        "INSERT OR REPLACE INTO users (username, salt, hash, role, created_ts, must_change, sites)"
        " VALUES (?,?,?,?,?,0,?)",
        (username.lower(), salt, _hash(password, salt), role, _now_ts(),
         json.dumps([x for x in (sites or []) if x])),
    )
    return ok is not None


def _ensure_columns():
    """Add the 2FA columns to an older database without losing it."""
    try:
        conn = _connect()
        cols = {r[1] for r in conn.execute("PRAGMA table_info(users)").fetchall()}
        for name, decl in (("totp_secret", "TEXT"), ("totp_enabled", "INTEGER DEFAULT 0"),
                           ("backup_codes", "TEXT"), ("sites", "TEXT")):
            if name not in cols:
                conn.execute(f"ALTER TABLE users ADD COLUMN {name} {decl}")
        conn.commit()
    except Exception:
        pass


def user_record(username):
    _ensure_columns()
    rows = _exec("SELECT username, role, totp_secret, totp_enabled, backup_codes, sites FROM users"
                 " WHERE username=?", ((username or "").lower(),), fetch=True)
    if not rows:
        return None
    row = dict(rows[0])
    import json
    try:
        row["backup_codes"] = json.loads(row.get("backup_codes") or "[]")
    except Exception:
        row["backup_codes"] = []
    try:
        row["sites"] = json.loads(row.get("sites") or "[]")
    except Exception:
        row["sites"] = []
    return row


def set_user_sites(username, sites):
    import json
    _ensure_columns()
    return _exec("UPDATE users SET sites=? WHERE username=?",
                 (json.dumps([x for x in (sites or []) if x]), (username or "").lower())) is not False


def set_totp(username, secret, enabled=False, backup_hashes=None):
    import json
    _ensure_columns()
    if backup_hashes is None:
        return _exec("UPDATE users SET totp_secret=?, totp_enabled=? WHERE username=?",
                     (secret, 1 if enabled else 0, (username or "").lower())) is not False
    return _exec("UPDATE users SET totp_secret=?, totp_enabled=?, backup_codes=? WHERE username=?",
                 (secret, 1 if enabled else 0, json.dumps(backup_hashes or []),
                  (username or "").lower())) is not False


def set_backup_codes(username, hashes):
    import json
    return _exec("UPDATE users SET backup_codes=? WHERE username=?",
                 (json.dumps(hashes or []), (username or "").lower())) is not False


def check_user(username, password):
    rows = _exec("SELECT * FROM users WHERE username=?", ((username or "").lower(),), fetch=True)
    if not rows:
        return None
    row = rows[0]
    if hmac.compare_digest(_hash(password or "", row["salt"]), row["hash"]):
        _exec("UPDATE users SET last_login_ts=? WHERE username=?", (_now_ts(), row["username"]))
        return {"username": row["username"], "role": row["role"]}
    return None


def set_password(username, password):
    rows = _exec("SELECT salt FROM users WHERE username=?", ((username or "").lower(),), fetch=True)
    salt = rows[0]["salt"] if rows else secrets.token_hex(16)
    return _exec("UPDATE users SET salt=?, hash=? WHERE username=?",
                 (salt, _hash(password, salt), (username or "").lower())) is not None


def list_users():
    rows = _exec("SELECT username, role, created_ts, last_login_ts FROM users ORDER BY username", fetch=True)
    return [dict(r) for r in rows or []]


def delete_user(username):
    return _exec("DELETE FROM users WHERE username=?", ((username or "").lower(),)) is not None


def totp_enabled_count():
    rows = _exec("SELECT COUNT(*) AS n FROM users WHERE totp_enabled=1", fetch=True)
    return (rows[0]["n"] if rows else 0) or 0


def user_count():
    rows = _exec("SELECT COUNT(*) AS n FROM users", fetch=True)
    return rows[0]["n"] if rows else 0


# ------------------------------------------------------------------- hosts ----

def save_host(ip, host, payload):
    _exec("INSERT OR REPLACE INTO hosts (ip, host, payload, updated_ts) VALUES (?,?,?,?)",
          (ip or host, host, _json(payload), _now_ts()))


def hosts():
    rows = _exec("SELECT ip, host, payload, updated_ts FROM hosts ORDER BY host", fetch=True)
    out = []
    for r in rows or []:
        item = {"ip": r["ip"], "host": r["host"], "updated_ts": r["updated_ts"],
                "payload": _unjson(r["payload"]) or {}}
        out.append(item)
    return out


# --------------------------------------------------------- sensor samples ----

def add_sensor_sample(sensor_id, state, value=None):
    return _exec("INSERT INTO sensor_samples (id, ts, state, value) VALUES (?,?,?,?)",
                 (sensor_id, _now_ts(), state, value)) is not False


def sensor_history(sensor_id, hours=24):
    cutoff = _now_ts() - int(hours * 3600)
    rows = _exec("SELECT ts, state, value FROM sensor_samples WHERE id=? AND ts>=?"
                 " ORDER BY ts", (sensor_id, cutoff), fetch=True)
    return [dict(r) for r in rows or []]


def sensor_summary(sensor_id, hours=24):
    """Availability and response trend for one sensor over a window."""
    rows = sensor_history(sensor_id, hours)
    if not rows:
        return {"points": [], "up_pct": None, "count": 0}
    up = sum(1 for r in rows if r["state"] == "up")
    return {"points": [{"ts": r["ts"], "state": r["state"], "value": r["value"]} for r in rows],
            "up_pct": round(100.0 * up / len(rows), 2), "count": len(rows)}


def prune_sensor_samples(days=30):
    cutoff = _now_ts() - int(days * 86400)
    return _exec("DELETE FROM sensor_samples WHERE ts<?", (cutoff,)) is not False


# ----------------------------------------------------------- host samples ----

def add_host_sample(ip, cpu, mem, disk):
    return _exec("INSERT INTO host_samples (ts, ip, cpu_pct, mem_pct, disk_pct) VALUES (?,?,?,?,?)",
                 (_now_ts(), ip, cpu, mem, disk)) is not False


def host_history(ip=None, hours=168):
    cutoff = _now_ts() - int(hours * 3600)
    if ip:
        rows = _exec("SELECT ts, ip, cpu_pct, mem_pct, disk_pct FROM host_samples"
                     " WHERE ip=? AND ts>=? ORDER BY ts", (ip, cutoff), fetch=True)
    else:
        rows = _exec("SELECT ts, ip, cpu_pct, mem_pct, disk_pct FROM host_samples"
                     " WHERE ts>=? ORDER BY ts", (cutoff,), fetch=True)
    return [dict(r) for r in rows or []]


def latency_history(hours=336):
    """Every sample in the window, for baselining (ip, ts, latency, loss)."""
    cutoff = _now_ts() - int(hours * 3600)
    rows = _exec("SELECT ip, ts, latency_ms, loss_pct, state FROM samples"
                 " WHERE ts>=? ORDER BY ts", (cutoff,), fetch=True)
    return [dict(r) for r in rows or []]


# ----------------------------------------------------------------- outbox ----

def queue_alert(kind, payload):
    """Keep an alert that could not be delivered, so it goes out when the link is back."""
    return _exec("INSERT INTO outbox (ts, kind, payload) VALUES (?,?,?)",
                 (_now_ts(), kind, _json(payload))) is not False


def pending_alerts(limit=200):
    rows = _exec("SELECT id, ts, kind, payload, attempts, last_error FROM outbox"
                 " ORDER BY id LIMIT ?", (limit,), fetch=True)
    out = []
    for r in rows or []:
        item = dict(r)
        item["payload"] = _unjson(item.get("payload"))
        out.append(item)
    return out


def note_alert_failure(alert_id, error):
    _exec("UPDATE outbox SET attempts=attempts+1, last_error=? WHERE id=?",
          (str(error)[:200], alert_id))


def drop_alert(alert_id):
    return _exec("DELETE FROM outbox WHERE id=?", (alert_id,)) is not False


def outbox_stats():
    rows = _exec("SELECT COUNT(*) AS n, MIN(ts) AS oldest FROM outbox", fetch=True)
    if not rows:
        return {"pending": 0, "oldest": None}
    return {"pending": rows[0]["n"] or 0, "oldest": rows[0]["oldest"]}


# ------------------------------------------------------------- api tokens ----

def save_api_token(name, token_hash, scope):
    return _exec("INSERT INTO api_tokens (name, hash, scope, created_ts) VALUES (?,?,?,?)",
                 (name, token_hash, scope, _now_ts())) is not False


def api_token_by_hash(token_hash):
    rows = _exec("SELECT id, name, scope, created_ts, last_used_ts FROM api_tokens WHERE hash=?",
                 (token_hash,), fetch=True)
    return dict(rows[0]) if rows else None


def api_tokens():
    rows = _exec("SELECT id, name, scope, created_ts, last_used_ts FROM api_tokens"
                 " ORDER BY created_ts DESC", fetch=True)
    return [dict(r) for r in rows or []]


def touch_api_token(token_id):
    _exec("UPDATE api_tokens SET last_used_ts=? WHERE id=?", (_now_ts(), token_id))


def delete_api_token(name_or_id):
    try:
        ident = int(name_or_id)
        return _exec("DELETE FROM api_tokens WHERE id=?", (ident,)) is not False
    except (TypeError, ValueError):
        return _exec("DELETE FROM api_tokens WHERE name=?", (str(name_or_id),)) is not False


# --------------------------------------------------------------- branches ----

def save_branch(name, payload):
    _exec("INSERT OR REPLACE INTO branches (name, last_ts, payload) VALUES (?,?,?)",
          (name, int(payload.get("ts") or _now_ts()), _json(payload)))


def branches():
    rows = _exec("SELECT name, last_ts, payload FROM branches ORDER BY name", fetch=True)
    out = []
    for r in rows or []:
        out.append({"name": r["name"], "last_ts": r["last_ts"],
                    "payload": _unjson(r["payload"]) or {}})
    return out


def delete_branch(name):
    return _exec("DELETE FROM branches WHERE name=?", (name,))


# ---------------------------------------------------------------- reports ----

def availability(hours=24):
    """Per-device availability over the window, from the sample table."""
    cutoff = _now_ts() - int(hours * 3600)
    rows = _exec(
        "SELECT ip, COUNT(*) AS n,"
        " SUM(CASE WHEN state='up' THEN 1 ELSE 0 END) AS up,"
        " SUM(CASE WHEN state='degraded' THEN 1 ELSE 0 END) AS degraded,"
        " SUM(CASE WHEN state='down' THEN 1 ELSE 0 END) AS down,"
        " AVG(CASE WHEN latency_ms>0 THEN latency_ms END) AS avg_ms,"
        " MAX(loss_pct) AS worst_loss"
        " FROM samples WHERE ts>=? GROUP BY ip",
        (cutoff,), fetch=True,
    )
    out = {}
    for r in rows or []:
        n = r["n"] or 0
        if not n:
            continue
        # a degraded sample counts as half available: the device answered, badly
        score = (r["up"] + 0.5 * (r["degraded"] or 0)) / n * 100
        out[r["ip"]] = {
            "samples": n,
            "availability_pct": round(score, 2),
            "down_samples": r["down"] or 0,
            "degraded_samples": r["degraded"] or 0,
            "avg_latency_ms": round(r["avg_ms"] or 0, 1),
            "worst_loss_pct": round(r["worst_loss"] or 0, 1),
        }
    return out


def incident_stats(days=7):
    """Counts by severity plus MTTR (mean time to resolve) in minutes."""
    cutoff = _now_ts() - int(days * 86400)
    rows = _exec(
        "SELECT severity, COUNT(*) AS n FROM incidents WHERE opened_ts>=? GROUP BY severity",
        (cutoff,), fetch=True,
    )
    by_sev = {r["severity"]: r["n"] for r in rows or []}
    mttr = _exec(
        "SELECT AVG(closed_ts - opened_ts) AS m, COUNT(*) AS n FROM incidents"
        " WHERE opened_ts>=? AND closed_ts IS NOT NULL AND state='resolved'",
        (cutoff,), fetch=True,
    )
    m = (mttr[0]["m"] or 0) if mttr else 0
    worst = _exec(
        "SELECT device_name, COUNT(*) AS n FROM incidents WHERE opened_ts>=?"
        " GROUP BY device_name ORDER BY n DESC LIMIT 8",
        (cutoff,), fetch=True,
    )
    total = _exec("SELECT COUNT(*) AS n FROM incidents WHERE opened_ts>=?", (cutoff,), fetch=True)
    open_now = _exec("SELECT COUNT(*) AS n FROM incidents WHERE state<>'resolved'", fetch=True)
    return {
        "days": days,
        "total": (total[0]["n"] if total else 0),
        "open_now": (open_now[0]["n"] if open_now else 0),
        "by_severity": by_sev,
        "mttr_minutes": round((m or 0) / 60.0, 1),
        "resolved_count": (mttr[0]["n"] if mttr else 0),
        "top_devices": [{"name": r["device_name"], "count": r["n"]} for r in worst or []],
    }


def sample_series(ip, hours=24, points=60):
    """Downsampled latency series for a chart."""
    cutoff = _now_ts() - int(hours * 3600)
    rows = _exec(
        "SELECT ts, latency_ms, loss_pct, state FROM samples WHERE ip=? AND ts>=? ORDER BY ts",
        (ip, cutoff), fetch=True,
    )
    rows = rows or []
    if len(rows) <= points:
        return [dict(r) for r in rows]
    step = max(1, len(rows) // points)
    return [dict(r) for r in rows[::step]][-points:]


# --------------------------------------------------------------- settings ----

def set_setting(key, value):
    _exec("INSERT OR REPLACE INTO settings (key, value) VALUES (?,?)", (key, str(value)))


def get_setting(key, default=None):
    rows = _exec("SELECT value FROM settings WHERE key=?", (key,), fetch=True)
    return rows[0]["value"] if rows else default


def _json(obj):
    import json
    try:
        return json.dumps(obj or {}, default=str)
    except Exception:
        return "{}"


def _unjson(text):
    import json
    try:
        return json.loads(text or "{}")
    except Exception:
        return {}
