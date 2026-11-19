"""Settings for NetSentinel, stored in %USERPROFILE%\\.netsentinel\\config.json.

Everything the dashboard can change lives here so it survives restarts, and the
file is plain JSON so an administrator can inspect or deploy it with Group Policy
or a copy script.
"""

from __future__ import annotations

import copy
import json
import os
import threading

CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".netsentinel")
CONFIG_PATH = os.path.join(CONFIG_DIR, "config.json")

DEFAULTS = {
    "site_name": "",
    "poll_interval_seconds": 60,
    "history_points": 180,
    "thresholds": {
        "latency_warn_ms": 150,
        "latency_crit_ms": 300,
        "loss_warn_pct": 3,
        "loss_crit_pct": 10,
        "open_after_bad_polls": 2,
        "resolve_after_good_polls": 3,
    },
    "monitor": {
        "printers": True,
        "phones": False,
        "unknown": False,
        "servers": True,
        "internet_targets": [
            {"name": "Internet - Google DNS", "host": "8.8.8.8"},
            {"name": "Internet - Cloudflare DNS", "host": "1.1.1.1"},
        ],
    },
    "discovery": {
        "interval_minutes": 10,
        "snmp_communities": ["public"],
        "deep_scan": True,
    },
    "netflow": {
        "enabled": True,
        "port": 2055,
        "sflow_port": 6343,
        "allowed_exporters": [],
    },
    "syslog": {
        "enabled": True,
        "port": 5514,
        "alert_patterns": [
            "gateway.{0,40}(dead|down|fail)",
            "(link|interface|port).{0,40}down",
            "(tunnel|ipsec|vpn).{0,40}(down|fail|disconnect)",
            "(cpu|memory|disk).{0,30}(high|critical|exceed)",
            "(temperature|thermal).{0,30}(high|critical)",
        ],
    },
    "email": {
        "enabled": False,
        "host": "",
        "port": 465,
        "ssl": True,
        "starttls": False,
        "username": "",
        "password": "",
        "from": "",
        "to": [],
        "min_severity": "medium",
    },
    "webhook": {"enabled": False, "url": "", "min_severity": "high"},
    "slack": {"enabled": False, "webhook_url": "", "min_severity": "high"},
    "teams": {"enabled": False, "webhook_url": "", "min_severity": "high"},
    "siem": {"enabled": False, "host": "", "port": 514, "proto": "udp",
             "format": "cef", "min_severity": "medium", "facility": 13},
    "hosts": {"cpu_warn_pct": 90, "disk_warn_pct": 90, "mem_warn_pct": 92,
              "stale_minutes": 10},
    "ai": {"enabled": False, "api_key": "", "model": "claude-opus-5-5", "effort": "high",
           "max_per_hour": 20},
    "wan": {"interval_seconds": 600},
    "hub": {"enabled": False, "expect_minutes": 5, "sites": []},
    "branch": {"hub_url": "", "token": "", "interval_seconds": 30},
    "auth": {"enabled": True, "session_hours": 12, "windows_login": True,
             "windows_users_role": "none"},
    "tls": {"enabled": False, "cert": "", "key": "", "redirect_http": False, "hsts": True},
    "access": {"allow_cidrs": [], "deny_cidrs": [],
               "trusted_proxies": ["127.0.0.1", "::1"]},
    "certs": {"renew_days": 21, "renew_command": "", "auto_restart": True},
    "auth_extra": {"require_totp_for_local": False},
    "heartbeat": {"enabled": False, "url": "", "interval_seconds": 300},
    "telegram": {"enabled": False, "token": "", "chat_ids": []},
    "snmp_v3": {"enabled": False, "user": "", "auth_password": "", "auth_proto": "sha1",
                "priv_password": "", "port": 161},
    "wifi": {"enabled": True, "client_oid": ""},
    "sla_email": {"enabled": False, "day": 1, "hour": 7, "to": [], "last_sent": ""},
    "defaults_check": {"enabled": False, "i_own_this_network": False, "allow_ips": [],
                       "max_attempts": 12, "delay_ms": 350},
    "backup": {"enabled": True, "every_hours": 24, "keep_daily": 7, "keep_weekly": 4},
    "fleet_update": {"version": ""},
    "update": {"check": True, "auto_install": True},
    "oidc": {"enabled": False, "issuer": "", "client_id": "", "client_secret": "",
             "redirect_uri": "", "scopes": "openid profile email",
             "role_claim": "groups", "role_map": {}, "default_role": "viewer",
             "allowed_domains": [], "button_label": "Sign in with your company account"},
    "remote": {"enabled": True, "from_other_devices": False},
}

_lock = threading.RLock()
_config = None


def _deep_merge(base, override):
    out = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def _vault():
    """Imported lazily: the vault needs the store module, which needs settings."""
    from . import vault as _v
    return _v


def _vault():
    """Imported lazily: the vault reads the database path from the store module."""
    from . import vault as _v
    return _v


def load():
    global _config
    with _lock:
        if _config is not None:
            return _config
        data = {}
        try:
            if os.path.exists(CONFIG_PATH):
                with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
                    data = json.load(fh) or {}
        except Exception:
            data = {}
        _config = _deep_merge(DEFAULTS, data)
        try:
            _config = _vault().open_secrets(_config)
        except Exception:
            pass
        return _config


def reload():
    """Drop the cache and read config.json again (used by branch-token checks)."""
    global _config
    with _lock:
        _config = None
    return load()


def save(patch=None):
    """Merge `patch` into the live config and write it to disk."""
    global _config
    with _lock:
        cfg = load()
        if patch:
            _config = _deep_merge(cfg, patch)
        cfg = _config
        try:
            os.makedirs(CONFIG_DIR, exist_ok=True)
            tmp = CONFIG_PATH + ".tmp"
            disk = cfg
            try:
                disk = _vault().seal(cfg)
            except Exception:
                pass
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(disk, fh, indent=2)
            os.replace(tmp, CONFIG_PATH)
            try:
                os.chmod(CONFIG_PATH, 0o600)
            except Exception:
                pass
        except Exception:
            pass
        return cfg


def get(*keys, default=None):
    cfg = load()
    for key in keys:
        if not isinstance(cfg, dict) or key not in cfg:
            return default
        cfg = cfg[key]
    return cfg


def reset():
    global _config
    with _lock:
        _config = copy.deepcopy(DEFAULTS)
        return _config


MASK = "********"
# Every secret the dashboard must never send back to a browser (viewers included).
SECRET_FIELDS = (("email", "password"), ("ai", "api_key"), ("telegram", "token"),
                 ("snmp_v3", "auth_password"), ("snmp_v3", "priv_password"),
                 ("oidc", "client_secret"), ("push", "url"), ("branch", "token"))


def public_view():
    """Config with secrets masked, for the dashboard."""
    cfg = copy.deepcopy(load())
    for section, field in SECRET_FIELDS:
        block = cfg.get(section)
        if not isinstance(block, dict):
            continue
        if block.get(field):
            block[field] = MASK
            block[field + "_set"] = True
        else:
            block[field + "_set"] = False
    return cfg


def drop_masked(patch):
    """Remove masked placeholders from a settings patch so they never overwrite a real secret."""
    for section, field in SECRET_FIELDS:
        block = (patch or {}).get(section)
        if isinstance(block, dict):
            if block.get(field) in (MASK, "******** saved"):
                block.pop(field, None)
            block.pop(field + "_set", None)
    return patch
