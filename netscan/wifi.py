"""Wi-Fi health from standard SNMP counters.

Every access point that speaks SNMP exposes the IEEE802dot11 counters per radio interface:
frames transmitted, retries, multiple retries, failures and ACK failures. Their ratios are
the honest measure of whether guests are actually having a good time on the Wi-Fi:

    retry rate   = retries / frames transmitted       (hidden retransmission)
    failure rate = failed  / frames transmitted       (frames given up on)

Above ~10% retries the Wi-Fi is fair, above ~25% it is poor - and that shows up as
"Wi-Fi is slow" complaints long before anything goes offline, which is exactly the gap a
ping-based monitor cannot see.

Counters are cumulative, so a rate is computed between two readings. The first reading only
establishes a baseline.

Client counts are not in a standard MIB. Where the controller or AP exposes one, put its OID
in settings (`wifi.client_oid`) and it will be read too.
"""

from __future__ import annotations

import time

from . import settings, snmp

# IEEE802dot11-MIB dot11CountersTable, indexed by ifIndex
OID_TX_FRAGMENTS = "1.3.6.1.2.1.10.6.1.1.1"
OID_FAILED = "1.3.6.1.2.1.10.6.1.1.3"
OID_RETRY = "1.3.6.1.2.1.10.6.1.1.4"
OID_MULTI_RETRY = "1.3.6.1.2.1.10.6.1.1.5"
OID_RX_FRAGMENTS = "1.3.6.1.2.1.10.6.1.1.10"

_CACHE = {}          # host -> {"ts": float, "counters": {...}, "rates": {...}}
CACHE_SECONDS = 300


def _by_index(host, base, community=None, timeout=1.5):
    """Walk a counter table and return {ifIndex: int}."""
    out = {}
    rows = snmp.walk(host, base, community=community, timeout=timeout)
    for oid, _tag, value in rows:
        try:
            index = oid[len(base) + 1:]
            out[index] = int(value)
        except (ValueError, TypeError):
            continue
    return out


def read(host, community=None, timeout=1.5):
    """One raw reading of the counters for every radio interface."""
    return {
        "tx": _by_index(host, OID_TX_FRAGMENTS, community, timeout),
        "failed": _by_index(host, OID_FAILED, community, timeout),
        "retry": _by_index(host, OID_RETRY, community, timeout),
        "multi": _by_index(host, OID_MULTI_RETRY, community, timeout),
        "rx": _by_index(host, OID_RX_FRAGMENTS, community, timeout),
    }


def rates(previous, current, seconds):
    """Turn two cumulative readings into percentages."""
    out = {}
    if not previous or not current or seconds <= 0:
        return out
    for index, now_tx in current["tx"].items():
        before_tx = previous["tx"].get(index)
        if before_tx is None or now_tx < before_tx:
            continue
        delta_tx = now_tx - before_tx
        if delta_tx <= 0:
            continue
        def delta(key):
            now_v = current[key].get(index)
            old_v = previous[key].get(index)
            if now_v is None or old_v is None or now_v < old_v:
                return 0
            return now_v - old_v
        retry_pct = 100.0 * delta("retry") / delta_tx
        fail_pct = 100.0 * delta("failed") / delta_tx
        multi_pct = 100.0 * delta("multi") / delta_tx
        verdict = "good"
        if retry_pct >= 25 or fail_pct >= 10:
            verdict = "poor"
        elif retry_pct >= 10 or fail_pct >= 4:
            verdict = "fair"
        out[index] = {"retry_pct": round(retry_pct, 1), "fail_pct": round(fail_pct, 1),
                      "multi_pct": round(multi_pct, 1), "frames": delta_tx,
                      "verdict": verdict}
    return out


def poll(device, community=None, force=False):
    """Read an AP, compare with the previous reading, return its Wi-Fi health."""
    host = (device or {}).get("ip")
    if not host:
        return None
    cfg = settings.load().get("wifi") or {}
    if not cfg.get("enabled", True):
        return None
    entry = _CACHE.get(host)
    now = time.time()
    if entry and not force and now - entry["ts"] < CACHE_SECONDS and entry.get("rates"):
        return entry
    try:
        current = read(host, community)
    except Exception:
        return entry
    if not any(current["tx"].values()):
        _CACHE[host] = {"ts": now, "counters": None, "rates": {}, "error": "no dot11 counters"}
        return _CACHE[host]
    prev = (entry or {}).get("counters")
    computed = rates(prev, current, now - entry["ts"]) if entry else {}
    result = {"ts": now, "counters": current, "rates": computed, "host": host,
              "name": device.get("label") or device.get("hostname") or host}
    _CACHE[host] = result
    return result


def summary(devices, community=None):
    """Wi-Fi view for the dashboard: per-AP rates and the worst offenders."""
    aps = [d for d in (devices or []) if (d.get("type") or "") in ("access_point", "wifi", "ap")]
    out = {"access_points": len(aps), "measured": [], "poor": [], "fair": []}
    for dev in aps:
        res = poll(dev, community)
        if not res or not res.get("rates"):
            continue
        for index, r in res["rates"].items():
            row = dict(r, ap=res.get("name"), ip=res.get("host"), radio=index)
            out["measured"].append(row)
            if r["verdict"] == "poor":
                out["poor"].append(row)
            elif r["verdict"] == "fair":
                out["fair"].append(row)
    out["measured"].sort(key=lambda r: -r["retry_pct"])
    out["measured"] = out["measured"][:20]
    return out
