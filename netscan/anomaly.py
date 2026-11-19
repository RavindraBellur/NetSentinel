"""Anomaly detection and capacity forecasting.

Two questions a rules-based monitor cannot answer:

  1. "Is this unusual *for this device at this hour*?" - a 90 ms latency is normal on a
     microwave-linked AP at 8 p.m. and alarming on a cabled switch at 4 a.m. The engine
     keeps a mean and a spread per device per hour-of-day (EWMA), then scores each new
     sample against it.
  2. "When will this break?" - a straight line through the last week of disk or memory
     samples gives "C: full in 9 days", which is actionable in a way that "C: at 87%" is not.

Pure standard library, no numpy, no ML. Everything is explainable: every alert carries the
baseline it was compared against.
"""

from __future__ import annotations

import datetime
import math
import statistics
import threading
import time

from . import settings, store

# how many hours of history feed a baseline
BASELINE_DAYS = 14
MIN_SAMPLES_PER_HOUR = 4
Z_LIMIT = 3.0          # standard deviations from the hour-of-day mean
ABS_FLOOR_MS = 25.0    # never call 5 ms -> 20 ms an anomaly
ABS_FLOOR_PCT = 5.0    # nor a 2% -> 4% loss


class AnomalyEngine:
    """Keeps per-device, per-hour baselines and reports deviations."""

    def __init__(self, log=None):
        self.log = log or (lambda m: None)
        self._lock = threading.RLock()
        self.baselines = {}        # (ip, metric, hour) -> {"mean", "var", "n"}
        self._built = 0.0
        self.recent = []           # last anomalies, newest first
        self.forecasts = []

    # ---------------------------------------------------------------- build --
    def rebuild(self, hours=BASELINE_DAYS * 24):
        """Recompute the baselines from stored samples (cheap: a few thousand rows)."""
        rows = store.latency_history(hours)
        table = {}
        for row in rows:
            try:
                hour = datetime.datetime.fromtimestamp(row["ts"]).hour
            except Exception:
                continue
            for metric, value in (("latency", row.get("latency_ms")),
                                  ("loss", row.get("loss_pct"))):
                if value is None:
                    continue
                key = (row["ip"], metric, hour)
                acc = table.setdefault(key, {"n": 0, "mean": 0.0, "m2": 0.0})
                acc["n"] += 1
                delta = value - acc["mean"]
                acc["mean"] += delta / acc["n"]
                acc["m2"] += delta * (value - acc["mean"])
        with self._lock:
            self.baselines = {}
            for key, acc in table.items():
                n = acc["n"]
                var = (acc["m2"] / (n - 1)) if n > 1 else 0.0
                self.baselines[key] = {"mean": acc["mean"], "var": var, "n": n}
            self._built = time.time()
        return len(self.baselines)

    def _stale(self, max_age=3600):
        return (time.time() - self._built) > max_age

    # ---------------------------------------------------------------- score --
    def score(self, ip, metric, value, when=None):
        """Return (z, baseline) or (None, None) when there is not enough history."""
        if value is None:
            return None, None
        hour = datetime.datetime.fromtimestamp(when or time.time()).hour
        with self._lock:
            base = self.baselines.get((ip, metric, hour))
        if not base or base["n"] < MIN_SAMPLES_PER_HOUR:
            return None, None
        sd = math.sqrt(base["var"]) if base["var"] > 0 else 0.0
        if sd <= 0.0001:
            return None, base
        z = (value - base["mean"]) / sd
        return z, base

    def check_device(self, ip, name, latency, loss, when=None):
        """Anomalies for one device's latest reading."""
        found = []
        z, base = self.score(ip, "latency", latency, when)
        if z is not None and z >= Z_LIMIT and latency >= ABS_FLOOR_MS:
            found.append({
                "kind": "anomaly", "metric": "latency", "ip": ip, "name": name,
                "value": round(latency, 1), "baseline": round(base["mean"], 1),
                "z": round(z, 1), "samples": base["n"],
                "text": (f"{name}: latency {latency:.0f} ms is {z:.0f}σ above the usual "
                         f"{base['mean']:.0f} ms for this hour"),
            })
        z, base = self.score(ip, "loss", loss, when)
        if z is not None and z >= Z_LIMIT and loss >= ABS_FLOOR_PCT:
            found.append({
                "kind": "anomaly", "metric": "loss", "ip": ip, "name": name,
                "value": round(loss, 1), "baseline": round(base["mean"], 1),
                "z": round(z, 1), "samples": base["n"],
                "text": (f"{name}: packet loss {loss:.0f}% against a usual "
                         f"{base['mean']:.0f}% for this hour"),
            })
        return found

    def record(self, anomalies, limit=60):
        if not anomalies:
            return
        stamp = int(time.time())
        with self._lock:
            for item in anomalies:
                item["ts"] = stamp
                self.recent.insert(0, item)
            del self.recent[limit:]
            seen = set()
            for item in anomalies:
                key = (item["ip"], item["metric"])
                if key in seen:
                    continue
                seen.add(key)
                store.add_event(f"anomaly {item['name']}", "medium", item["text"][:300])

    # ------------------------------------------------------------ forecast --
    def forecast(self, warn_days=21):
        """Linear trend on host metrics: when does a disk fill, memory run out."""
        out = []
        rows = store.host_history(None, hours=14 * 24)
        by_ip = {}
        for row in rows:
            by_ip.setdefault(row["ip"], []).append(row)
        now = time.time()
        for ip, series in by_ip.items():
            series.sort(key=lambda r: r["ts"])
            if len(series) < 10:
                continue
            for metric, label in (("disk_pct", "disk"), ("mem_pct", "memory")):
                points = [(r["ts"], r[metric]) for r in series if r.get(metric) is not None]
                if len(points) < 10:
                    continue
                slope, intercept = _linreg(points)
                current = points[-1][1]
                if slope <= 0 or current < 50:
                    continue
                per_day = slope * 86400
                if per_day <= 0.01:
                    continue
                days_left = (100.0 - current) / per_day
                if days_left > 180:
                    continue
                severity = "high" if days_left <= 7 else ("medium" if days_left <= warn_days else "info")
                out.append({
                    "kind": "forecast", "metric": label, "ip": ip,
                    "current_pct": round(current, 1),
                    "per_day": round(per_day, 2),
                    "days_left": round(days_left, 1),
                    "severity": severity,
                    "text": (f"{label} on {ip} is {current:.0f}% and rising "
                             f"{per_day:.2f}%/day - full in about {days_left:.0f} days"),
                })
        out.sort(key=lambda r: r["days_left"])
        self.forecasts = out
        return out

    # ---------------------------------------------------------------- view --
    def view(self, limit=20):
        if self._stale():
            try:
                self.rebuild()
            except Exception:
                pass
        try:
            self.forecast()
        except Exception:
            pass
        with self._lock:
            return {"anomalies": list(self.recent[:limit]),
                    "forecasts": list(self.forecasts[:limit]),
                    "baselines": len(self.baselines),
                    "built_age": int(time.time() - self._built) if self._built else None}


def _linreg(points):
    """Least squares on (x, y) - returns (slope, intercept)."""
    n = len(points)
    mean_x = sum(p[0] for p in points) / n
    mean_y = sum(p[1] for p in points) / n
    num = sum((p[0] - mean_x) * (p[1] - mean_y) for p in points)
    den = sum((p[0] - mean_x) ** 2 for p in points)
    if den == 0:
        return 0.0, mean_y
    slope = num / den
    return slope, mean_y - slope * mean_x
