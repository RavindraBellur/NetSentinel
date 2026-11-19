"""Monthly SLA report, as a PDF, built from the history this console already keeps.

One page of numbers an owner or an ISP can read: availability, incidents, MTTR, latency,
packet loss, host disk trends, Wi-Fi retries and the security score. No dependencies.
"""

from __future__ import annotations

import calendar
import datetime
import os
import time

from . import settings, store
from .pdf import Doc


def month_range(month=None):
    """'2026-11' -> (start_ts, end_ts, label). Default: the previous whole month."""
    today = datetime.date.today()
    if month:
        year, mon = (int(x) for x in month.split("-")[:2])
    else:
        first = today.replace(day=1)
        prev = first - datetime.timedelta(days=1)
        year, mon = prev.year, prev.month
    start = datetime.datetime(year, mon, 1)
    days = calendar.monthrange(year, mon)[1]
    end = start + datetime.timedelta(days=days)
    label = start.strftime("%B %Y")
    return int(start.timestamp()), int(end.timestamp()), label


def _duration(seconds):
    seconds = int(max(0, seconds))
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m"
    hours, rest = divmod(seconds, 3600)
    if hours < 24:
        return f"{hours}h {rest // 60:02d}m"
    return f"{hours // 24}d {hours % 24}h"


def collect(start, end):
    """Everything the report needs, from samples and incidents in the window."""
    rows = store._exec(
        "SELECT ip, ts, state, latency_ms, loss_pct FROM samples WHERE ts>=? AND ts<?"
        " ORDER BY ts", (start, end), fetch=True) or []
    devices = {d["ip"]: d for d in store.known_devices(500)}
    per = {}
    for row in rows:
        ip = row["ip"]
        entry = per.setdefault(ip, {"total": 0, "up": 0, "lat": [], "loss": []})
        entry["total"] += 1
        if (row["state"] or "") == "up":
            entry["up"] += 1
        if row["latency_ms"] is not None:
            entry["lat"].append(row["latency_ms"])
        if row["loss_pct"] is not None:
            entry["loss"].append(row["loss_pct"])

    incidents = [i for i in store.incidents(500)
                 if start <= int(i.get("opened_ts") or 0) < end]
    closed = [i for i in incidents if i.get("closed_ts")]
    durations = [int(i["closed_ts"]) - int(i["opened_ts"]) for i in closed
                 if i.get("closed_ts") and i.get("opened_ts")]
    mttr = sum(durations) / len(durations) if durations else 0

    total_samples = sum(e["total"] for e in per.values())
    up_samples = sum(e["up"] for e in per.values())
    availability = (100.0 * up_samples / total_samples) if total_samples else 0.0

    table = []
    for ip, entry in per.items():
        lat = sorted(entry["lat"])
        p95 = lat[int(len(lat) * 0.95) - 1] if lat else 0
        device = devices.get(ip) or {}
        table.append({
            "ip": ip,
            "name": device.get("label") or device.get("last_type") or ip,
            "uptime": 100.0 * entry["up"] / entry["total"] if entry["total"] else 0.0,
            "avg_lat": (sum(entry["lat"]) / len(entry["lat"])) if entry["lat"] else 0.0,
            "p95": p95,
            "loss": (sum(entry["loss"]) / len(entry["loss"])) if entry["loss"] else 0.0,
            "incidents": sum(1 for i in incidents if i.get("device_ip") == ip),
        })
    table.sort(key=lambda r: r["uptime"])

    return {
        "availability": availability,
        "samples": total_samples,
        "devices": len(per),
        "incidents": incidents,
        "closed": len(closed),
        "open_at_end": len(incidents) - len(closed),
        "mttr": mttr,
        "longest": max(durations) if durations else 0,
        "table": table,
        "hosts": store.host_history(None, hours=int((end - start) / 3600) + 24),
    }


def rolling_summary(days=31):
    """A compact summary a branch can send to the hub on every report."""
    end = int(time.time())
    start = end - days * 86400
    rows = store._exec(
        "SELECT ip, state, latency_ms, loss_pct FROM samples WHERE ts>=?", (start,),
        fetch=True) or []
    per = {}
    for row in rows:
        entry = per.setdefault(row["ip"], {"total": 0, "up": 0, "lat": []})
        entry["total"] += 1
        if (row["state"] or "") == "up":
            entry["up"] += 1
        if row["latency_ms"] is not None:
            entry["lat"].append(row["latency_ms"])
    incidents = [i for i in store.incidents(300) if int(i.get("opened_ts") or 0) >= start]
    closed = [i for i in incidents if i.get("closed_ts")]
    durations = [int(i["closed_ts"]) - int(i["opened_ts"]) for i in closed
                 if i.get("closed_ts") and i.get("opened_ts")]
    total = sum(e["total"] for e in per.values())
    up = sum(e["up"] for e in per.values())
    devices = []
    for ip, entry in per.items():
        lat = sorted(entry["lat"])
        devices.append({"ip": ip,
                        "uptime": round(100.0 * entry["up"] / entry["total"], 2) if entry["total"] else 0,
                        "avg_lat": round(sum(lat) / len(lat), 1) if lat else 0,
                        "p95": round(lat[int(len(lat) * 0.95) - 1], 1) if lat else 0})
    devices.sort(key=lambda d: d["uptime"])
    return {"days": days,
            "availability": round(100.0 * up / total, 2) if total else None,
            "samples": total, "devices": len(per),
            "incidents": len(incidents), "resolved": len(closed),
            "mttr": int(sum(durations) / len(durations)) if durations else 0,
            "longest": max(durations) if durations else 0,
            "worst": devices[:5], "ts": end}


def fleet(out_dir="reports", month=None):
    """One PDF per hotel, built on the hub from the summaries the branches send."""
    from . import sites as sites_mod
    start, end, label = month_range(month)
    overview = sites_mod.hub_overview(None)
    rows = [b for b in (overview.get("branches") or []) if (b.get("kind") or "hotel") == "hotel"]
    os.makedirs(out_dir, exist_ok=True)
    written = []
    for branch in rows:
        data = branch.get("sla") or {}
        doc = Doc()
        doc.text(doc.margin, doc.y - 26, "NetSentinel", 20, True, 0.16)
        doc.text(doc.margin, doc.y - 44, "Monthly service report", 11, False, 0.4)
        doc.y -= 60
        doc.line(doc.margin, doc.y, doc.margin + doc.width, doc.y, 0.6, 1.2)
        doc.space(12)
        doc.text(doc.margin, doc.y - 12, branch.get("name") or "site", 14, True, 0.1)
        doc.text(doc.margin, doc.y - 28, label, 10, False, 0.35)
        doc.space(26)
        doc.heading("Summary")
        rows_tbl = [
            ["Availability (last %s days)" % data.get("days", 31),
             (f"{data['availability']:.2f}%" if data.get("availability") is not None else "no data")],
            ["Devices monitored", str(data.get("devices", 0))],
            ["Incidents", f"{data.get('incidents', 0)} ({data.get('resolved', 0)} resolved)"],
            ["Mean time to resolve", _duration(data.get("mttr", 0)) if data.get("mttr") else "n/a"],
            ["Longest outage", _duration(data.get("longest", 0)) if data.get("longest") else "none"],
            ["Version reporting", branch.get("version") or "-"],
            ["Last report received", f"{branch.get('age', 0)} s before this was generated"],
        ]
        doc.table(["Measure", "Value"], rows_tbl, [0.62, 0.38], size=9)
        worst = data.get("worst") or []
        if worst:
            doc.heading("Weakest devices")
            doc.table(["Device", "Uptime", "Avg latency", "95th pct"],
                      [[w["ip"], f"{w['uptime']:.2f}%", f"{w['avg_lat']:.0f} ms",
                        f"{w['p95']:.0f} ms"] for w in worst],
                      [0.4, 0.2, 0.2, 0.2], size=9)
        doc.space(8)
        doc.para("Collected at head office from the reports this site sends every few minutes. "
                 "Availability is the share of the site's own polls that answered over the "
                 "last 31 days; the per-device detail lives on that site's console.", 9,
                 grey=0.3)
        safe = "".join(c if c.isalnum() or c in " -_" else "-"
                       for c in (branch.get("name") or "site")).strip().replace(" ", "-")
        path = os.path.join(out_dir, f"NetSentinel-SLA-{safe}-{label.replace(' ', '-')}.pdf")
        with open(path, "wb") as fh:
            fh.write(doc.build())
        written.append(path)
    return written


def render(month=None, site=None, out_dir="reports"):
    """Write the PDF and return its path."""
    cfg = settings.load()
    site = site or cfg.get("site_name") or "NetSentinel site"
    start, end, label = month_range(month)
    data = collect(start, end)

    doc = Doc()
    # ---- cover block
    doc.text(doc.margin, doc.y - 26, "NetSentinel", 22, True, 0.16)
    doc.text(doc.margin, doc.y - 44, "Monthly service report", 12, False, 0.4)
    doc.y -= 64
    doc.line(doc.margin, doc.y, doc.margin + doc.width, doc.y, 0.6, 1.2)
    doc.space(14)
    doc.text(doc.margin, doc.y - 12, site, 15, True, 0.1)
    doc.text(doc.margin, doc.y - 28, label, 11, False, 0.35)
    doc.text(doc.margin + doc.width - 150, doc.y - 12,
             "Generated " + time.strftime("%d/%m/%Y %H:%M"), 8, False, 0.5)
    doc.space(34)

    # ---- headline numbers
    doc.heading("Summary")
    doc.table(["Measure", "Value"], [
        ["Availability", f"{data['availability']:.2f}%"],
        ["Devices monitored", str(data["devices"])],
        ["Incidents opened", str(len(data["incidents"]))],
        ["Incidents resolved", str(data["closed"])],
        ["Mean time to resolve", _duration(data["mttr"]) if data["mttr"] else "n/a"],
        ["Longest outage", _duration(data["longest"]) if data["longest"] else "none"],
    ], [0.62, 0.38], size=9)
    if not data["samples"]:
        doc.para("No monitoring samples fall inside this month, so availability could not "
                 "be measured. Start the console with --monitor to collect them.",
                 9, grey=0.35)

    # ---- per device
    if data["table"]:
        doc.heading("Devices")
        rows = []
        for r in data["table"][:22]:
            rows.append([r["name"][:26], f"{r['uptime']:.2f}%", f"{r['avg_lat']:.0f} ms",
                         f"{r['p95']:.0f} ms", f"{r['loss']:.1f}%", str(r["incidents"])])
        doc.table(["Device", "Uptime", "Avg latency", "95th pct", "Loss", "Incidents"],
                  rows, [0.34, 0.14, 0.15, 0.14, 0.1, 0.13], size=8.5)

    # ---- incidents
    doc.heading("Incidents")
    if data["incidents"]:
        rows = []
        for inc in data["incidents"][:18]:
            opened = datetime.datetime.fromtimestamp(int(inc.get("opened_ts") or 0))
            closed_ts = inc.get("closed_ts")
            length = (int(closed_ts) - int(inc.get("opened_ts") or 0)) if closed_ts else None
            rows.append([opened.strftime("%d/%m %H:%M"),
                         (inc.get("severity") or "")[:8],
                         (inc.get("device_name") or inc.get("device_ip") or "")[:20],
                         _duration(length) if length is not None else "open",
                         (inc.get("title") or "")[:46]])
        doc.table(["Opened", "Severity", "Device", "Duration", "What happened"],
                  rows, [0.15, 0.12, 0.22, 0.13, 0.38], size=8.5)
    else:
        doc.para("No incident was opened in this month.", 9, grey=0.35)

    # ---- disk trend from the agents
    if data["hosts"]:
        by_ip = {}
        for row in data["hosts"]:
            by_ip.setdefault(row["ip"], []).append(row)
        doc.heading("Host disk usage")
        for ip, series in list(by_ip.items())[:6]:
            latest = series[-1]
            worst = max((r["disk_pct"] or 0) for r in series)
            doc.bar(ip, (worst or 0) / 100.0, f"{worst:.0f}% peak, {latest['disk_pct']:.0f}% now",
                    size=8.5, colour=0.55 if (worst or 0) < 90 else 0.15)

    # ---- Wi-Fi and security, if this console has them
    try:
        from . import wifi as wifi_mod
        devices = list(store.known_devices(500))
        summary = wifi_mod.summary([{"ip": d["ip"], "type": d.get("last_type"),
                                     "label": d.get("label")} for d in devices])
        if summary.get("measured"):
            doc.heading("Wi-Fi")
            for row in summary["measured"][:8]:
                doc.bar(f"{row['ap']} radio {row['radio']}", row["retry_pct"] / 100.0,
                        f"{row['retry_pct']:.0f}% retry", size=8.5,
                        colour=0.2 if row["verdict"] == "poor" else 0.55)
    except Exception:
        pass

    # ---- footer on every page
    doc.new_page()
    doc.heading("How these numbers were measured")
    doc.para("Availability is the share of monitoring polls that answered inside the month, "
             "across every device being monitored. A device that is switched off for a week "
             "counts as unavailable. Latency and loss come from the same polls; the 95th "
             "percentile is the value that 95% of polls were better than, which is a fairer "
             "picture than an average when the line is mostly good with occasional stalls.",
             9, grey=0.25)
    doc.para("Incidents are opened automatically when a device fails enough consecutive "
             "polls, and closed when it recovers or when someone acknowledges them. Mean time "
             "to resolve covers resolved incidents only.", 9, grey=0.25)
    doc.para("Disk figures come from the host agents (run.bat --agent on a server). Wi-Fi "
             "retry rates come from the standard IEEE802dot11 counters on the access points.",
             9, grey=0.25)
    doc.space(10)
    doc.text(doc.margin, doc.y - 9, "NetSentinel - LAN discovery, monitoring and multi-site network console",
             8, False, 0.5)

    os.makedirs(out_dir, exist_ok=True)
    safe = "".join(c if c.isalnum() or c in " -_" else "-" for c in site).strip().replace(" ", "-")
    path = os.path.join(out_dir, f"NetSentinel-SLA-{safe}-{start and datetime.datetime.fromtimestamp(start).strftime('%Y-%m')}.pdf")
    with open(path, "wb") as fh:
        fh.write(doc.build())
    return path
