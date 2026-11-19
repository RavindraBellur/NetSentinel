"""Plain-text report, for the console and for /api/report.txt."""

from __future__ import annotations


def _fmt_bps(v):
    if not v or v < 1:
        return "0"
    units = ["bps", "Kbps", "Mbps", "Gbps"]
    i = 0
    n = float(v)
    while n >= 1000 and i < len(units) - 1:
        n /= 1000
        i += 1
    return f"{n:.1f} {units[i]}" if n < 10 else f"{n:.0f} {units[i]}"


def text_report(snap, width=110):
    loc = snap.get("local") or {}
    pub = snap.get("public") or {}
    devices = snap.get("devices") or []
    counts = snap.get("counts") or {}
    health = snap.get("health") or {}
    incidents = snap.get("incidents") or []
    out = []
    line = "=" * width
    out.append(line)
    out.append("Prahari - local network report".center(width))
    out.append(line)
    out.append(f"Generated        : {snap.get('status', {}).get('last_scan') or 'scanning'}")
    out.append(f"This computer    : {loc.get('ip','?')}  (adapter {loc.get('adapter','?')}, MAC {loc.get('mac') or 'n/a'})")
    out.append(f"Local network    : {loc.get('network','?')}/{loc.get('prefix','?')}  mask {loc.get('mask','?')}")
    out.append(f"Gateway / router : {loc.get('gateway') or 'not detected'}")
    out.append(f"DNS servers      : {', '.join(loc.get('dns') or []) or 'n/a'}")
    pub_line = pub.get("ip") or "not reachable"
    if pub.get("isp"):
        pub_line += f"   ({pub.get('isp')}"
        extra = ", ".join(x for x in (pub.get("city"), pub.get("country")) if x)
        pub_line += f" - {extra})" if extra else ")"
    out.append(f"Public IP        : {pub_line}")
    wan = snap.get("wan_rate") or {}
    if wan.get("rx_bps"):
        out.append(f"WAN throughput   : {_fmt_bps(wan.get('rx_bps'))} down / {_fmt_bps(wan.get('tx_bps'))} up  [{wan.get('source')}]")
    out.append("")
    summary = ", ".join(
        f"{counts[t]} {label}"
        for t, label in (
            ("router", "router"), ("switch", "switch"), ("access_point", "access point"),
            ("kot_printer", "KOT printer"), ("printer", "printer"), ("scanner", "scanner"),
            ("dvr", "DVR"), ("nvr", "NVR"), ("camera", "camera"),
        )
        if counts.get(t)
    )
    out.append(f"Devices found    : {counts.get('total', len(devices))}   {summary}")
    if health:
        out.append(f"Health           : {health.get('score', 0)}%  "
                   f"({health.get('up', 0)} up, {health.get('degraded', 0)} degraded, "
                   f"{health.get('down', 0)} down of {health.get('monitored', 0)} monitored)")
    open_inc = [i for i in incidents if i.get("state") != "resolved"]
    if open_inc:
        out.append("")
        out.append(f"OPEN INCIDENTS ({len(open_inc)})")
        for inc in open_inc[:10]:
            d = inc.get("diagnosis") or {}
            out.append(f"  [{inc.get('severity', '').upper():<8}] {inc.get('title', '')[:60]}")
            out.append(f"           {inc.get('device_name', '')} ({inc.get('device_ip', '')}) "
                       f"opened {inc.get('opened_human', '')}")
            if d.get("root_cause"):
                out.append(f"           cause: {d['root_cause'][:90]}  "
                           f"[{d.get('confidence', 0)}% {d.get('category_label', '')}]")
            for action in (d.get("recommended_actions") or [])[:2]:
                out.append(f"           do: {action[:90]}")
    out.append("")

    header = (f"{'TYPE':<22}{'IP':<16}{'MAC':<18}{'NAME / VENDOR':<24}{'STATE':<9}"
              f"{'LATENCY':>8} {'PORTS':<13}{'DOWN':>8}{'UP':>8}")
    out.append(header)
    out.append("-" * width)
    for d in devices:
        ports = ",".join(str(p["port"]) for p in (d.get("ports") or [])[:5])
        if len(d.get("ports") or []) > 5:
            ports += ",+"
        name = d.get("label") or d.get("hostname") or d.get("vendor") or d.get("snmp_name") or ""
        latency = d.get("latency_ms") or 0
        out.append(
            f"{d.get('type_label','')[:21]:<22}{d.get('ip',''):<16}{(d.get('mac') or '-'):<18}"
            f"{name[:23]:<24}{(d.get('state') or '-')[:8]:<9}"
            f"{(str(round(latency,1))+'ms' if latency else '-'):>8} "
            f"{ports[:12]:<13}{_fmt_bps(d.get('rx_bps')):>8}{_fmt_bps(d.get('tx_bps')):>8}"
        )
        ev = "; ".join((d.get("evidence") or [])[:3])
        if ev:
            out.append(f"{'':<20}{'':<16}why: {ev[:width - 22]}")
    out.append("-" * width)

    talkers = [d for d in devices if (d.get("rx_bps") or 0) + (d.get("tx_bps") or 0) > 0]
    talkers.sort(key=lambda d: -((d.get("rx_bps") or 0) + (d.get("tx_bps") or 0)))
    if talkers:
        out.append("")
        out.append("Top bandwidth users right now")
        for d in talkers[:8]:
            total = (d.get("rx_bps") or 0) + (d.get("tx_bps") or 0)
            label = d.get("label") or d.get("hostname") or d.get("type_label")
            out.append(f"  {d.get('ip',''):<16}{label[:34]:<36}{_fmt_bps(total):>10}   [{d.get('rate_source','')}]")
    else:
        out.append("")
        out.append("No per-device traffic counters yet.")
        out.append("  Best: export NetFlow v5/v9, IPFIX or sFlow from the router to this PC")
        out.append("        (UDP 2055 / 6343) - then this list shows real per-device usage.")
        out.append("  Or: enable SNMP (community 'public') on the router/switch for per-port usage,")
        out.append("  or install Npcap and run Prahari as Administrator for passive capture.")

    notes = snap.get("warnings") or []
    cap = snap.get("capture") or {}
    if cap.get("error"):
        notes = list(notes) + [cap["error"]]
    if notes:
        out.append("")
        out.append("Notes")
        for n in notes:
            out.append("  - " + n)
    out.append("")
    out.append("Confidence: 'high' = several independent signals agree. Verify anything you plan to act on.")
    out.append(line)
    return "\n".join(out) + "\n"
