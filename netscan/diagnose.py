"""Rule-based fault diagnosis.

No AI, no API key, no data leaving the machine: the same reasoning an experienced
network engineer does from the evidence, written down as ordered rules. Every
diagnosis states what it is based on and which data is missing, so a wrong guess
is obvious rather than plausible-sounding.
"""

from __future__ import annotations

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

CATEGORIES = {
    "isp_wan": "Internet / WAN",
    "firewall": "Firewall / Router",
    "wifi": "Wi-Fi",
    "lan_switch": "LAN / Switching",
    "device": "Single device",
    "congestion": "Congestion",
    "power_or_site_down": "Power / site down",
    "monitoring_host": "Monitoring host",
    "unknown": "Unclassified",
}


def _pct(part, whole):
    if not whole:
        return 0
    return round(100.0 * part / whole, 1)


# devices that sleep or answer ping slowly by design; never evidence of congestion by themselves
SLEEPY_TYPES = ("printer", "kot_printer", "scanner", "phone", "iot")


def _sleepy(d):
    return (d.get("type") or "") in SLEEPY_TYPES


def _slow_awake(dev, degraded):
    """Slow devices that are not sleepy, counting the device under diagnosis once."""
    ip = dev.get("ip")
    out = [s for s in degraded if not _sleepy(s) and s.get("ip") != ip]
    if not _sleepy(dev):
        out.append(dev)
    return out


def _congested(dev, degraded, gateway, internet):
    """At least two always-on devices slow at once, or the gateway / internet slow plus one more."""
    slow = _slow_awake(dev, degraded)
    path_slow = gateway.get("state") == "degraded" or any(
        t.get("state") == "degraded" for t in internet)
    return len(slow) >= 2 or (path_slow and len(slow) >= 1)


def diagnose(ctx):
    """ctx keys: device, state, latency, loss, siblings(list), gateway, internet(list),
    events(list), traffic(top talkers), thresholds, data_sources(dict of bool)."""
    dev = ctx.get("device") or {}
    state = ctx.get("state", "unknown")
    latency = ctx.get("latency") or 0
    loss = ctx.get("loss") or 0
    th = ctx.get("thresholds") or {}
    siblings = ctx.get("siblings") or []
    internet = ctx.get("internet") or []
    events = ctx.get("events") or []
    sources = ctx.get("data_sources") or {}
    gateway = ctx.get("gateway") or {}
    traffic = ctx.get("traffic") or []

    dev_type = dev.get("type", "unknown")
    dev_name = dev.get("label") or dev.get("hostname") or dev.get("type_label") or dev.get("ip", "?")
    is_gateway = bool(dev.get("is_gateway")) or dev_type == "router"

    monitored = [s for s in siblings if s.get("monitored")]
    down = [s for s in monitored if s.get("state") == "down"]
    degraded = [s for s in monitored if s.get("state") == "degraded"]
    down_share = _pct(len(down), len(monitored))
    internet_down = [t for t in internet if t.get("state") == "down"]
    internet_up = [t for t in internet if t.get("state") == "up"]

    evidence = []
    actions = []
    gaps = []
    category = "unknown"
    confidence = 40
    impact = ""
    severity = "medium"
    title = f"{dev_name} is {state}"

    if not sources.get("netflow"):
        gaps.append("router flow export (NetFlow/sFlow) is not configured, so bandwidth congestion "
                    "cannot be confirmed or excluded")
    if not sources.get("syslog"):
        gaps.append("no firewall syslog is arriving, so link/ISP events are not visible")
    if not sources.get("snmp"):
        gaps.append("SNMP is not answering on the gateway, so interface errors and WAN state are unknown")

    # -- 1. everything down ------------------------------------------------
    if state == "down" and monitored and len(down) >= max(3, 0.8 * len(monitored)):
        if is_gateway or (gateway.get("state") == "down"):
            category = "power_or_site_down"
            severity = "critical"
            confidence = 75
            title = "Whole site appears down"
            evidence.append(f"{len(down)} of {len(monitored)} monitored devices are unreachable, "
                            f"including the gateway")
            actions += [
                "Check power and the UPS at the site before anything else.",
                "If power is fine, check the core switch and the firewall's status LEDs.",
                "Confirm from outside (mobile data) whether the internet link itself is up.",
            ]
            impact = "The whole office is offline."
        else:
            category = "lan_switch"
            severity = "critical"
            confidence = 65
            title = "Most of the network is unreachable"
            evidence.append(f"{len(down)} of {len(monitored)} devices are down but the gateway answers")
            actions += [
                "Check the core switch and the access switches for a failed uplink.",
                "Check for a spanning-tree loop or broadcast storm (switch CPU high).",
            ]
            impact = "Most users cannot reach anything."

    # -- 2. gateway / firewall down ---------------------------------------
    elif is_gateway and state == "down":
        category = "firewall"
        severity = "critical"
        confidence = 80
        title = "Gateway / firewall is not responding"
        evidence.append("The default gateway itself does not answer ping or a TCP probe")
        if internet_down:
            evidence.append("Internet targets are also unreachable, consistent with the firewall being down")
        actions += [
            "Check the firewall's power, then its WAN and LAN link LEDs.",
            "Console/SSH into the firewall if possible and check interface state and CPU.",
            "If it just rebooted, verify the configuration came back.",
        ]
        impact = "No internet and no routing between VLANs."

    # -- 3. internet path --------------------------------------------------
    elif internet_down and state in ("down", "degraded"):
        category = "isp_wan"
        severity = "high"
        confidence = 70
        title = "Internet path is down or failing"
        evidence.append(f"{len(internet_down)} of {len(internet)} internet targets are unreachable "
                        f"while the gateway answers")
        if internet_up:
            evidence.append("Some internet targets still answer, so the link may be flapping or "
                            "the ISP is partially down")
        actions += [
            "Check the ONT/ISP router status lights; reboot the ONT only if the ISP asks you to.",
            "Look at the firewall WAN interface: is the PPPoE/DHCP lease up? Any interface errors?",
            "Open a ticket with the ISP quoting the times and the packet loss figures.",
            "If a backup link exists, confirm failover happened.",
        ]
        impact = "Internet-dependent work (cloud, UPI, email, CCTV remote view) fails or slows down."

    # -- 4. congestion -----------------------------------------------------
    # Congestion means several things are SLOW at the same time. Devices that are switched off
    # (down) are a different problem, and printers / phones / IoT answer slowly when they wake
    # from power-save, so on their own they never make a congestion verdict.
    elif state == "degraded" and (
        (latency or 0) >= th.get("latency_crit_ms", 300) or (loss or 0) >= th.get("loss_crit_pct", 10)
    ) and _congested(dev, degraded, gateway, internet):
        category = "congestion"
        severity = "medium"
        confidence = 55
        title = "Network is congested"
        slow = _slow_awake(dev, degraded)
        evidence.append(f"{len(slow)} always-on devices show latency above "
                        f"{th.get('latency_warn_ms', 150)} ms or loss above {th.get('loss_warn_pct', 3)}%")
        if gateway.get("state") == "degraded":
            evidence.append("The gateway itself is slow")
        if any(t.get("state") == "degraded" for t in internet):
            evidence.append("Internet targets are slow too")
        if traffic:
            top = traffic[0]
            evidence.append(f"Top talker right now: {top.get('name') or top.get('ip')} "
                            f"at {round((top.get('down_bps', 0) + top.get('up_bps', 0)) / 1e6, 2)} Mbps")
            actions.append(f"Throttle or move {top.get('name') or top.get('ip')} "
                           f"(the biggest consumer) or apply a QoS policy for business traffic.")
        actions += [
            "Compare the WAN rate with the ISP plan; saturation shows as flat-topped throughput.",
            "Check for a backup or Windows Update running during office hours.",
        ]
        impact = "Everything feels slow, calls drop, billing software lags."

    # -- 5. Wi-Fi ----------------------------------------------------------
    elif dev_type == "access_point" and state in ("down", "degraded"):
        category = "wifi"
        severity = "high" if state == "down" else "medium"
        confidence = 65
        title = f"Access point {dev_name} is {state}"
        evidence.append("The access point itself does not answer on its management address")
        others = [s for s in monitored if s.get("type") == "access_point" and s.get("state") == "up"]
        if others:
            evidence.append(f"{len(others)} other access point(s) are healthy, so the controller and "
                            f"core switch are fine")
        actions += [
            "Check the PoE port on the switch (PoE budget or a failed port).",
            "Power-cycle the AP or reseat the cable; check the AP LED pattern.",
            "If it is a mesh/controller AP, check whether it is still adopted.",
        ]
        impact = "Wireless clients in that area lose connectivity or drop to weak signal."

    # -- 6. single device --------------------------------------------------
    elif state == "down":
        category = "device"
        severity = "high" if dev_type in ("dvr", "nvr", "switch", "server") else "medium"
        confidence = 70
        title = f"{dev_name} is down"
        evidence.append("This device does not answer while the rest of the network is reachable")
        if dev_type in ("printer", "kot_printer"):
            actions += ["Check printer power and the paper/toner status on the panel.",
                        "Print a self-test page; check the network cable or Wi-Fi association."]
            impact = "Kitchen/office printing stops."
        elif dev_type in ("dvr", "nvr", "camera"):
            actions += ["Check the DVR/NVR power and the PoE switch port.",
                        "Verify the recorder still writes (look at the HDD LED) before rebooting it."]
            impact = "Recording or live view is lost for that camera/recorder."
        elif dev_type in ("access_point",):
            actions += ["Check the PoE port and the AP's power injector."]
            impact = "Wireless coverage in that area is lost."
        else:
            actions += ["Check power, then the switch port LED for that device.",
                        "Ping from the same VLAN to rule out routing/VLAN changes."]
            impact = "That service is unavailable to users."
        if loss and loss > 0:
            evidence.append(f"Before it went down it was already losing {loss}% of packets, "
                            f"which points at a cable or PoE problem rather than a reboot")

    # -- 7. degraded single device ----------------------------------------
    elif state == "degraded":
        category = "device"
        severity = "low"
        confidence = 50
        title = f"{dev_name} is degraded"
        evidence.append(f"Latency {round(latency, 1)} ms, packet loss {round(loss, 1)}%")
        actions += [
            "Check the cable and the switch port for errors (CRC/collisions).",
            "If it is wireless, check signal strength and channel interference.",
        ]
        impact = "Slower responses; may escalate."

    if not evidence:
        evidence.append(f"State is {state}; latency {round(latency, 1)} ms, loss {round(loss, 1)}%")

    # -- syslog correlation (any category) --------------------------------
    relevant = []
    for ev in events[:40]:
        text = (ev.get("message") or "").lower()
        if any(k in text for k in ("link down", "interface down", "gateway dead", "vpn down",
                                   "failover", "ipsec", "pppoe", "cpu", "memory", "temperature")):
            relevant.append(ev)
    if relevant:
        confidence = min(95, confidence + 10)
        for ev in relevant[:3]:
            evidence.append(f"firewall log: {ev.get('message', '')[:140]}")
        actions.insert(0, "Read the matching firewall log lines above - they usually name the "
                          "interface or peer that failed.")

    if not sources.get("netflow") and category == "congestion":
        confidence = max(30, confidence - 15)

    return {
        "category": category,
        "category_label": CATEGORIES.get(category, category),
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "root_cause": evidence[0] if evidence else "",
        "evidence": evidence,
        "recommended_actions": actions[:6],
        "user_impact": impact,
        "data_gaps": gaps[:4],
        "needs_onsite_visit": category in ("power_or_site_down", "lan_switch") or state == "down",
        "engine": "rules",
    }


def escalate(severity, steps=1):
    order = ["info", "low", "medium", "high", "critical"]
    try:
        idx = min(len(order) - 1, order.index(severity) + steps)
    except ValueError:
        idx = 2
    return order[idx]


def at_least(severity, minimum):
    return SEVERITY_ORDER.get(severity, 0) >= SEVERITY_ORDER.get(minimum, 0)
