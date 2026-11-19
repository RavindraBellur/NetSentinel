"""Topology map from LLDP and CDP.

Switches and access points announce their neighbours: which port they are on, what is on the
other end, and what that device calls itself. Walking those tables gives a real map of the
building - core switch, floor switches, access points, and where each one is plugged in -
without any configuration.

LLDP (IEEE 802.1AB) is the standard; CDP is Cisco's older equivalent, and many Cisco devices
answer both, so the two are merged and duplicates are dropped.
"""

from __future__ import annotations

import time

from . import snmp

# IEEE 802.1AB LLDP-MIB
LLDP_LOC_PORT_ID = "1.0.8802.1.1.2.1.3.7.1.3"
LLDP_REM_CHASSIS_SUBTYPE = "1.0.8802.1.1.2.1.4.1.1.4"
LLDP_REM_CHASSIS_ID = "1.0.8802.1.1.2.1.4.1.1.5"
LLDP_REM_PORT_ID = "1.0.8802.1.1.2.1.4.1.1.7"
LLDP_REM_PORT_DESC = "1.0.8802.1.1.2.1.4.1.1.8"
LLDP_REM_SYS_NAME = "1.0.8802.1.1.2.1.4.1.1.9"
LLDP_REM_SYS_DESC = "1.0.8802.1.1.2.1.4.1.1.10"

# CISCO-CDP-MIB
CDP_DEVICE_ID = "1.3.6.1.4.1.9.9.23.1.2.1.1.6"
CDP_DEVICE_PORT = "1.3.6.1.4.1.9.9.23.1.2.1.1.7"
CDP_PLATFORM = "1.3.6.1.4.1.9.9.23.1.2.1.1.8"

_CACHE = {"ts": 0, "graph": None}
CACHE_SECONDS = 600


def _table(host, base, community=None, timeout=1.2):
    """{suffix: value} for one table."""
    out = {}
    for oid, _tag, value in snmp.walk(host, base, community=community, timeout=timeout):
        if oid.startswith(base + "."):
            out[oid[len(base) + 1:]] = value
    return out


def _norm_chassis(value, subtype=None):
    """Chassis ids arrive as MAC, string or local id - normalise to something comparable."""
    text = str(value or "").strip()
    if not text:
        return ""
    hexish = text.replace(" ", "").replace("-", ":").lower()
    parts = hexish.split(":")
    if len(parts) == 6 and all(len(p) == 2 for p in parts):
        return hexish
    return text.lower()


def neighbours(host, community=None, timeout=1.2):
    """Everything one device knows about its neighbours (LLDP and CDP merged)."""
    found = []
    local_ports = _table(host, LLDP_LOC_PORT_ID, community, timeout)

    # ---- LLDP
    chassis_id = _table(host, LLDP_REM_CHASSIS_ID, community, timeout)
    sys_name = _table(host, LLDP_REM_SYS_NAME, community, timeout)
    port_id = _table(host, LLDP_REM_PORT_ID, community, timeout)
    port_desc = _table(host, LLDP_REM_PORT_DESC, community, timeout)
    sys_desc = _table(host, LLDP_REM_SYS_DESC, community, timeout)
    for suffix, remote_chassis in chassis_id.items():
        parts = suffix.split(".")
        local_port = parts[-2] if len(parts) >= 2 else ""
        found.append({
            "protocol": "lldp",
            "local_port": local_ports.get(local_port) or f"port {local_port}",
            "remote_name": str(sys_name.get(suffix) or "").strip(),
            "remote_id": _norm_chassis(remote_chassis),
            "remote_port": str(port_desc.get(suffix) or port_id.get(suffix) or "").strip(),
            "remote_desc": str(sys_desc.get(suffix) or "").strip()[:120],
        })

    # ---- CDP
    cdp_id = _table(host, CDP_DEVICE_ID, community, timeout)
    if cdp_id:
        cdp_port = _table(host, CDP_DEVICE_PORT, community, timeout)
        cdp_platform = _table(host, CDP_PLATFORM, community, timeout)
        for suffix, remote in cdp_id.items():
            name = str(remote or "").strip()
            if any(n["remote_name"].lower() == name.lower() for n in found):
                continue
            found.append({
                "protocol": "cdp",
                "local_port": "if" + suffix.split(".")[0],
                "remote_name": name,
                "remote_id": _norm_chassis(name),
                "remote_port": str(cdp_port.get(suffix) or "").strip(),
                "remote_desc": str(cdp_platform.get(suffix) or "").strip()[:120],
            })
    return found


def build(devices, community=None, max_devices=60):
    """Assemble the whole graph from the devices that answer LLDP or CDP."""
    now = time.time()
    if _CACHE["graph"] and now - _CACHE["ts"] < CACHE_SECONDS:
        return _CACHE["graph"]

    by_ip = {d.get("ip"): d for d in (devices or []) if d.get("ip")}
    by_mac = {}
    by_name = {}
    for dev in (devices or []):
        mac = (dev.get("mac") or "").lower()
        if mac:
            by_mac[mac] = dev
        for key in ("label", "hostname"):
            if dev.get(key):
                by_name[str(dev[key]).strip().lower()] = dev

    nodes = {}
    links = []
    queried = 0
    for dev in (devices or []):
        ip = dev.get("ip")
        if not ip or queried >= max_devices:
            continue
        kind = dev.get("type") or ""
        if kind not in ("router", "switch", "access_point", "firewall", "unknown", "server"):
            continue
        queried += 1
        try:
            found = neighbours(ip, community)
        except Exception:
            continue
        if not found:
            continue
        me = f"ip:{ip}"
        nodes.setdefault(me, {"id": me, "label": dev.get("label") or dev.get("hostname") or ip,
                              "ip": ip, "type": kind, "mac": dev.get("mac") or "",
                              "known": True, "is_gateway": bool(dev.get("is_gateway"))})
        for item in found:
            remote_mac = item["remote_id"]
            remote_name = item["remote_name"]
            target = by_mac.get(remote_mac) or by_name.get(remote_name.lower())
            if target and target.get("ip"):
                tid = f"ip:{target['ip']}"
                nodes.setdefault(tid, {"id": tid,
                                       "label": target.get("label") or target.get("hostname")
                                       or target["ip"],
                                       "ip": target["ip"], "type": target.get("type") or "unknown",
                                       "mac": target.get("mac") or remote_mac, "known": True,
                                       "is_gateway": bool(target.get("is_gateway"))})
            else:
                label = remote_name or remote_mac or "unknown"
                tid = f"ext:{remote_mac or remote_name}"
                nodes.setdefault(tid, {"id": tid, "label": label, "ip": "",
                                       "type": "switch" if "switch" in
                                       (item["remote_desc"] or "").lower() else "unknown",
                                       "mac": remote_mac, "known": False,
                                       "is_gateway": False})
            seen = any((l["a"] == tid and l["b"] == me) or (l["a"] == me and l["b"] == tid)
                       for l in links)
            if tid != me and not seen:
                links.append({"a": me, "b": tid, "a_port": item["local_port"],
                              "b_port": item["remote_port"], "protocol": item["protocol"]})

    # depth from the gateway (or the busiest node) so the map reads top-down
    adj = {}
    for link in links:
        adj.setdefault(link["a"], []).append(link["b"])
        adj.setdefault(link["b"], []).append(link["a"])
    root = next((n["id"] for n in nodes.values() if n["is_gateway"]), None)
    if not root and adj:
        root = max(adj, key=lambda k: len(adj[k]))
    depth = {}
    if root:
        queue = [(root, 0)]
        while queue:
            node, d = queue.pop(0)
            if node in depth:
                continue
            depth[node] = d
            for nxt in adj.get(node, []):
                if nxt not in depth:
                    queue.append((nxt, d + 1))
    for node_id, node in nodes.items():
        node["depth"] = depth.get(node_id, 0)

    graph = {"nodes": list(nodes.values()), "links": links,
             "stats": {"devices": len(nodes), "links": len(links), "queried": queried,
                       "root": root},
             "ts": int(now)}
    _CACHE.update({"ts": now, "graph": graph})
    return graph


def summary(devices, community=None):
    graph = build(devices, community)
    return {"devices": graph["stats"]["devices"], "links": graph["stats"]["links"],
            "ts": graph["ts"]}
