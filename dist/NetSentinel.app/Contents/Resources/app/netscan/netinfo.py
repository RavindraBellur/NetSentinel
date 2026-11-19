"""Local network facts: my IP, subnet, gateway, DNS, MAC and public IP.

Standard library only. Works on Windows, Linux and macOS.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import urllib.request

IS_WINDOWS = os.name == "nt"
_CREATE_NO_WINDOW = 0x08000000 if IS_WINDOWS else 0


def run(cmd, timeout=12):
    """Run a command and return its combined output (never raises)."""
    try:
        p = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            errors="ignore",
            creationflags=_CREATE_NO_WINDOW,
        )
        return (p.stdout or "") + (p.stderr or "")
    except Exception:
        return ""


def primary_ipv4():
    """Best guess at the LAN address of this machine."""
    for probe in ("8.8.8.8", "1.1.1.1", "9.9.9.9"):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.settimeout(0.6)
            s.connect((probe, 53))
            ip = s.getsockname()[0]
            if ip and not ip.startswith("127."):
                return ip
        except Exception:
            pass
        finally:
            try:
                s.close()
            except Exception:
                pass
    try:
        ip = socket.gethostbyname(socket.gethostname())
        if ip and not ip.startswith("127."):
            return ip
    except Exception:
        pass
    return "127.0.0.1"


def _windows_adapters():
    """Parse ipconfig into a list of adapter dicts."""
    out = run(["ipconfig", "/all"])
    adapters = []
    for block in re.split(r"\r?\n(?=[^\s].*adapter [^:]+:)", out):
        if "adapter" not in block:
            continue
        name = block.split("adapter", 1)[1].split(":", 1)[0].strip()
        ip = re.search(r"IPv4 Address[^:]*:\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})", block)
        if not ip:
            continue
        mask = re.search(r"Subnet Mask[^:]*:\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})", block)
        gw = re.search(r"Default Gateway[^:]*:\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})", block)
        dns = []
        dns_block = re.search(r"DNS Servers[^:]*:\s*(.+)", block)
        if dns_block:
            for line in block[dns_block.start():].splitlines()[:6]:
                m = re.search(r"([0-9]{1,3}(?:\.[0-9]{1,3}){3})", line)
                if m and m.group(1) not in dns:
                    dns.append(m.group(1))
        mac = re.search(r"Physical Address[^:]*:\s*([0-9A-Fa-f:-]{17})", block)
        adapters.append(
            {
                "name": name,
                "ip": ip.group(1),
                "mask": mask.group(1) if mask else "255.255.255.0",
                "gateway": gw.group(1) if gw else "",
                "dns": dns,
                "mac": (mac.group(1).replace("-", ":").lower() if mac else ""),
            }
        )
    return adapters


def _linux_adapters():
    adapters = []
    out = run(["ip", "-4", "-o", "addr", "show"])
    routes = run(["ip", "-4", "route", "show", "default"])
    default_gw = ""
    default_dev = ""
    m = re.search(r"default via ([0-9.]+)(?: dev (\S+))?", routes)
    if m:
        default_gw = m.group(1)
        default_dev = m.group(2) or ""
    for line in out.splitlines():
        # 2: eth0    inet 192.168.1.5/24 brd 192.168.1.255 scope global eth0
        m = re.match(r"\d+:\s+(\S+)\s+inet\s+([0-9.]+)/(\d+)", line)
        if not m:
            continue
        iface, ip, prefix = m.group(1), m.group(2), int(m.group(3))
        if iface == "lo" or ip.startswith("127."):
            continue
        mac = ""
        mm = re.search(r"link/ether\s+([0-9a-f:]{17})", run(["ip", "link", "show", iface]))
        if mm:
            mac = mm.group(1)
        gw = default_gw if (not default_dev or default_dev == iface) else ""
        adapters.append(
            {
                "name": iface,
                "ip": ip,
                "mask": str(ipaddress.IPv4Network("0.0.0.0/" + str(prefix)).netmask),
                "gateway": gw,
                "dns": [],
                "mac": mac,
            }
        )
    return adapters


def _darwin_adapters():
    """macOS: route -n get default + ifconfig -a + scutil --dns."""
    adapters = []
    gw, dev = "", ""
    out = run(["route", "-n", "get", "default"])
    m = re.search(r"gateway:\s*([0-9.]+)", out)
    if m:
        gw = m.group(1)
    m = re.search(r"interface:\s*(\S+)", out)
    if m:
        dev = m.group(1)

    dns = []
    for line in run(["scutil", "--dns"]).splitlines():
        m = re.search(r"nameserver\[\d+\] : ([0-9.]+)", line)
        if m and m.group(1) not in dns:
            dns.append(m.group(1))

    text = run(["ifconfig", "-a"])
    for block in re.split(r"\n(?=\w)", text):
        m = re.match(r"(\w+): flags", block)
        if not m:
            continue
        iface = m.group(1)
        if iface.startswith("lo") or iface.startswith("utun") or iface.startswith("gif"):
            continue
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+) netmask (0x[0-9a-f]+)", block)
        if not m:
            continue
        ip = m.group(1)
        if ip.startswith("127."):
            continue
        try:
            mask_int = int(m.group(2), 16)
            mask = str(ipaddress.IPv4Address(mask_int))
            prefix = ipaddress.IPv4Network("0.0.0.0/" + mask).prefixlen
        except Exception:
            mask, prefix = "255.255.255.0", 24
        mm = re.search(r"ether ([0-9a-f:]{17})", block)
        adapters.append({
            "name": iface,
            "ip": ip,
            "mask": mask,
            "gateway": gw if (not dev or dev == iface) else "",
            "dns": dns,
            "mac": mm.group(1) if mm else "",
        })
    return adapters


def local_network(subnet_override=None):
    """Return a dict describing the LAN this machine sits on."""
    my_ip = primary_ipv4()
    adapters = []
    try:
        if IS_WINDOWS:
            adapters = _windows_adapters()
        elif sys.platform == "darwin":
            adapters = _darwin_adapters()
        else:
            adapters = _linux_adapters()
    except Exception:
        adapters = []

    chosen = None
    for a in adapters:
        if a.get("ip") == my_ip:
            chosen = a
            break
    if chosen is None and adapters:
        # prefer an adapter that has a gateway
        with_gw = [a for a in adapters if a.get("gateway")]
        chosen = with_gw[0] if with_gw else adapters[0]
    if chosen is None:
        chosen = {"name": "?", "ip": my_ip, "mask": "255.255.255.0", "gateway": "", "dns": [], "mac": ""}

    ip = chosen["ip"]
    mask = chosen.get("mask") or "255.255.255.0"
    try:
        net = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
    except Exception:
        net = ipaddress.IPv4Network(f"{ip}/24", strict=False)

    if subnet_override:
        try:
            net = ipaddress.IPv4Network(subnet_override, strict=False)
        except Exception:
            pass

    hosts = list(net.hosts())
    truncated = False
    if len(hosts) > 1024:
        hosts = hosts[:1024]
        truncated = True

    gw = chosen.get("gateway") or ""
    if not gw and hosts:
        # common convention fallback
        try:
            gw = str(net.network_address + 1)
        except Exception:
            gw = ""

    return {
        "ip": ip,
        "mask": mask,
        "prefix": net.prefixlen,
        "network": str(net),
        "netmask": str(net.netmask),
        "broadcast": str(net.broadcast_address),
        "gateway": gw,
        "dns": chosen.get("dns") or [],
        "mac": chosen.get("mac") or "",
        "adapter": chosen.get("name") or "",
        "host_count": len(hosts),
        "truncated": truncated,
        "subnet": str(net),
        "adapters": adapters,
    }


def _fetch_json(url, timeout=5):
    req = urllib.request.Request(
        url, headers={"User-Agent": "NetSentinel/1.0", "Accept": "application/json,text/plain,*/*"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read(200000).decode("utf-8", "replace")


def public_ip(timeout=5):
    """Ask a couple of public services for the WAN address. Never raises."""
    result = {
        "ip": "",
        "isp": "",
        "city": "",
        "region": "",
        "country": "",
        "source": "",
        "error": "",
    }
    try:
        data = json.loads(_fetch_json("https://ipinfo.io/json", timeout))
        if data.get("ip"):
            result.update(
                ip=data.get("ip", ""),
                isp=data.get("org", ""),
                city=data.get("city", ""),
                region=data.get("region", ""),
                country=data.get("country", ""),
                source="ipinfo.io",
            )
            return result
    except Exception:
        pass
    for url, key in (
        ("https://api.ipify.org?format=json", "ip"),
        ("https://ifconfig.me/all.json", "ip_addr"),
        ("https://api.my-ip.io/v2/ip.json", "ip"),
        ("https://ipapi.co/json/", "ip"),
        ("https://api64.ipify.org?format=json", "ip"),
    ):
        try:
            data = json.loads(_fetch_json(url, timeout))
            ip = data.get(key) or ""
            if ip:
                result.update(ip=ip, source=url.split("/")[2])
                return result
        except Exception:
            continue
    try:
        txt = _fetch_json("https://api.ipify.org", timeout).strip()
        if re.match(r"^[0-9.]+$", txt):
            result.update(ip=txt, source="api.ipify.org")
            return result
    except Exception as e:
        result["error"] = "public IP lookup failed (no internet or a firewall is blocking it): " + str(e)[:120]
    return result


def arp_table():
    """Return {ip: mac} from the OS ARP cache."""
    table = {}
    if IS_WINDOWS:
        out = run(["arp", "-a"])
        for line in out.splitlines():
            m = re.search(r"([0-9]{1,3}(?:\.[0-9]{1,3}){3})\s+([0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5})", line)
            if m:
                table[m.group(1)] = m.group(2).replace("-", ":").lower()
    else:
        out = run(["ip", "neigh"]) or run(["arp", "-n"])
        for line in out.splitlines():
            m = re.search(r"([0-9]{1,3}(?:\.[0-9]{1,3}){3}).*?([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})", line)
            if m:
                table[m.group(1)] = m.group(2).lower()
    return table


def pc_interface_rates():
    """Throughput of this PC's own network cards, if psutil is present."""
    try:
        import psutil  # type: ignore
    except Exception:
        return {"available": False, "interfaces": []}
    try:
        import time

        first = psutil.net_io_counters(pernic=True)
        time.sleep(1.0)
        second = psutil.net_io_counters(pernic=True)
        out = []
        for nic, c2 in second.items():
            c1 = first.get(nic)
            if not c1 or nic.lower().startswith("lo"):
                continue
            rx = c2.bytes_recv - c1.bytes_recv
            tx = c2.bytes_sent - c1.bytes_sent
            if rx == 0 and tx == 0:
                continue
            out.append({"name": nic, "rx_bps": rx, "tx_bps": tx})
        return {"available": True, "interfaces": out}
    except Exception:
        return {"available": False, "interfaces": []}
