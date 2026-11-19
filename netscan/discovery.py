"""Active discovery: ping sweep, ARP harvest, TCP port scan and banner probes."""

from __future__ import annotations

import os
import re
import socket
import ssl
import struct
import sys
from concurrent.futures import ThreadPoolExecutor

from . import netinfo, snmp

IS_WINDOWS = os.name == "nt"

# port -> service label
PORT_SERVICES = {
    21: "ftp",
    25: "smtp",
    587: "smtp-submission",
    993: "imaps",
    995: "pop3s",
    22: "ssh",
    23: "telnet",
    53: "dns",
    80: "http",
    81: "http-alt",
    137: "netbios",
    139: "netbios-ssn",
    161: "snmp",
    443: "https",
    445: "smb",
    515: "lpd",
    554: "rtsp",
    631: "ipp",
    1883: "mqtt",
    3389: "rdp",
    5000: "http-alt",
    5060: "sip",
    5357: "wsd",
    5900: "vnc",
    7547: "tr-069",
    8000: "hikvision-sdk",
    8001: "http-alt",
    8080: "http-alt",
    8081: "http-alt",
    8443: "https-alt",
    8888: "http-alt",
    9000: "http-alt",
    9100: "jetdirect/raw-print",
    34567: "dvr-client",
    37777: "dahua-sdk",
    6036: "dvr-media",
    1935: "rtmp",
    3702: "wsd-discovery",
}

# UDP services are probed with a real request each (udp_scan); everything else is a TCP connect.
UDP_SERVICES = {123: "ntp", 137: "netbios", 161: "snmp", 1900: "upnp", 5353: "mdns"}
PORT_SERVICES.update({p: n for p, n in UDP_SERVICES.items() if p not in PORT_SERVICES})
TCP_PORTS = sorted(p for p in PORT_SERVICES if p not in UDP_SERVICES and p != 3702)
ALIVE_PORTS = (80, 443, 445, 22, 9100, 8000)
REFUSED_ERRNOS = {10061, 111, 61, 10054}


# ---- liveness ---------------------------------------------------------------


def ping(ip: str, timeout_ms: int = 300) -> bool:
    if IS_WINDOWS:
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), "-4", str(ip)]
    elif sys.platform == "darwin":
        cmd = ["ping", "-c", "1", "-W", str(max(100, timeout_ms)), "-t", "2", str(ip)]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout_ms / 1000))), "-n", str(ip)]
    out = netinfo.run(cmd, timeout=max(3, timeout_ms / 1000 + 2))
    return bool(re.search(r"TTL=\s*\d+", out, re.I))


def tcp_alive(ip: str, ports=ALIVE_PORTS, timeout: float = 0.25) -> bool:
    """A refused connection still proves the host is up (and fills the ARP cache)."""
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.settimeout(timeout)
            rc = s.connect_ex((ip, port))
            if rc == 0 or rc in REFUSED_ERRNOS:
                return True
        except Exception:
            pass
        finally:
            try:
                s.close()
            except Exception:
                pass
    return False


def sweep(network, timeout_ms=300, workers=128, progress=None):
    """Return the list of live IPv4 addresses in the network."""
    hosts = list(network.hosts())[:1024]
    total = len(hosts)
    alive = []

    def work(ip):
        addr = str(ip)
        if ping(addr, timeout_ms):
            return addr
        if tcp_alive(addr):
            return addr
        return None

    done = 0
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for result in ex.map(work, hosts):
            done += 1
            if result:
                alive.append(result)
            if progress and (done % 8 == 0 or done == total):
                progress(done, total, result)
    alive.sort(key=lambda a: tuple(int(x) for x in a.split(".")))
    return alive


# ---- port scanning ----------------------------------------------------------


def port_scan(ip: str, ports=None, timeout: float = 0.35, workers: int = 16):
    ports = list(ports or TCP_PORTS)
    found = []

    def work(port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                return port
        except Exception:
            pass
        finally:
            try:
                s.close()
            except Exception:
                pass
        return None

    with ThreadPoolExecutor(max_workers=workers) as ex:
        for p in ex.map(work, ports):
            if p:
                found.append(p)
    return sorted(found)


# ---- UDP probes ---------------------------------------------------------------
# A closed UDP port usually says nothing, so "no answer" never counts as open: a port is reported
# only when the service itself replies to a well-formed request.

NTP_REQUEST = b"\x1b" + b"\x00" * 47                      # LI=0, VN=3, mode 3 (client)
SSDP_SEARCH = (b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
               b"MAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n")
MDNS_QUERY = (b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"     # id 0, 1 question
              b"\x09_services\x07_dns-sd\x04_udp\x05local\x00"
              b"\x00\x0c\x80\x01")                                 # PTR, IN + unicast-response bit


def _udp_ask(ip, port, payload, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.settimeout(timeout)
        s.sendto(payload, (ip, port))
        data, _addr = s.recvfrom(4096)
        return data
    except Exception:
        return b""
    finally:
        try:
            s.close()
        except Exception:
            pass


def probe_ntp(ip, port=123, timeout=0.6):
    data = _udp_ask(ip, port, NTP_REQUEST, timeout)
    return len(data) >= 48 and (data[0] & 0x07) == 4        # mode 4 = server reply


def probe_ssdp(ip, port=1900, timeout=0.8):
    """UPnP answers a unicast M-SEARCH. Returns the SERVER header (or 'upnp') when it does."""
    data = _udp_ask(ip, port, SSDP_SEARCH, timeout)
    text = data.decode("latin-1", "replace")
    if not text.startswith("HTTP/1.1 200"):
        return ""
    m = re.search(r"(?im)^server:\s*(.+)$", text)
    return (m.group(1).strip()[:120] if m else "") or "upnp"


def probe_mdns(ip, port=5353, timeout=0.6):
    data = _udp_ask(ip, port, MDNS_QUERY, timeout)
    return len(data) >= 12 and bool(data[2] & 0x80)          # QR bit set = a response


def probe_netbios(ip, port=137, timeout=0.6):
    return bool(netbios_name(ip, timeout, port=port))


def snmp_communities():
    """Communities to try: the ones configured in Settings first, then the common defaults."""
    try:
        from . import settings
        configured = list((settings.get("discovery") or {}).get("snmp_communities") or [])
    except Exception:
        configured = []
    out = []
    for c in configured + ["public", "private", "Community", "cable-docsis"]:
        if c and c not in out:
            out.append(c)
    return out[:8]


def probe_snmp(ip, timeout=0.7, port=161):
    """Ask sysDescr with every candidate community AT ONCE. Returns the community that answered."""
    def ask(community):
        try:
            res = snmp.get(ip, [snmp.OID_SYS_DESCR], community, timeout, retries=0)
            return community if res and res[0][2] else ""
        except Exception:
            return ""
    communities = snmp_communities()
    with ThreadPoolExecutor(max_workers=len(communities)) as ex:
        for community in ex.map(ask, communities):
            if community:
                return community
    return ""


def udp_scan(ip, timeout=0.7):
    """Probe the UDP services in UDP_SERVICES. Returns {port: detail} for those that answered."""
    probes = {
        123: lambda: probe_ntp(ip, timeout=timeout),
        137: lambda: probe_netbios(ip, timeout=timeout),
        161: lambda: probe_snmp(ip, timeout=timeout),            # community that answered
        1900: lambda: probe_ssdp(ip, timeout=timeout + 0.3),
        5353: lambda: probe_mdns(ip, timeout=timeout),
    }
    found = {}
    with ThreadPoolExecutor(max_workers=len(probes)) as ex:
        futures = {port: ex.submit(fn) for port, fn in probes.items()}
        for port, fut in futures.items():
            try:
                result = fut.result()
            except Exception:
                result = None
            if result:
                found[port] = result
    return found


# ---- banner / identity probes ----------------------------------------------


def _recv_some(sock, limit=4096):
    chunks = b""
    try:
        while len(chunks) < limit:
            data = sock.recv(1024)
            if not data:
                break
            chunks += data
    except Exception:
        pass
    return chunks


def http_probe(ip: str, port: int, timeout: float = 1.5):
    """Grab HTTP status, Server header and page title."""
    info = {"port": port, "server": "", "title": "", "status": "", "location": ""}
    use_tls = port in (443, 8443)
    raw = b""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(timeout)
        s.connect((ip, port))
        if use_tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=ip)
        req = (
            f"GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: Prahari/1.0\r\n"
            "Accept: */*\r\nConnection: close\r\n\r\n"
        )
        s.sendall(req.encode())
        raw = _recv_some(s)
    except Exception:
        return info
    finally:
        try:
            s.close()
        except Exception:
            pass

    text = raw.decode("utf-8", "replace")
    head, _, body = text.partition("\r\n\r\n")
    m = re.match(r"HTTP/\d\.\d\s+(\d{3})", head)
    if m:
        info["status"] = m.group(1)
    m = re.search(r"(?im)^server:\s*(.+)$", head)
    if m:
        info["server"] = m.group(1).strip()[:120]
    m = re.search(r"(?im)^location:\s*(.+)$", head)
    if m:
        info["location"] = m.group(1).strip()[:160]
    m = re.search(r"(?is)<title[^>]*>(.*?)</title>", body)
    if m:
        info["title"] = re.sub(r"\s+", " ", m.group(1)).strip()[:120]
    if not info["title"]:
        m = re.search(r"(?i)realm=\"?([^\",\r\n]+)", head)
        if m:
            info["title"] = "auth realm: " + m.group(1)[:100]
    return info


def rtsp_probe(ip: str, port: int = 554, timeout: float = 1.2):
    """RTSP OPTIONS - cameras and DVRs answer with their Server header."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(timeout)
        s.connect((ip, port))
        s.sendall(f"OPTIONS rtsp://{ip}/ RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: Prahari\r\n\r\n".encode())
        text = _recv_some(s, 2048).decode("utf-8", "replace")
    except Exception:
        return {}
    finally:
        try:
            s.close()
        except Exception:
            pass
    out = {}
    m = re.search(r"(?im)^server:\s*(.+)$", text)
    if m:
        out["server"] = m.group(1).strip()[:120]
    m = re.match(r"RTSP/\d\.\d\s+(\d{3})", text)
    if m:
        out["status"] = m.group(1)
    return out


def netbios_name(ip: str, timeout: float = 0.7, port: int = 137):
    """NBSTAT node-status query - returns the Windows/Samba computer name."""
    packet = (
        b"\xab\xcd"          # transaction id
        b"\x00\x00"          # flags
        b"\x00\x01\x00\x00\x00\x00\x00\x00"  # 1 question
        b"\x20" + b"CK" + b"A" * 30 + b"\x00"  # wildcard name, encoded
        b"\x00\x21"          # NBSTAT
        b"\x00\x01"          # INET
    )
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.settimeout(timeout)
        s.sendto(packet, (ip, port))
        data, _ = s.recvfrom(2048)
    except Exception:
        return ""
    finally:
        try:
            s.close()
        except Exception:
            pass
    try:
        if len(data) < 57:
            return ""
        # 12 header + 34 question + 2 type + 2 class + 4 ttl + 2 rdlength
        offset = 56
        rdlength = struct.unpack(">H", data[54:56])[0]
        rd = data[offset : offset + rdlength]
        count = rd[0]
        best = ""
        for i in range(count):
            start = 1 + i * 18
            entry = rd[start : start + 18]
            if len(entry) < 16:
                break
            name = entry[:15].decode("ascii", "ignore").strip()
            suffix = entry[15]
            if name and suffix in (0x00, 0x20):
                if suffix == 0x20 or not best:
                    best = name
        return best[:63]
    except Exception:
        return ""


def reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0].split(".")[0][:63]
    except Exception:
        return ""


def snmp_identify(ip: str, timeout: float = 0.8, community: str = ""):
    """Try SNMP for a description string (identifies switches, APs, printers).

    Returns (descr, extra_fields, community). With a known community, asks only with that one.
    """
    if community:
        res = snmp.get(ip, [snmp.OID_SYS_DESCR], community, timeout)
        descr = str(res[0][2]) if res and res[0][2] else ""
    else:
        descr, community = snmp.sysdescr(ip, timeout)
    if not descr:
        return "", {}, ""
    extra = {}
    try:
        res = snmp.get(
            ip,
            [snmp.OID_SYS_NAME, snmp.OID_SYS_LOCATION],
            community,
            timeout,
        )
        if res:
            for _oid, _tag, value in res:
                if isinstance(value, str) and value.strip():
                    if "name" not in extra:
                        extra["snmp_name"] = value.strip()[:63]
                    else:
                        extra["snmp_location"] = value.strip()[:63]
    except Exception:
        pass
    return descr, extra, community


def fingerprint_host(ip: str, is_gateway: bool = False, deep: bool = True):
    """Collect everything we can about one host in one dict."""
    info = {
        "ip": ip,
        "is_gateway": is_gateway,
        "ports": [],
        "http": [],
        "rtsp": {},
        "snmp_descr": "",
        "snmp_community": "",
        "hostname": "",
    }
    if not deep:
        return info

    ports = port_scan(ip)
    udp = udp_scan(ip)
    info["udp_ports"] = sorted(udp)
    if udp.get(1900) and udp[1900] != "upnp":
        info["upnp_server"] = udp[1900]
    ports = sorted(set(ports) | set(udp))
    info["ports"] = ports

    if 554 in ports:
        r = rtsp_probe(ip)
        if r:
            info["rtsp"] = r

    for port in [p for p in ports if p in (80, 81, 443, 8000, 8001, 8080, 8081, 8443, 8888, 9000, 5000, 6036)][:5]:
        h = http_probe(ip, port)
        if h.get("title") or h.get("server") or h.get("status"):
            info["http"].append(h)

    if 161 in udp:   # the UDP probe already tried every community, in parallel
        descr, extra, community = snmp_identify(ip, community=udp[161])
        if descr or community:
            info["snmp_descr"] = descr
            info["snmp_community"] = community
            info.update(extra)

    if not info["hostname"]:
        info["hostname"] = reverse_dns(ip)
    if not info["hostname"] and (137 in ports or not ports):
        info["hostname"] = netbios_name(ip)
    if not info["hostname"] and 137 in ports:
        info["hostname"] = netbios_name(ip)
    return info
