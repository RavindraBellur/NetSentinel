"""Flow ingestion: NetFlow v5, NetFlow v9 and sFlow v5.

This is how "who is using the internet" is answered properly: the router or
firewall exports one record per conversation, we add up the bytes per LAN address
and rank them. Works with MikroTik, Cisco, Fortinet, pfSense/OPNsense, UniFi,
Juniper, Aruba/HPE and anything else that speaks these three formats.

Parsers are pure functions so they can be unit-tested with crafted packets.
"""

from __future__ import annotations

import socket
import struct
import threading
import time

PRIVATE_PREFIXES = ("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2",
                    "172.30.", "172.31.", "127.", "169.254.", "100.64.", "0.", "224.", "239.",
                    "255.")


def is_private(ip):
    return ip.startswith(PRIVATE_PREFIXES)


def _ip(raw):
    try:
        return socket.inet_ntoa(raw)
    except Exception:
        return ""


# --------------------------------------------------------------- NetFlow v5 --

def parse_v5(data):
    """Return [(src, dst, octets, packets, proto)] or []."""
    if len(data) < 24:
        return []
    version, count = struct.unpack_from("!HH", data, 0)
    if version != 5 or count > 60:
        return []
    out = []
    off = 24
    for _ in range(count):
        if off + 48 > len(data):
            break
        rec = data[off:off + 48]
        src, dst = rec[0:4], rec[4:8]
        octets = struct.unpack_from("!I", rec, 20)[0]
        packets = struct.unpack_from("!I", rec, 16)[0]
        proto = rec[38]
        out.append((_ip(src), _ip(dst), octets, packets, proto))
        off += 48
    return out


# --------------------------------------------------------------- NetFlow v9 --

_TEMPLATES = {}
_FIELD_SRC, _FIELD_DST, _FIELD_BYTES, _FIELD_PKTS = 8, 12, 1, 2


def _v9_templates(data, off, count, source_id):
    end = off + count
    while off + 4 <= end:
        template_id, field_count = struct.unpack_from("!HH", data, off)
        off += 4
        fields = []
        for _ in range(field_count):
            if off + 4 > end:
                return
            ftype, flen = struct.unpack_from("!HH", data, off)
            off += 4
            fields.append((ftype, flen))
        _TEMPLATES[(source_id, template_id)] = fields


def parse_v9(data):
    """Return [(src, dst, octets, packets, proto)] or []."""
    if len(data) < 20:
        return []
    version, count, _uptime, _secs, _seq, source_id = struct.unpack_from("!HHIIII", data, 0)
    if version != 9:
        return []
    out = []
    off = 20
    for _ in range(count):
        if off + 4 > len(data):
            break
        set_id, length = struct.unpack_from("!HH", data, off)
        off += 4
        if length < 4 or off + length - 4 > len(data):
            break
        body = data[off:off + length - 4]
        off += length - 4
        if set_id == 0:
            _v9_templates(body, 0, len(body), source_id)
            continue
        if set_id < 256:
            continue  # options / other sets
        template = _TEMPLATES.get((source_id, set_id))
        if not template:
            continue
        record_len = sum(f[1] for f in template)
        if record_len <= 0:
            continue
        for start in range(0, len(body) - record_len + 1, record_len):
            rec = body[start:start + record_len]
            pos = 0
            src = dst = ""
            octets = packets = 0
            proto = 0
            for ftype, flen in template:
                value = rec[pos:pos + flen]
                pos += flen
                if ftype == _FIELD_SRC and flen == 4:
                    src = _ip(value)
                elif ftype == _FIELD_DST and flen == 4:
                    dst = _ip(value)
                elif ftype == _FIELD_BYTES:
                    octets = int.from_bytes(value, "big")
                elif ftype == _FIELD_PKTS:
                    packets = int.from_bytes(value, "big")
                elif ftype == 4 and flen == 1:
                    proto = value[0]
            if src and dst:
                out.append((src, dst, octets, packets, proto))
    return out


# ------------------------------------------------------------------ sFlow v5 --

def _parse_eth_ip(header):
    """Pull (src, dst, proto) out of an Ethernet frame carrying IPv4/IPv6."""
    if len(header) < 34:
        return None
    ethertype = struct.unpack_from("!H", header, 12)[0]
    offset = 14
    while ethertype in (0x8100, 0x88A8) and len(header) >= offset + 4:
        ethertype = struct.unpack_from("!H", header, offset + 2)[0]
        offset += 4
    if ethertype == 0x0800 and len(header) >= offset + 20:
        ihl = (header[offset] & 0x0F) * 4
        if ihl < 20:
            return None
        proto = header[offset + 9]
        total = struct.unpack_from("!H", header, offset + 2)[0]
        src = _ip(header[offset + 12:offset + 16])
        dst = _ip(header[offset + 16:offset + 20])
        return src, dst, proto, max(0, total - ihl)
    return None


def parse_sflow(data):
    """Return [(src, dst, octets, packets, proto)] from flow samples."""
    if len(data) < 28:
        return []
    version, addr_type = struct.unpack_from("!II", data, 0)
    if version != 5:
        return []
    off = 8
    if addr_type == 1:
        off += 4
    elif addr_type == 2:
        off += 16
    else:
        return []
    off += 4  # sub agent id
    off += 4  # sequence
    off += 4  # uptime
    if off + 4 > len(data):
        return []
    num_samples = struct.unpack_from("!I", data, off)[0]
    off += 4
    out = []
    for _ in range(min(num_samples, 64)):
        if off + 8 > len(data):
            break
        data_format, length = struct.unpack_from("!II", data, off)
        off += 8
        if off + length > len(data):
            break
        sample = data[off:off + length]
        off += length
        enterprise = data_format >> 12
        fmt = data_format & 0xFFF
        if enterprise != 0 or fmt not in (1, 3):  # flow sample / flow sample expanded
            continue
        try:
            pos = 44 if fmt == 3 else 32
            if len(sample) < pos:
                continue
            num_records = struct.unpack_from("!I", sample, pos - 4)[0]
            rpos = pos
            for _r in range(min(num_records, 32)):
                if rpos + 8 > len(sample):
                    break
                rfmt, rlen = struct.unpack_from("!II", sample, rpos)
                rpos += 8
                if rpos + rlen > len(sample):
                    break
                rec = sample[rpos:rpos + rlen]
                rpos += rlen
                if (rfmt & 0xFFF) != 1 or (rfmt >> 12) != 0:  # raw packet header only
                    continue
                if len(rec) < 16:
                    continue
                frame_len = struct.unpack_from("!I", rec, 4)[0]
                header_len = struct.unpack_from("!I", rec, 12)[0]
                parsed = _parse_eth_ip(rec[16:16 + header_len])
                if not parsed:
                    continue
                src, dst, proto, l3len = parsed
                out.append((src, dst, frame_len or l3len, 1, proto))
        except Exception:
            continue
    return out


# ------------------------------------------------------------------- service --

class FlowCollector(threading.Thread):
    """Listens for NetFlow v5/v9 and sFlow, and keeps per-IP byte counters."""

    def __init__(self, scanner, config=None, log=None):
        super().__init__(daemon=True, name="flow-collector")
        self.scanner = scanner
        self.cfg = config or {}
        self.log = log or (lambda m: None)
        self._stop = threading.Event()
        self.lock = threading.Lock()
        self.buckets = {}          # ip -> {"down": [(ts, bytes)], "up": [...]}
        self.today = {}            # ip -> {"down": bytes, "up": bytes, "day": "YYYY-MM-DD"}
        self.packets = 0
        self.errors = 0
        self.last_packet_ts = 0.0
        self.exporters = set()
        self.sockets = []
        self.started = False

    # -- lifecycle ------------------------------------------------------
    def stop(self):
        self._stop.set()
        for sock in self.sockets:
            try:
                sock.close()
            except Exception:
                pass

    def _bind(self, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("0.0.0.0", port))
        except OSError as exc:
            self.log(f"flow: could not listen on UDP {port}: {exc}")
            sock.close()
            return None
        sock.settimeout(1.0)
        self.sockets.append(sock)
        return sock

    def run(self):
        ports = []
        if self.cfg.get("enabled", True):
            ports.append(int(self.cfg.get("port") or 2055))
            sflow_port = int(self.cfg.get("sflow_port") or 6343)
            if sflow_port not in ports:
                ports.append(sflow_port)
        socks = [s for s in (self._bind(p) for p in ports) if s]
        if not socks:
            return
        self.started = True
        self.log(f"flow: listening for NetFlow/sFlow on UDP {', '.join(str(p) for p in ports)}")
        while not self._stop.is_set():
            for sock in socks:
                try:
                    data, addr = sock.recvfrom(65535)
                except socket.timeout:
                    continue
                except OSError:
                    continue
                try:
                    self.ingest(data, addr[0])
                except Exception:
                    self.errors += 1
            self._prune()

    # -- accounting -----------------------------------------------------
    def ingest(self, data, exporter=""):
        if len(data) < 4:
            return 0
        version = struct.unpack_from("!H", data, 0)[0]
        if version == 5:
            flows = parse_v5(data)
        elif version == 9:
            flows = parse_v9(data)
        elif version == 1:
            flows = parse_sflow(data)
        else:
            flows = []
        if not flows:
            return 0
        allowed = self.cfg.get("allowed_exporters") or []
        if allowed and exporter not in allowed:
            return 0
        self.packets += 1
        self.last_packet_ts = time.time()
        self.exporters.add(exporter)
        now = time.time()
        day = time.strftime("%Y-%m-%d")
        with self.lock:
            for src, dst, octets, _pkts, _proto in flows:
                src_local = is_private(src)
                dst_local = is_private(dst)
                if src_local and not dst_local:
                    self._add(src, "up", octets, now, day)
                elif dst_local and not src_local:
                    self._add(dst, "down", octets, now, day)
                elif src_local and dst_local:
                    self._add(src, "up", octets, now, day, lan=True)
                    self._add(dst, "down", octets, now, day, lan=True)
        return len(flows)

    def _add(self, ip, direction, octets, now, day, lan=False):
        entry = self.buckets.setdefault(ip, {"down": [], "up": []})
        entry[direction].append((now, octets))
        today = self.today.setdefault(ip, {"down": 0, "up": 0, "day": day})
        if today.get("day") != day:
            today.update(down=0, up=0, day=day)
        today[direction] += octets

    def _prune(self, window=180):
        cutoff = time.time() - window
        with self.lock:
            for entry in self.buckets.values():
                for direction in ("down", "up"):
                    lst = entry[direction]
                    if lst and lst[0][0] < cutoff:
                        entry[direction] = [x for x in lst if x[0] >= cutoff]

    def rates(self, window=60):
        """{ip: {"down_bps", "up_bps", "down_bytes_today", "up_bytes_today"}}"""
        now = time.time()
        out = {}
        with self.lock:
            for ip, entry in self.buckets.items():
                down = sum(b for ts, b in entry["down"] if now - ts <= window)
                up = sum(b for ts, b in entry["up"] if now - ts <= window)
                today = self.today.get(ip, {})
                out[ip] = {
                    "down_bps": down * 8 / window,
                    "up_bps": up * 8 / window,
                    "down_bytes_today": today.get("down", 0),
                    "up_bytes_today": today.get("up", 0),
                }
        return out

    def status(self):
        return {
            "active": self.started,
            "packets": self.packets,
            "errors": self.errors,
            "exporters": sorted(self.exporters),
            "last_packet_age": (time.time() - self.last_packet_ts) if self.last_packet_ts else None,
        }
