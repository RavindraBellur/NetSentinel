"""Tiny SNMPv2c client (GET + GETNEXT walk) with no third-party dependencies.

Used to identify managed switches / access points / printers and to read
per-interface byte counters from a router or switch, which is how Prahari
works out which port (and therefore which device) is eating the bandwidth.
"""

from __future__ import annotations

import random
import socket

# ---- BER encoding -----------------------------------------------------------


def _enc_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _tlv(tag: int, payload: bytes) -> bytes:
    return bytes([tag]) + _enc_len(len(payload)) + payload


def _enc_int(v: int) -> bytes:
    if v == 0:
        return _tlv(0x02, b"\x00")
    n = (v.bit_length() + 8) // 8
    body = v.to_bytes(n, "big", signed=True)
    while len(body) > 1 and (
        (body[0] == 0x00 and body[1] < 0x80) or (body[0] == 0xFF and body[1] >= 0x80)
    ):
        body = body[1:]
    return _tlv(0x02, body)


def _enc_oid(oid: str) -> bytes:
    parts = [int(x) for x in oid.strip(".").split(".") if x != ""]
    if len(parts) < 2:
        raise ValueError("bad oid")
    out = bytearray([parts[0] * 40 + parts[1]])
    for p in parts[2:]:
        if p == 0:
            out.append(0)
            continue
        chunks = []
        while p:
            chunks.insert(0, p & 0x7F)
            p >>= 7
        for i, c in enumerate(chunks):
            out.append(c | (0x80 if i < len(chunks) - 1 else 0))
    return _tlv(0x06, bytes(out))


def _dec_oid(body: bytes) -> str:
    if not body:
        return ""
    first = body[0]
    parts = [first // 40, first % 40]
    val = 0
    for b in body[1:]:
        val = (val << 7) | (b & 0x7F)
        if not b & 0x80:
            parts.append(val)
            val = 0
    return ".".join(str(p) for p in parts)


def _read_tlv(data: bytes, i: int = 0):
    tag = data[i]
    i += 1
    length = data[i]
    i += 1
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(data[i : i + n], "big")
        i += n
    return tag, data[i : i + length], i + length


def _dec_value(tag: int, body: bytes):
    if tag == 0x02:
        return int.from_bytes(body, "big", signed=True)
    if tag in (0x41, 0x42, 0x43, 0x46):  # Counter32/Gauge32/TimeTicks/Counter64
        return int.from_bytes(body, "big")
    if tag == 0x04:
        return body.decode("utf-8", "replace")
    if tag == 0x06:
        return _dec_oid(body)
    if tag == 0x40:
        return ".".join(str(b) for b in body)
    if tag == 0x05:
        return None
    return body.hex()


# ---- protocol ---------------------------------------------------------------


def _build(oids, community: str, request_id: int, pdu_tag: int = 0xA0) -> bytes:
    varbinds = b"".join(_tlv(0x30, _enc_oid(o) + _tlv(0x05, b"")) for o in oids)
    pdu = _tlv(
        pdu_tag,
        _enc_int(request_id) + _enc_int(0) + _enc_int(0) + _tlv(0x30, varbinds),
    )
    return _tlv(0x30, _enc_int(1) + _tlv(0x04, community.encode()) + pdu)


def _parse(data: bytes):
    """Return list of (oid, tag, value) or None."""
    try:
        tag, body, _ = _read_tlv(data, 0)
        if tag != 0x30:
            return None
        i = 0
        _, _, i = _read_tlv(body, i)  # version
        _, _, i = _read_tlv(body, i)  # community
        _, pdu, i = _read_tlv(body, i)
        j = 0
        _, _, j = _read_tlv(pdu, j)  # request id
        _, err, j = _read_tlv(pdu, j)
        _, _, j = _read_tlv(pdu, j)  # error index
        _, vbl, j = _read_tlv(pdu, j)
        err_status = int.from_bytes(err, "big", signed=True) if err else 0
        if err_status:
            return None
        out = []
        k = 0
        while k < len(vbl):
            _, vb, k = _read_tlv(vbl, k)
            m = 0
            _, oidb, m = _read_tlv(vb, m)
            vtag, vbody, m = _read_tlv(vb, m)
            out.append((_dec_oid(oidb), vtag, _dec_value(vtag, vbody)))
        return out
    except Exception:
        return None


def _v3_config():
    """SNMPv3 credentials from settings, or None when v3 is off."""
    try:
        from . import settings as _settings
        cfg = (_settings.load().get("snmp_v3") or {})
        if cfg.get("enabled") and cfg.get("user") and cfg.get("auth_password"):
            return cfg
    except Exception:
        pass
    return None


def _v3_session(host, timeout=2.0):
    """Cached session per device - discovery is expensive, so it is reused."""
    from . import snmpv3
    cfg = _v3_config()
    if not cfg:
        return None
    cache = _v3_session.cache
    entry = cache.get(host)
    now = __import__("time").time()
    if entry and now - entry[0] < 300:
        return entry[1]
    session = snmpv3.V3Session(host, cfg.get("user"), cfg.get("auth_password"),
                               cfg.get("priv_password") or "",
                               cfg.get("auth_proto") or "sha1", timeout=timeout,
                               port=int(cfg.get("port") or 161))
    cache[host] = (now, session)
    return session


_v3_session.cache = {}


def get(host: str, oids, community: str = "public", timeout: float = 1.0, retries: int = 1):
    """SNMP GET one or more OIDs. Returns list of (oid, tag, value) or None."""
    session = _v3_session(host, timeout + 1)
    if session is not None:
        try:
            return session.get(oids)
        except Exception:
            return None
    if isinstance(oids, str):
        oids = [oids]
    oids = list(oids)
    request_id = random.randint(1, 2**30)
    packet = _build(oids, community, request_id)
    for _ in range(retries + 1):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.settimeout(timeout)
            s.sendto(packet, (host, 161))
            while True:
                data, _addr = s.recvfrom(4096)
                parsed = _parse(data)
                if parsed:
                    return parsed
                break
        except Exception:
            continue
        finally:
            try:
                s.close()
            except Exception:
                pass
    return None


def walk(host: str, base: str, community: str = "public", timeout: float = 1.0, max_rows: int = 3000):
    """GETNEXT walk below `base`. Returns list of (oid, tag, value)."""
    session = _v3_session(host, timeout + 1)
    if session is not None:
        try:
            return session.walk(base, max_rows)
        except Exception:
            return []
    rows = []
    current = base
    while len(rows) < max_rows:
        res = get(host, [current], community, timeout)
        if not res:
            break
        oid, tag, value = res[0]
        if tag == 0x80 or value is None:  # noSuchObject / endOfMibView
            break
        if not (oid == base or oid.startswith(base + ".")):
            break
        if oid == current:
            break
        rows.append((oid, tag, value))
        current = oid
    return rows


def bulk(host: str, oids, community: str = "public", timeout: float = 1.5,
         max_repetitions: int = 25, non_repeaters: int = 0):
    """SNMP GETBULK (v2c only). Returns list of (oid, tag, value)."""
    if isinstance(oids, str):
        oids = [oids]
    oids = list(oids)
    request_id = random.randint(1, 2**30)
    varbinds = b"".join(_tlv(0x30, _enc_oid(o) + _tlv(0x05, b"")) for o in oids)
    pdu = _tlv(
        0xA5,
        _enc_int(request_id) + _enc_int(non_repeaters) + _enc_int(max_repetitions)
        + _tlv(0x30, varbinds),
    )
    packet = _tlv(0x30, _enc_int(1) + _tlv(0x04, community.encode()) + pdu)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.settimeout(timeout)
        s.sendto(packet, (host, 161))
        data, _ = s.recvfrom(65535)
    except Exception:
        return []
    finally:
        try:
            s.close()
        except Exception:
            pass
    return _parse(data) or []


def walk_bulk(host: str, base: str, community: str = "public", timeout: float = 1.5,
              max_rows: int = 4000):
    """Walk a subtree with GETBULK, falling back to GETNEXT if the agent refuses."""
    rows = []
    current = base
    prefix = base + "."
    while len(rows) < max_rows:
        got = bulk(host, [current], community, timeout)
        if not got:
            break
        progressed = False
        for oid, tag, value in got:
            if tag in (0x80, 0x81, 0x82) or not (oid == base or oid.startswith(prefix)):
                progressed = False
                got = []
                break
            rows.append((oid, tag, value))
            progressed = True
            current = oid
        if not progressed:
            break
    if not rows:
        return walk(host, base, community, timeout, max_rows)
    return rows


def set(host: str, oid: str, value, index: str = "", community: str = "private",
        timeout: float = 2.0, retries: int = 1):
    """SNMP SET one integer value. Returns True when the device accepted it.

    Used by remediation (PoE port bounce). SET needs a write community, so this always goes
    out over v2c - v3 SET is not implemented and the console says so.
    """
    full = oid + ("." + str(index) if index else "")
    request_id = random.randint(1, 2 ** 30)
    varbind = _tlv(0x30, _enc_oid(full) + _enc_int(int(value)))
    pdu = _tlv(0xA3, _enc_int(request_id) + _enc_int(0) + _enc_int(0) + _tlv(0x30, varbind))
    packet = _tlv(0x30, _enc_int(1) + _tlv(0x04, community.encode()) + pdu)
    for _ in range(retries + 1):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.settimeout(timeout)
            s.sendto(packet, (host, 161))
            data, _addr = s.recvfrom(4096)
            parsed = _parse(data)
            if parsed:
                return True
        except Exception:
            continue
        finally:
            try:
                s.close()
            except Exception:
                pass
    return False


def sysdescr(host: str, timeout: float = 0.8):
    """Return (sysDescr, community) or ('', '')."""
    for community in ("public", "private", "Community", "cable-docsis"):
        res = get(host, ["1.3.6.1.2.1.1.1.0"], community, timeout)
        if res and res[0][2]:
            return str(res[0][2]), community
    return "", ""


# ---- well known OIDs --------------------------------------------------------

OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"
OID_SYS_LOCATION = "1.3.6.1.2.1.1.6.0"
OID_IF_DESCR = "1.3.6.1.2.1.2.2.1.2"
OID_IF_IN_OCTETS = "1.3.6.1.2.1.2.2.1.10"
OID_IF_OUT_OCTETS = "1.3.6.1.2.1.2.2.1.16"
OID_IF_HC_IN = "1.3.6.1.2.1.31.1.1.1.6"
OID_IF_HC_OUT = "1.3.6.1.2.1.31.1.1.1.10"
OID_IF_ALIAS = "1.3.6.1.2.1.31.1.1.1.18"
OID_FDB_ADDRESS = "1.3.6.1.2.1.17.4.3.1.1"  # dot1dTpFdbAddress
OID_FDB_PORT = "1.3.6.1.2.1.17.4.3.1.2"  # dot1dTpFdbPort
OID_BASE_PORT_IF = "1.3.6.1.2.1.17.1.4.1.2"  # dot1dBasePortIfIndex
# Q-BRIDGE-MIB: MAC per VLAN -> bridge port. Index is <fdb-id>.<6 MAC octets>.
OID_Q_FDB_PORT = "1.3.6.1.2.1.17.7.1.2.2.1.2"      # dot1qTpFdbPort
OID_Q_VLAN_NAME = "1.3.6.1.2.1.17.7.1.4.3.1.1"     # dot1qVlanStaticName
OID_IF_HIGH_SPEED = "1.3.6.1.2.1.31.1.1.1.15"      # ifHighSpeed (Mbps)
