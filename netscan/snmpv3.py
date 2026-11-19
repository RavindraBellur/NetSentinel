"""SNMPv3 (USM): authenticated and encrypted polling.

Version 2c sends the community string in clear text, which every security baseline
prohibits. Version 3 with `authPriv` signs each message and encrypts the payload:

    auth : HMAC-MD5-96, HMAC-SHA-96 or HMAC-SHA-256 (RFC 3414 / RFC 7860)
    priv : AES-128-CFB (RFC 3826)

Key localisation follows RFC 3414 A.2 / 2.6 exactly - one hash over the password repeated
to 1 MB, then the engine-id mix - and is checked against the published test vectors.

DES privacy is deliberately not implemented: vendors are removing it and the library
support is deprecated. If a device only offers DES, use v2c on a management VLAN.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import socket
import struct

from .snmp import (_dec_oid, _dec_value, _enc_int, _enc_oid, _read_tlv, _tlv)

AUTH_PROTOCOLS = {
    "md5": ("md5", 12),
    "sha": ("sha1", 12),
    "sha1": ("sha1", 12),
    "sha224": ("sha224", 16),
    "sha256": ("sha256", 24),
    "sha384": ("sha384", 32),
    "sha512": ("sha512", 48),
}
USM_MODEL = 3
FLAG_AUTH = 0x01
FLAG_PRIV = 0x02
FLAG_REPORT = 0x04
MSG_MAX_SIZE = 65507
PLACEHOLDER = b"\x5a" * 12      # 12-byte default; the real length follows the protocol


def password_to_key(password, engine_id, proto="sha1"):
    """RFC 3414: Ku = hash(password repeated to 1 MB), Kul = hash(Ku|engineID|Ku)."""
    name = AUTH_PROTOCOLS.get((proto or "sha1").lower(), ("sha1", 12))[0]
    h = getattr(hashlib, name)
    pw = (password or "").encode("utf-8")
    if not pw:
        return b""
    repeats = (1048576 // len(pw)) + 1
    ku = h((pw * repeats)[:1048576]).digest()
    return h(ku + engine_id + ku).digest()


def _enc_str(value):
    if isinstance(value, str):
        value = value.encode("utf-8")
    return _tlv(0x04, value)


def _enc_seq(*parts):
    return _tlv(0x30, b"".join(parts))


class V3Error(Exception):
    pass


class V3Session:
    """One SNMPv3 conversation with one device."""

    def __init__(self, host, user, auth_password="", priv_password="",
                 auth_proto="sha1", priv_proto="aes", context="",
                 timeout=2.0, retries=1, port=161):
        self.host = host
        self.port = port
        self.user = user or ""
        self.auth_password = auth_password or ""
        self.priv_password = priv_password or ""
        self.auth_proto = (auth_proto or "sha1").lower()
        self.priv_proto = (priv_proto or "aes").lower()
        self.context = context or ""
        self.timeout = timeout
        self.retries = retries
        self.engine_id = b""
        self.boots = 0
        self.engine_time = 0
        self.msg_id = int.from_bytes(os.urandom(3), "big") or 1
        self.salt = int.from_bytes(os.urandom(4), "big")
        self.auth_key = b""
        self.priv_key = b""
        self._discovered = False
        self.last_error = ""

    # ------------------------------------------------------------------ io --
    def _send(self, payload):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        try:
            sock.sendto(payload, (self.host, self.port))
            data, _ = sock.recvfrom(65535)
            return data
        finally:
            sock.close()

    def _next_id(self):
        self.msg_id = (self.msg_id + 1) % 0x7FFFFF or 1
        return self.msg_id

    # ----------------------------------------------------------- discovery --
    def discover(self):
        """Learn the engine id, boot counter and clock (RFC 3414 section 4)."""
        if self._discovered:
            return True
        msg_id = self._next_id()
        scoped = _enc_seq(_enc_str(b""), _enc_str(self.context.encode()),
                          _tlv(0xA0, _enc_int(0) + _enc_int(0) + _enc_int(0) +
                               _enc_seq(_enc_seq(_enc_oid("1.3.6.1.2.1.1.1.0"),
                                                 _tlv(0x05, b"")))))
        usm = _enc_seq(_enc_str(b""), _enc_int(0), _enc_int(0),
                       _enc_str(self.user.encode()), _enc_str(b""), _enc_str(b""))
        msg = _enc_seq(_enc_int(3),
                       _enc_seq(_enc_int(msg_id), _enc_int(MSG_MAX_SIZE),
                                _enc_str(bytes([FLAG_REPORT])), _enc_int(USM_MODEL)),
                       _enc_str(usm), _enc_str(scoped))
        try:
            reply = self._send(msg)
        except Exception as exc:
            self.last_error = f"discovery failed: {exc.__class__.__name__}"
            return False
        try:
            engine_id, boots, when, _u, _a, _p, _scoped, _mid = self._parse(reply)
        except Exception as exc:
            self.last_error = f"discovery reply unreadable: {exc}"
            return False
        if not engine_id:
            self.last_error = "device did not return an engine id"
            return False
        self.engine_id = engine_id
        self.boots = boots
        self.engine_time = when
        self._derive_keys()
        self._discovered = True
        return True

    def _derive_keys(self):
        if self.auth_password:
            self.auth_key = password_to_key(self.auth_password, self.engine_id, self.auth_proto)
        if self.priv_password:
            self.priv_key = password_to_key(self.priv_password, self.engine_id, self.auth_proto)

    # ------------------------------------------------------------- encoding --
    def _flags(self):
        flags = FLAG_REPORT
        if self.auth_password:
            flags |= FLAG_AUTH
        if self.priv_password:
            flags |= FLAG_PRIV
        return bytes([flags])

    def _cipher(self, key, iv):
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
        except Exception as exc:
            raise V3Error("the 'cryptography' package is needed for SNMPv3 privacy") from exc
        try:                                     # cryptography >= 48
            from cryptography.hazmat.decrepit.ciphers.modes import CFB as _CFB
        except Exception:                        # older releases
            from cryptography.hazmat.primitives.ciphers.modes import CFB as _CFB
        return Cipher(algorithms.AES(key[:16]), _CFB(iv))

    def _encrypt(self, plain):
        if len(self.priv_key) < 16:
            raise V3Error("privacy password produced a short key")
        self.salt = (self.salt + 1) & 0xFFFFFFFF
        salt = struct.pack(">Q", self.salt)
        iv = struct.pack(">II", self.boots & 0xFFFFFFFF,
                         self.engine_time & 0xFFFFFFFF) + salt
        enc = self._cipher(self.priv_key, iv).encryptor()
        return enc.update(plain) + enc.finalize(), salt

    def _decrypt(self, ciphertext, salt):
        iv = struct.pack(">II", self.boots & 0xFFFFFFFF,
                         self.engine_time & 0xFFFFFFFF) + salt
        dec = self._cipher(self.priv_key, iv).decryptor()
        return dec.update(ciphertext) + dec.finalize()

    def _auth_len(self):
        return AUTH_PROTOCOLS.get(self.auth_proto, ("sha1", 12))[1]

    def _sign(self, message):
        name, length = AUTH_PROTOCOLS.get(self.auth_proto, ("sha1", 12))
        marker = b"\x5a" * length
        idx = message.find(marker)
        if idx < 0:
            raise V3Error("auth placeholder lost")
        zeroed = message[:idx] + b"\x00" * length + message[idx + length:]
        digest = hmac.new(self.auth_key, zeroed, getattr(hashlib, name)).digest()[:length]
        return zeroed[:idx] + digest + zeroed[idx + length:]

    def _verify(self, message, engine_id, auth_params):
        """Check an authenticated reply against the engine's key."""
        name, length = AUTH_PROTOCOLS.get(self.auth_proto, ("sha1", 12))
        if not self.auth_key:
            self._derive_keys()
        idx = message.find(auth_params) if auth_params else -1
        if idx < 0:
            return False
        zeroed = message[:idx] + b"\x00" * len(auth_params) + message[idx + len(auth_params):]
        digest = hmac.new(self.auth_key, zeroed, getattr(hashlib, name)).digest()[:length]
        return hmac.compare_digest(digest, auth_params[:length])

    def _build(self, pdu_tag, oids, extra=None):
        """extra replaces error-status/error-index (GetBulk uses it)."""
        msg_id = self._next_id()
        varbinds = b"".join(_enc_seq(_enc_oid(o), _tlv(0x05, b"")) for o in oids)
        if extra is None:
            extra = _enc_int(0) + _enc_int(0)      # error-status, error-index
        pdu = _tlv(pdu_tag, _enc_int(msg_id) + extra + _enc_seq(varbinds))
        scoped = _enc_seq(_enc_str(self.engine_id), _enc_str(self.context.encode()), pdu)
        if self.priv_password:
            body, salt = self._encrypt(scoped)
            priv_params = _enc_str(salt)
            msg_data = _enc_str(body)
        else:
            priv_params = _enc_str(b"")
            msg_data = _enc_str(scoped)
        auth_params = (_enc_str(b"\x5a" * self._auth_len()) if self.auth_password
                       else _enc_str(b""))
        usm = _enc_seq(_enc_str(self.engine_id), _enc_int(self.boots),
                       _enc_int(self.engine_time), _enc_str(self.user.encode()),
                       auth_params, priv_params)
        msg = _enc_seq(_enc_int(3),
                       _enc_seq(_enc_int(msg_id), _enc_int(MSG_MAX_SIZE),
                                _enc_str(self._flags()), _enc_int(USM_MODEL)),
                       _enc_str(usm), msg_data)
        if self.auth_password:
            msg = self._sign(msg)
        return msg

    # ------------------------------------------------------------- decoding --
    def _parse(self, data):
        """-> (engine_id, boots, time, user, auth, priv, scoped_bytes, msg_id)."""
        _tag, body, _end = _read_tlv(data, 0)
        i = 0
        _t, ver, i = _read_tlv(body, i)
        if int.from_bytes(ver, "big") != 3:
            raise V3Error("not an SNMPv3 reply")
        _t, hdr, i = _read_tlv(body, i)
        j = 0
        _t, msg_id_b, j = _read_tlv(hdr, j)
        msg_id = int.from_bytes(msg_id_b, "big")
        _t, _max_size, j = _read_tlv(hdr, j)      # msgMaxSize
        _t, flags_b, j = _read_tlv(hdr, j)        # msgFlags
        flags = flags_b[0] if flags_b else 0
        _t, sec, i = _read_tlv(body, i)
        _t, usm, _ = _read_tlv(sec, 0)
        k = 0
        _t, engine_id, k = _read_tlv(usm, k)
        _t, boots_b, k = _read_tlv(usm, k)
        _t, time_b, k = _read_tlv(usm, k)
        _t, user_b, k = _read_tlv(usm, k)
        _t, auth_b, k = _read_tlv(usm, k)
        _t, priv_b, k = _read_tlv(usm, k)
        boots = int.from_bytes(boots_b, "big") if boots_b else 0
        when = int.from_bytes(time_b, "big") if time_b else 0
        if flags & FLAG_AUTH and auth_b:
            self._verify(data, engine_id, auth_b)
        _t, msg_data, _ = _read_tlv(body, i)
        scoped = msg_data
        if (flags & FLAG_PRIV) and self.priv_key:
            scoped = self._decrypt(msg_data, priv_b)
        return (engine_id, boots, when, user_b.decode("utf-8", "replace"),
                auth_b, priv_b, scoped, msg_id)

    @staticmethod
    def _scoped_pdu(scoped):
        _t, body, _ = _read_tlv(scoped, 0)
        i = 0
        _t, _ctx_engine, i = _read_tlv(body, i)
        _t, _ctx_name, i = _read_tlv(body, i)
        t_pdu, pdu, _ = _read_tlv(body, i)
        return t_pdu, pdu

    @staticmethod
    def _varbinds(pdu):
        i = 0
        _t, _rid, i = _read_tlv(pdu, i)
        _t, err_status, i = _read_tlv(pdu, i)
        _t, _err_index, i = _read_tlv(pdu, i)
        _t, vbl, i = _read_tlv(pdu, i)
        out = []
        j = 0
        while j < len(vbl):
            _t, vb, j = _read_tlv(vbl, j)
            k = 0
            _t, oid_b, k = _read_tlv(vb, k)
            t_val, val_b, k = _read_tlv(vb, k)
            out.append((_dec_oid(oid_b), t_val, _dec_value(t_val, val_b)))
        err = int.from_bytes(err_status, "big") if err_status else 0
        return out, err

    # ---------------------------------------------------------------- verbs --
    def get(self, oids, pdu_tag=0xA0):
        if isinstance(oids, str):
            oids = [oids]
        if not self.discover():
            return []
        msg = self._build(pdu_tag, oids)
        for _attempt in range(self.retries + 1):
            try:
                reply = self._send(msg)
            except socket.timeout:
                self.last_error = "timeout"
                continue
            except Exception as exc:
                self.last_error = f"{exc.__class__.__name__}: {exc}"[:120]
                continue
            try:
                _eid, boots, when, _u, _a, _p, scoped, _mid = self._parse(reply)
                self.boots, self.engine_time = boots, when
                _tag, pdu = self._scoped_pdu(scoped)
                vbs, err = self._varbinds(pdu)
                if err:
                    self.last_error = f"device returned error-status {err}"
                    return []
                self.last_error = ""
                return vbs
            except Exception as exc:
                self.last_error = f"reply: {exc}"[:120]
        return []

    def walk(self, base, max_rows=2000):
        rows = []
        current = base
        while len(rows) < max_rows:
            vbs = self.get([current], pdu_tag=0xA1)
            if not vbs:
                break
            oid, tag, value = vbs[0]
            if tag == 0x80 or not oid:
                break
            if oid != base and not oid.startswith(base + "."):
                break
            if oid == current:
                break
            rows.append((oid, tag, value))
            current = oid
        return rows

    def sys_descr(self):
        vbs = self.get(["1.3.6.1.2.1.1.1.0"])
        return str(vbs[0][2]) if vbs and vbs[0][2] else ""


def probe(host, user, auth_password, priv_password="", auth_proto="sha1", timeout=2.0, port=161):
    """Console helper: does v3 work with these credentials?"""
    session = V3Session(host, user, auth_password, priv_password, auth_proto,
                        timeout=timeout, port=port)
    descr = session.sys_descr()
    return bool(descr), (descr or session.last_error)
