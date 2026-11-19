"""Syslog receiver: firewall and switch logs become dashboard events.

Listens on UDP (default 5514, so it can run next to an existing syslog server on
514) and raises an event when a line matches one of the alert patterns - link
down, VPN down, failover, high CPU and so on. Everything is rate limited so a
noisy device cannot fill the disk.
"""

from __future__ import annotations

import re
import socket
import threading
import time

SEVERITY_NAMES = {0: "critical", 1: "critical", 2: "critical", 3: "high", 4: "high",
                  5: "medium", 6: "info", 7: "info"}

DEFAULT_PATTERNS = [
    "gateway.{0,40}(dead|down|fail)",
    "(link|interface|port).{0,40}down",
    "(tunnel|ipsec|vpn).{0,40}(down|fail|disconnect)",
    "(cpu|memory|disk).{0,30}(high|critical|exceed)",
    "(temperature|thermal).{0,30}(high|critical)",
]

PRI_RE = re.compile(r"^<(\d{1,3})>(?:\d\s)?")
TAG_RE = re.compile(r"^(?:[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2}\s)?(\S+?)(?:\[\d+\])?:\s")


def parse_line(raw):
    """Return {pri, severity, host, tag, message} for one syslog line."""
    text = raw.decode("utf-8", "replace").strip()
    pri = None
    m = PRI_RE.match(text)
    if m:
        pri = int(m.group(1))
        text = text[m.end():]
    parts = text.split(" ", 3)
    host = ""
    rest = text
    # RFC3164: "Oct 11 22:14:15 host tag: msg"  /  RFC5424: "1 2023-.. host app - - msg"
    if parts and re.match(r"^[A-Z][a-z]{2}\s+\d{1,2}$", parts[0]):
        rest = text.split(" ", 3)[3] if len(parts) > 3 else text
        host = parts[2] if len(parts) > 2 else ""
    elif parts and parts[0] == "1":
        fields = text.split(" ", 6)
        host = fields[2] if len(fields) > 2 else ""
        rest = fields[6] if len(fields) > 6 else ""
    tag = ""
    m = TAG_RE.match(rest)
    if m:
        tag = m.group(1)
        rest = rest[m.end():]
    severity = SEVERITY_NAMES.get(pri & 7, "info") if pri is not None else "info"
    return {"pri": pri, "severity": severity, "host": host, "tag": tag, "message": rest[:500]}


class SyslogReceiver(threading.Thread):
    def __init__(self, scanner, config=None, log=None):
        super().__init__(daemon=True, name="syslog")
        self.scanner = scanner
        self.cfg = config or {}
        self.log = log or (lambda m: None)
        self._stop = threading.Event()
        self.sock = None
        self.received = 0
        self.matched = 0
        self.last_ts = 0.0
        self.hosts = set()
        self._patterns = self._compile(self.cfg.get("alert_patterns") or DEFAULT_PATTERNS)
        self._recent = {}
        self.running = False

    @staticmethod
    def _compile(patterns):
        out = []
        for pat in patterns:
            try:
                out.append((pat, re.compile(pat, re.I)))
            except re.error:
                continue
        return out

    def stop(self):
        self._stop.set()
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass

    def run(self):
        if not self.cfg.get("enabled", True):
            return
        port = int(self.cfg.get("port") or 5514)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("0.0.0.0", port))
        except OSError as exc:
            self.log(f"syslog: could not listen on UDP {port}: {exc}")
            return
        sock.settimeout(1.0)
        self.sock = sock
        self.running = True
        self.log(f"syslog: listening on UDP {port}")
        from . import store

        while not self._stop.is_set():
            try:
                data, addr = sock.recvfrom(8192)
            except socket.timeout:
                continue
            except OSError:
                break
            self.received += 1
            self.last_ts = time.time()
            self.hosts.add(addr[0])
            parsed = parse_line(data)
            if not parsed["host"]:
                parsed["host"] = addr[0]
            matched = self._match(parsed)
            if matched:
                key = (parsed["host"], matched[:60])
                now = time.time()
                if now - self._recent.get(key, 0) < 60:   # one event per minute per pattern
                    continue
                self._recent[key] = now
                self.matched += 1
                severity = parsed["severity"] if parsed["severity"] != "info" else "medium"
                store.add_event(f"syslog {parsed['host']}", severity,
                                f"{parsed['message']}  [matched /{matched}/]")
                if len(self._recent) > 500:
                    cutoff = now - 600
                    self._recent = {k: v for k, v in self._recent.items() if v > cutoff}

    def _match(self, parsed):
        text = parsed["message"]
        for pattern, regex in self._patterns:
            if regex.search(text):
                return pattern
        return ""

    def status(self):
        return {
            "active": self.running,
            "received": self.received,
            "matched": self.matched,
            "hosts": sorted(self.hosts)[:20],
            "last_age": (time.time() - self.last_ts) if self.last_ts else None,
            "port": int(self.cfg.get("port") or 5514),
        }
