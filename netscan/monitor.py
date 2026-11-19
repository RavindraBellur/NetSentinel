"""Bandwidth attribution.

Three independent collectors, all optional and all best-effort:

1. `SnmpPoller`  - polls byte counters on the router/switch (ifHCInOctets /
   ifHCOutOctets) and maps MAC addresses to switch ports via the bridge MIB, so
   a device's traffic can be read off the port it is plugged into. This is the
   only method that gives true per-device internet usage without extra drivers.
2. `CapturePoller` - passive packet capture with scapy (needs Npcap on Windows).
   Counts bytes per LAN IP that go to/from public addresses. Accurate for what
   passes the capture point; run it on the router, a SPAN port, or the machine
   whose traffic you care about.
3. `LocalRatePoller` - this PC's own NIC throughput (psutil).
"""

from __future__ import annotations

import re
import threading
import time

from . import netinfo, snmp

WAN_HINTS = ("wan", "internet", "pppoe", "ppp", "uplink", "ether1", "vlan2", "fiber", "gpon")
PUBLIC_PREFIXES = ("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
                   "172.2", "172.30.", "172.31.", "127.", "169.254.", "100.64.",
                   "224.", "239.", "255.", "0.")


def is_private(ip: str) -> bool:
    return ip.startswith(PUBLIC_PREFIXES)


WAN_RE = re.compile(
    r"\bwan\d*\b|internet|pppoe|\bppp\d*|gpon|fib(er|re)?|\bisp\b|uplink|"
    r"^ether1$|^sfp[\w./-]*$|airtel|jio|bsnl|\bact\b|broadband|leased", re.I)
SKIP_RE = re.compile(
    r"^lo\d*$|loopback|null|^vlan|^bridge|^br\d|^tun|^gre|^ipsec|^wg\d|cpu|stack|^vl\d|^po\d", re.I)


class SnmpPoller(threading.Thread):
    """Read interface counters and the MAC table from SNMP-capable network gear.

    Two things make the port -> device mapping work on real office networks:
      * BRIDGE-MIB (dot1dTpFdbPort) for flat switches;
      * Q-BRIDGE-MIB (dot1qTpFdbPort) for VLAN-tagged networks, where the plain
        bridge table is empty. Without it, per-port usage on a VLAN'd switch
        shows traffic but cannot say which device it belongs to.
    Walks use GETBULK, so a 48-port switch is read in a handful of packets.
    """

    def __init__(self, scanner, interval=30.0, fdb_interval=300.0):
        super().__init__(daemon=True, name="snmp-poller")
        self.scanner = scanner
        self.interval = interval
        self.fdb_interval = fdb_interval
        self._prev = {}          # (host, ifindex) -> (ts, in_octets, out_octets)
        self._fdb_cache = {}     # host -> (ts, {mac: ifindex})
        self._stop = threading.Event()
        self.errors = 0
        self.last_ok = 0.0

    def stop(self):
        self._stop.set()

    def _targets(self):
        targets = []
        with self.scanner.lock:
            for dev in self.scanner.devices.values():
                if dev.get("snmp_community") or dev.get("is_gateway"):
                    targets.append((dev["ip"], dev.get("snmp_community") or "public"))
        return targets[:8]

    # -- MAC -> switch port --------------------------------------------------
    def _mac_port_map(self, host, community):
        cached = self._fdb_cache.get(host)
        now = time.time()
        if cached and now - cached[0] < self.fdb_interval:
            return cached[1]

        mapping = {}
        base_port_if = {}
        for oid, _tag, value in snmp.walk_bulk(host, snmp.OID_BASE_PORT_IF, community, max_rows=400):
            if isinstance(value, int):
                base_port_if[oid.rsplit(".", 1)[-1]] = value
        if not base_port_if:
            return {}

        # flat bridge first
        ports = {}
        for oid, _tag, value in snmp.walk_bulk(host, snmp.OID_FDB_PORT, community, max_rows=1500):
            ports[oid.rsplit(".", 1)[-1]] = value
        for oid, _tag, value in snmp.walk_bulk(host, snmp.OID_FDB_ADDRESS, community, max_rows=1500):
            if not isinstance(value, str):
                continue
            mac = value.replace(" ", ":").lower()
            ifindex = base_port_if.get(str(ports.get(oid.rsplit(".", 1)[-1])))
            if ifindex:
                mapping[mac] = int(ifindex)

        # Q-BRIDGE: index = <fdb-id>.<6 MAC octets>
        for oid, _tag, value in snmp.walk_bulk(host, snmp.OID_Q_FDB_PORT, community, max_rows=2000):
            if not isinstance(value, int):
                continue
            parts = oid.split(".")
            if len(parts) < 7:
                continue
            octets = parts[-6:]
            try:
                mac = ":".join(f"{int(o):02x}" for o in octets)
            except ValueError:
                continue
            ifindex = base_port_if.get(str(value))
            if ifindex:
                mapping.setdefault(mac, int(ifindex))

        self._fdb_cache[host] = (now, mapping)
        return mapping

    # -- one poll ------------------------------------------------------------
    def poll_once(self):
        for host, community in self._targets():
            try:
                self._poll_host(host, community)
                self.last_ok = time.time()
            except Exception:
                self.errors += 1
                continue

    def _poll_host(self, host, community):
        descrs = {}
        for base in (snmp.OID_IF_NAME, snmp.OID_IF_ALIAS, snmp.OID_IF_DESCR):
            for oid, _tag, value in snmp.walk_bulk(host, base, community, max_rows=300):
                if isinstance(value, str) and value.strip():
                    descrs.setdefault(oid.rsplit(".", 1)[-1], value.strip())
            if descrs:
                break
        if not descrs:
            return

        counters = {}
        for base, key in ((snmp.OID_IF_HC_IN, "in"), (snmp.OID_IF_HC_OUT, "out")):
            rows = snmp.walk_bulk(host, base, community, max_rows=400)
            if not rows:
                base = snmp.OID_IF_IN_OCTETS if key == "in" else snmp.OID_IF_OUT_OCTETS
                rows = snmp.walk_bulk(host, base, community, max_rows=400)
            for oid, _tag, value in rows:
                if isinstance(value, int):
                    counters.setdefault(oid.rsplit(".", 1)[-1], {})[key] = value

        now = time.time()
        iface_rates = {}
        for ifindex, values in counters.items():
            prev = self._prev.get((host, ifindex))
            self._prev[(host, ifindex)] = (now, values.get("in", 0), values.get("out", 0))
            if not prev:
                continue
            dt = now - prev[0]
            if dt <= 0.5:
                continue
            delta_in = values.get("in", 0) - prev[1]
            delta_out = values.get("out", 0) - prev[2]
            if delta_in < 0 or delta_out < 0:      # counter wrap / reboot
                continue
            name = descrs.get(ifindex, "if" + ifindex)
            iface_rates[ifindex] = {
                "ifindex": int(ifindex),
                "name": name,
                "rx_bps": delta_in * 8 / dt,
                "tx_bps": delta_out * 8 / dt,
                "wan": bool(WAN_RE.search(name)) and not SKIP_RE.search(name),
                "internal": bool(SKIP_RE.search(name)),
            }

        mac_map = self._mac_port_map(host, community)
        by_port = {}
        with self.scanner.lock:
            for dev in self.scanner.devices.values():
                ifindex = mac_map.get((dev.get("mac") or "").lower())
                if ifindex:
                    by_port[ifindex] = dev.get("label") or dev.get("hostname") or dev.get("type_label") or dev["ip"]
            self.scanner.snmp_interfaces[host] = sorted(
                iface_rates.values(), key=lambda r: -(r["rx_bps"] + r["tx_bps"])
            )
            self.scanner.snmp_port_map[host] = {
                mac: ifindex for mac, ifindex in mac_map.items()
            }
            for dev in self.scanner.devices.values():
                ifindex = mac_map.get((dev.get("mac") or "").lower())
                if ifindex and ifindex in iface_rates:
                    rate = iface_rates[ifindex]
                    dev["rx_bps"] = rate["rx_bps"]
                    dev["tx_bps"] = rate["tx_bps"]
                    dev["rate_source"] = f"SNMP {host} port {rate['name']}"
            for ifindex, rate in iface_rates.items():
                if rate["wan"]:
                    self.scanner.wan_rate = {
                        "rx_bps": rate["rx_bps"], "tx_bps": rate["tx_bps"],
                        "source": f"SNMP {host} {rate['name']}",
                        "interface": rate["name"],
                    }
            for entry in self.scanner.snmp_interfaces.get(host, []):
                entry["device"] = by_port.get(entry["ifindex"], "")

    def run(self):
        self._stop.wait(5)
        while not self._stop.is_set():
            self.poll_once()
            self._stop.wait(self.interval)


class CapturePoller(threading.Thread):
    """Passive capture: bytes per LAN IP talking to the internet."""

    def __init__(self, scanner, window=6.0):
        super().__init__(daemon=True, name="capture-poller")
        self.scanner = scanner
        self.window = window
        self._stop = threading.Event()
        self._bytes = {}  # ip -> {"rx": n, "tx": n}
        self._last_flush = time.time()

    def stop(self):
        self._stop.set()

    def available(self):
        try:
            import scapy.all  # noqa: F401
            return True, ""
        except Exception as e:
            return False, f"scapy not installed ({e.__class__.__name__})"

    def _handle(self, pkt):
        try:
            from scapy.all import IP  # type: ignore

            if IP not in pkt:
                return
            src, dst = pkt[IP].src, pkt[IP].dst
            size = len(pkt)
            with self.scanner.lock:
                if not is_private(dst) and is_private(src):
                    entry = self._bytes.setdefault(src, {"rx": 0, "tx": 0})
                    entry["tx"] += size
                elif not is_private(src) and is_private(dst):
                    entry = self._bytes.setdefault(dst, {"rx": 0, "tx": 0})
                    entry["rx"] += size
        except Exception:
            pass

    def _flush(self):
        now = time.time()
        dt = now - self._last_flush
        if dt < 2:
            return
        with self.scanner.lock:
            for ip, counters in list(self._bytes.items()):
                dev = self.scanner.devices.get(ip)
                if dev is None:
                    continue
                dev["rx_bps"] = counters["rx"] * 8 / dt
                dev["tx_bps"] = counters["tx"] * 8 / dt
                dev["rate_source"] = "passive capture"
            self._bytes = {}
            self._last_flush = now

    def run(self):
        ok, why = self.available()
        if not ok:
            with self.scanner.lock:
                self.scanner.capture_error = why
            return
        try:
            from scapy.all import sniff  # type: ignore
        except Exception as e:
            with self.scanner.lock:
                self.scanner.capture_error = f"capture unavailable: {e}"
            return

        with self.scanner.lock:
            self.scanner.capture_active = True
            self.scanner.capture_error = ""

        def ticker():
            while not self._stop.is_set():
                time.sleep(1.0)
                try:
                    self._flush()
                except Exception:
                    pass

        threading.Thread(target=ticker, daemon=True, name="capture-flush").start()
        while not self._stop.is_set():
            try:
                sniff(prn=self._handle, store=False, timeout=3, filter="ip")
            except Exception as e:
                msg = str(e)
                with self.scanner.lock:
                    self.scanner.capture_active = False
                    if "wpcap" in msg.lower() or "npcap" in msg.lower() or "winpcap" in msg.lower():
                        self.scanner.capture_error = (
                            "Npcap is not installed - install Npcap (npcap.com) and run as Administrator "
                            "for per-device traffic capture."
                        )
                    else:
                        self.scanner.capture_error = f"capture stopped: {msg[:160]}"
                return


class LocalRatePoller(threading.Thread):
    def __init__(self, scanner, interval=3.0):
        super().__init__(daemon=True, name="local-rate")
        self.scanner = scanner
        self.interval = interval
        self._stop = threading.Event()

    def stop(self):
        self._stop.set()

    def run(self):
        while not self._stop.is_set():
            data = netinfo.pc_interface_rates()
            with self.scanner.lock:
                self.scanner.pc_rates = data
            self._stop.wait(self.interval)
