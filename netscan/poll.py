"""The monitoring engine: poll every device, keep state, raise and close incidents.

This is the piece that turns a one-off scan into a NOC view. Every poll interval
it probes each monitored device (ICMP with a TCP fallback, three samples), records
latency and loss, decides up/degraded/down, and drives an incident state machine:

    bad polls  >= open_after_bad_polls   -> incident opens (diagnosed, alerted)
    severity rises                       -> incident escalates (alerted again)
    good polls >= resolve_after_good_polls -> incident resolves automatically
"""

from __future__ import annotations

import re
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from . import ai, alerts, diagnose, netinfo, settings, store

MONITORED_TYPES = {"router", "switch", "access_point", "dvr", "nvr", "camera", "nas", "server"}

_TIME_RE = re.compile(r"time[=<]\s*([\d.]+)\s*ms", re.I)
_WIN_LOSS_RE = re.compile(r"\((\d+)%\s*loss\)", re.I)
_NIX_LOSS_RE = re.compile(r"([\d.]+)%\s*packet loss", re.I)
_RTT_RE = re.compile(r"=\s*([\d.]+)/([\d.]+)/([\d.]+)", re.I)


def probe(ip, timeout_ms=800, count=3, tcp_port=None):
    """Return (latency_ms, loss_pct, alive). ICMP first, TCP timing as fallback."""
    if netinfo.IS_WINDOWS:
        cmd = ["ping", "-n", str(count), "-w", str(timeout_ms), "-4", ip]
    else:
        cmd = ["ping", "-c", str(count), "-W", str(max(1, int(timeout_ms / 1000))), "-n", ip]
    out = netinfo.run(cmd, timeout=count * (timeout_ms / 1000.0) + 4)
    times = [float(x) for x in _TIME_RE.findall(out)]
    loss = None
    m = _WIN_LOSS_RE.search(out) or _NIX_LOSS_RE.search(out)
    if m:
        loss = float(m.group(1))
    avg = None
    m = _RTT_RE.search(out)
    if m:
        avg = float(m.group(2))
    if times:
        latency = sum(times) / len(times)
        if avg:
            latency = avg
        return round(latency, 1), (loss if loss is not None else round(100 * (count - len(times)) / count, 1)), True
    # ICMP blocked or host silent - fall back to a TCP connect timed by hand
    if tcp_port:
        start = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(timeout_ms / 1000.0)
            if sock.connect_ex((ip, tcp_port)) == 0:
                return round((time.time() - start) * 1000, 1), 0.0, True
        except Exception:
            pass
        finally:
            try:
                sock.close()
            except Exception:
                pass
    return 0.0, 100.0, False


class Poller(threading.Thread):
    def __init__(self, scanner, log=None):
        super().__init__(daemon=True, name="poller")
        self.scanner = scanner
        self.log = log or (lambda m: None)
        self._stop = threading.Event()
        self.lock = threading.RLock()
        self.incidents = {}          # id -> dict
        self.device_state = {}       # ip -> {"bad": n, "good": n, "incident": id|None, "sev": str}
        self.polls = 0
        self.last_poll_ts = 0.0
        self.next_poll_ts = 0.0
        self.poll_seconds = 0.0
        self._last_alert = {}

    # -- lifecycle -------------------------------------------------------
    def stop(self):
        self._stop.set()

    def run(self):
        self._stop.wait(6)  # let the first scan finish
        while not self._stop.is_set():
            cfg = settings.load()
            interval = max(15, int(cfg.get("poll_interval_seconds") or 60))
            started = time.time()
            try:
                self.poll_once()
            except Exception as exc:
                self.log(f"poll failed: {exc}")
            self.poll_seconds = round(time.time() - started, 1)
            self.next_poll_ts = time.time() + interval
            self._stop.wait(interval)

    # -- one poll --------------------------------------------------------
    def monitored(self):
        cfg = settings.load()
        mon = cfg.get("monitor") or {}
        allow = set(MONITORED_TYPES)
        if mon.get("printers", True):
            allow |= {"printer", "kot_printer", "scanner"}
        if mon.get("phones"):
            allow |= {"phone", "iot"}
        if mon.get("unknown"):
            allow.add("unknown")
        if not mon.get("servers", True):
            allow.discard("server")
        with self.scanner.lock:
            devices = [dict(d) for d in self.scanner.devices.values()]
        out = []
        for dev in devices:
            if dev.get("is_self"):
                continue
            if dev.get("type") in allow:
                out.append(dev)
        return out

    def _tcp_port(self, dev):
        for port in (dev.get("ports") or []):
            if port.get("port") in (80, 443, 22, 3389, 9100, 554, 8000, 23):
                return port["port"]
        return None

    def poll_once(self):
        if getattr(self.scanner, "standby", ""):
            return          # another Prahari watches this network (see Scanner.standby)
        cfg = settings.load()
        th = cfg.get("thresholds") or {}
        targets = self.monitored()
        internet = (cfg.get("monitor") or {}).get("internet_targets") or []

        jobs = [(d["ip"], self._tcp_port(d)) for d in targets]
        jobs += [(t.get("host"), 53) for t in internet if t.get("host")]

        results = {}
        if jobs:
            with ThreadPoolExecutor(max_workers=min(32, max(4, len(jobs)))) as pool:
                futures = {pool.submit(probe, ip, 800, 3, port): ip for ip, port in jobs}
                for fut, ip in futures.items():
                    try:
                        results[ip] = fut.result()
                    except Exception:
                        results[ip] = (0.0, 100.0, False)

        now = time.time()
        if now - getattr(self, "_last_wifi", 0) > 300:
            self._last_wifi = now
            try:
                self.scanner.refresh_wifi()
            except Exception:
                pass
            try:
                self.scanner.refresh_topology()
            except Exception:
                pass
            try:
                self.scanner.run_sensors()
            except Exception:
                pass
        sy = cfg.get("systems") or {}
        if sy.get("enabled", True):
            every = max(60, int(float(sy.get("interval_seconds") or 120)))
            if now - getattr(self, "_last_systems", 0) >= every:
                self._last_systems = now
                try:
                    self.scanner.refresh_systems()
                except Exception:
                    pass
        if now - getattr(self, "_last_escalation", 0) >= 60:
            self._last_escalation = now
            try:
                self.scanner.run_escalation()
            except Exception as exc:
                self.log(f"escalation pass failed: {exc}")
        cb = cfg.get("config_backup") or {}
        if cb.get("enabled"):
            every = max(1, int(float(cb.get("every_hours") or 24))) * 3600
            if now - getattr(self, "_last_config_backup", now - every + 600) >= every:
                self._last_config_backup = now
                try:
                    self.scanner.run_config_backup()
                except Exception:
                    pass
        self.polls += 1
        self.last_poll_ts = now
        states = {}

        for dev in targets:
            latency, loss, alive = results.get(dev["ip"], (0.0, 100.0, False))
            state = self._state_for(alive, latency, loss, th)
            states[dev["ip"]] = {"ip": dev["ip"], "state": state, "latency": latency, "loss": loss,
                                 "name": dev.get("label") or dev.get("hostname") or dev.get("type_label"),
                                 "type": dev.get("type"), "monitored": True}
            self._apply_to_device(dev["ip"], latency, loss, state, cfg)
            store.add_sample(dev["ip"], latency, loss, state)
            self._observe(dev, latency, loss)

        internet_states = []
        for target in internet:
            host = target.get("host")
            if not host:
                continue
            latency, loss, alive = results.get(host, (0.0, 100.0, False))
            state = self._state_for(alive, latency, loss, th)
            internet_states.append({"ip": host, "name": target.get("name") or host,
                                    "state": state, "latency": latency, "loss": loss,
                                    "monitored": True, "kind": "internet"})
            self._incident_machine(
                key="target:" + host,
                dev={"ip": host, "type": "internet", "type_label": "Internet target",
                     "label": target.get("name") or host},
                state=state, latency=latency, loss=loss,
                siblings=list(states.values()) + internet_states,
                internet=internet_states, th=th, cfg=cfg,
            )

        gateway_ip = (self.scanner.local or {}).get("gateway")
        gateway = dict(states.get(gateway_ip) or {"state": "unknown"})
        gateway["ip"] = gateway_ip

        for dev in targets:
            info = states.get(dev["ip"], {})
            self._incident_machine(
                key=dev["ip"], dev=dev, state=info.get("state", "unknown"),
                latency=info.get("latency", 0), loss=info.get("loss", 0),
                siblings=list(states.values()) + internet_states,
                internet=internet_states, th=th, cfg=cfg, gateway=gateway,
            )

        with self.scanner.lock:
            self.scanner.internet_state = internet_states
            self.scanner.gateway_state = gateway
        if self.polls % 50 == 0:
            store.prune(int(cfg.get("history_retention_days") or 14))

    # -- helpers ---------------------------------------------------------
    @staticmethod
    def _state_for(alive, latency, loss, th):
        if not alive or loss >= 100:
            return "down"
        if (loss >= th.get("loss_crit_pct", 10) or latency >= th.get("latency_crit_ms", 300)):
            return "degraded"
        if (loss >= th.get("loss_warn_pct", 3) or latency >= th.get("latency_warn_ms", 150)):
            return "degraded"
        return "up"

    def _observe(self, dev, latency, loss):
        """Feed the history that makes anomaly detection and forecasting possible."""
        try:
            eng = getattr(self.scanner, "anomaly", None)
            host = dev.get("host") or {}
            if host and dev.get("ip"):
                disk = 0.0
                for d in host.get("disks") or []:
                    disk = max(disk, d.get("used_pct") or 0)
                store.add_host_sample(dev["ip"], host.get("cpu_pct"),
                                      host.get("mem_pct"), disk)
            if eng is not None:
                name = (dev.get("label") or dev.get("hostname") or dev.get("ip"))
                found = eng.check_device(dev["ip"], name, latency, loss)
                if found:
                    eng.record(found)
        except Exception:
            pass

    def _apply_to_device(self, ip, latency, loss, state, cfg):
        with self.scanner.lock:
            dev = self.scanner.devices.get(ip)
            if not dev:
                return
            dev["latency_ms"] = latency
            dev["loss_pct"] = loss
            dev["state"] = state
            dev["last_poll"] = time.strftime("%H:%M:%S")
            hist = dev.setdefault("history", [])
            hist.append([int(time.time()), round(latency, 1), round(loss, 1)])
            keep = int(cfg.get("history_points") or 180)
            if len(hist) > keep:
                del hist[: len(hist) - keep]

    def _incident_machine(self, key, dev, state, latency, loss, siblings, internet, th,
                          cfg, gateway=None):
        st = self.device_state.setdefault(key, {"bad": 0, "good": 0, "incident": None,
                                                "sev": "", "state": ""})
        # a device behind a dead parent is not its own incident
        try:
            from . import sensors as sensors_mod
            parent_down, why = sensors_mod.parent_down(cfg, dev.get("ip") or "", self.device_state)
            if parent_down and state in ("down", "degraded"):
                if st.get("suppressed") != why:
                    st["suppressed"] = why
                    store.add_event("dependency", "info",
                                    f"{dev.get('label') or dev.get('ip')}: alert suppressed, {why}")
                st["state"] = state           # so devices behind THIS one are suppressed too
                return
            quiet, reason = sensors_mod.in_maintenance(cfg, ip=dev.get("ip") or "")
            if quiet and state in ("down", "degraded"):
                if st.get("suppressed") != reason:
                    st["suppressed"] = reason
                    store.add_event("maintenance", "info",
                                    f"{dev.get('label') or dev.get('ip')}: {state} during quiet hours "
                                    f"({reason}) - no alert")
                st["state"] = state
                return
            st["suppressed"] = ""
        except Exception:
            pass
        st["state"] = state
        bad = state in ("down", "degraded")
        if bad:
            st["bad"] += 1
            st["good"] = 0
        else:
            st["good"] += 1
            st["bad"] = 0

        severity = self._severity(dev, state, latency, loss, th)
        if st["incident"]:
            inc = self.incidents.get(st["incident"])
            if not inc:
                st["incident"] = None
            elif not bad and st["good"] >= th.get("resolve_after_good_polls", 3):
                self._resolve(inc, cfg)
                st["incident"] = None
                st["sev"] = ""
            elif bad and diagnose.SEVERITY_ORDER.get(severity, 0) > diagnose.SEVERITY_ORDER.get(inc["severity"], 0):
                self._escalate(inc, severity, state, latency, loss, siblings, internet, th, cfg)
                st["sev"] = severity
            else:
                inc["updated_ts"] = int(time.time())
                inc["last_state"] = state
                inc["last_latency"] = latency
                inc["last_loss"] = loss
            return

        if bad and st["bad"] >= th.get("open_after_bad_polls", 2):
            inc = self._open(key, dev, severity, state, latency, loss, siblings, internet, th, cfg)
            st["incident"] = inc["id"]
            st["sev"] = severity

    @staticmethod
    def _severity(dev, state, latency, loss, th):
        if state == "down":
            return "critical" if dev.get("type") in ("router", "switch", "access_point") else "high"
        if (loss >= th.get("loss_crit_pct", 10) or latency >= th.get("latency_crit_ms", 300)):
            return "high"
        return "medium"

    def _context(self, dev, state, latency, loss, siblings, internet, th, cfg):
        flow = getattr(self.scanner, "flow", None)
        traffic = []
        if flow:
            try:
                traffic = self.scanner.top_talkers(limit=3)
            except Exception:
                traffic = []
        return {
            "device": dev, "state": state, "latency": latency, "loss": loss,
            "siblings": siblings, "internet": internet, "gateway": self.scanner.gateway_state,
            "events": store.events(limit=40), "traffic": traffic, "thresholds": th,
            "data_sources": {
                "netflow": bool(flow and flow.status().get("packets")),
                "syslog": bool(getattr(self.scanner, "syslog", None) and
                               self.scanner.syslog.status().get("received")),
                "snmp": bool(getattr(self.scanner, "snmp_interfaces", None)),
            },
        }

    def _open(self, key, dev, severity, state, latency, loss, siblings, internet, th, cfg):
        ctx = self._context(dev, state, latency, loss, siblings, internet, th, cfg)
        diag = diagnose.diagnose(ctx)
        name = dev.get("label") or dev.get("hostname") or dev.get("type_label") or dev.get("ip")
        inc = {
            "id": f"INC-{int(time.time())}-{abs(hash(key)) % 9999:04d}",
            "device_ip": dev.get("ip"), "device_name": name, "device_type": dev.get("type"),
            "severity": severity, "state": "open",
            "title": diag.get("title") or f"{name} is {state}",
            "opened_ts": int(time.time()), "updated_ts": int(time.time()), "closed_ts": None,
            "opened_human": time.strftime("%Y-%m-%d %H:%M:%S"),
            "diagnosis": diag,
            "last_state": state, "last_latency": latency, "last_loss": loss,
            "timeline": [{"ts": int(time.time()),
                          "text": f"Opened: {state} (latency {round(latency, 1)} ms, loss {round(loss, 1)}%)"}],
        }
        self.incidents[inc["id"]] = inc
        store.save_incident(inc)
        store.add_event("monitor", severity, f"Incident opened: {inc['title']}")
        self.log(f"incident {inc['id']} opened: {inc['title']} [{severity}]")
        alerts.notify_incident(cfg, inc, self.log)
        ai.refine_in_background(inc, ctx, store.save_incident, self.log)
        return inc

    def _escalate(self, inc, severity, state, latency, loss, siblings, internet, th, cfg):
        dev = {"ip": inc["device_ip"], "type": inc.get("device_type"),
               "type_label": inc.get("device_type"), "label": inc.get("device_name")}
        ctx = self._context(dev, state, latency, loss, siblings, internet, th, cfg)
        diag = diagnose.diagnose(ctx)
        inc.update(severity=severity, state="escalated", updated_ts=int(time.time()),
                   diagnosis=diag, title=diag.get("title") or inc["title"])
        inc["timeline"].append({"ts": int(time.time()),
                                "text": f"Escalated to {severity}: {state} "
                                        f"(latency {round(latency, 1)} ms, loss {round(loss, 1)}%)"})
        store.save_incident(inc)
        store.add_event("monitor", severity, f"Incident escalated: {inc['title']}")
        self.log(f"incident {inc['id']} escalated to {severity}")
        alerts.notify_incident(cfg, inc, self.log)
        ai.refine_in_background(inc, ctx, store.save_incident, self.log)

    def _resolve(self, inc, cfg):
        inc.update(state="resolved", closed_ts=int(time.time()), updated_ts=int(time.time()))
        inc["timeline"].append({"ts": int(time.time()), "text": "Resolved: device answered "
                                                              "the good-poll threshold again"})
        store.save_incident(inc)
        store.add_event("monitor", "info", f"Incident resolved: {inc['title']}")
        self.log(f"incident {inc['id']} resolved")
        alerts.notify_incident(cfg, inc, self.log)

    # -- views -----------------------------------------------------------
    def snapshot(self):
        with self.lock:
            items = list(self.incidents.values())
        items.sort(key=lambda i: (i.get("state") == "resolved", -i.get("opened_ts", 0)))
        return {
            "polls": self.polls,
            "last_poll_age": (time.time() - self.last_poll_ts) if self.last_poll_ts else None,
            "next_poll_in": max(0, int(self.next_poll_ts - time.time())) if self.next_poll_ts else None,
            "poll_seconds": self.poll_seconds,
            "incidents": items[:60],
            "open": [i for i in items if i.get("state") != "resolved"],
        }

    def health(self):
        with self.scanner.lock:
            devices = [d for d in self.scanner.devices.values() if d.get("state")]
        monitored = [d for d in devices if d.get("state") != "unknown"]
        up = sum(1 for d in monitored if d.get("state") == "up")
        degraded = sum(1 for d in monitored if d.get("state") == "degraded")
        down = sum(1 for d in monitored if d.get("state") == "down")
        total = len(monitored)
        score = 100 if not total else max(0, round(100 * (up + 0.5 * degraded) / total))
        with self.lock:
            open_inc = [i for i in self.incidents.values() if i.get("state") != "resolved"]
        return {
            "score": score, "up": up, "degraded": degraded, "down": down, "monitored": total,
            "open_incidents": len(open_inc),
            "critical": sum(1 for i in open_inc if i.get("severity") == "critical"),
        }
