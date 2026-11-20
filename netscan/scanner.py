"""Scan orchestration and the live state the dashboard reads."""

from __future__ import annotations

import ipaddress
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from . import (alerts, anomaly, auth, backup as backup_mod, discovery, fingerprint,
               heartbeat as hb_mod, monitor, netflow, netinfo,
               defaults as defaults_mod, ports as ports_mod, posture,
               remediation as remediation_mod,
               sensors as sensors_mod,
               telegram as telegram_mod,
               topology as topology_mod, vault as vault_mod,
               wifi as wifi_mod,
               oui, poll, remote, settings, sites, store, syslogrx, wan)


class Scanner:
    def __init__(self, subnet=None, community="public", deep=True, capture=True, workers=48,
                 allow_remote_control=False, remote_control=True, monitoring=True):
        self.lock = threading.RLock()
        self.subnet_override = subnet
        self.community = community
        self.deep = deep
        self.enable_capture = capture
        self.workers = workers
        self.monitoring = monitoring
        self.remote_control = remote_control
        self.allow_remote_control = allow_remote_control

        self.devices = {}
        self.local = {}
        self.public = {}
        self.status = {
            "phase": "idle", "message": "Starting up", "done": 0, "total": 0,
            "scan_running": False, "last_scan": "", "scan_count": 0,
        }
        self.warnings = []
        self.snmp_interfaces = {}
        self.snmp_port_map = {}
        self.wan_rate = {}
        self.pc_rates = {"available": False, "interfaces": []}
        self.capture_error = ""
        self.capture_active = False
        self.internet_state = []
        self.gateway_state = {}
        self.started = time.strftime("%Y-%m-%d %H:%M:%S")

        self.poller = None
        self.flow = None
        self.syslog = None
        self.wan_watcher = None
        self.branch_reporter = None
        self.lost_contact = None
        self.agent = None
        self.heartbeat = None
        self._outbox = None
        self.backup = None
        self.report_mailer = None
        self.telegram = None
        self._host_events = {}
        self.anomaly = anomaly.AnomalyEngine(log=self.log)
        self.wifi_state = {"measured": [], "poor": [], "fair": [], "access_points": 0,
                           "ts": 0}
        self.topology = {"nodes": [], "links": [], "stats": {}, "ts": 0}
        self.defaults_state = {"state": "idle", "checked": 0, "findings": [], "ts": 0}
        self.sensors = sensors_mod.SensorRunner(log=self.log)
        self._scan_thread = None
        self._snmp_poller = None
        self._capture = None
        self._local_rate = None
        self._auto_scan = None

    # ---- lifecycle --------------------------------------------------------

    def start_scan(self):
        with self.lock:
            if self.status.get("scan_running"):
                return False
            self.status["scan_running"] = True
        self._scan_thread = threading.Thread(target=self._scan, daemon=True, name="scan")
        self._scan_thread.start()
        return True

    def ensure_branch_reporter(self):
        """Start reporting to the hub/portal as soon as it is configured (also right after Save)."""
        if self.branch_reporter is not None and self.branch_reporter.is_alive():
            return
        if sites.branch_target()[0]:
            self.branch_reporter = sites.BranchReporter(self, log=self.log)
            self.branch_reporter.start()

    def start_monitors(self):
        cfg = settings.load()
        if self.monitoring and self.poller is None:
            self.poller = poll.Poller(self, log=self.log)
            self.poller.start()
        if self.flow is None and (cfg.get("netflow") or {}).get("enabled", True):
            self.flow = netflow.FlowCollector(self, cfg.get("netflow") or {}, self.log)
            self.flow.start()
        if self.syslog is None and (cfg.get("syslog") or {}).get("enabled", True):
            self.syslog = syslogrx.SyslogReceiver(self, cfg.get("syslog") or {}, self.log)
            self.syslog.start()
        self.ensure_branch_reporter()
        hub_cfg = settings.get("hub") or {}
        if hub_cfg.get("enabled") and self.lost_contact is None:
            self.lost_contact = sites.LostContactWatcher(self, log=self.log)
            self.lost_contact.start()
        if self._outbox is None:
            import threading as _th
            def _flush_loop():
                import time as _t
                while True:
                    _t.sleep(60)
                    try:
                        alerts.flush(settings.load(), log=self.log)
                    except Exception:
                        pass
            self._outbox = _th.Thread(target=_flush_loop, daemon=True, name="outbox")
            self._outbox.start()
        if self.report_mailer is None and (settings.get("sla_email") or {}).get("enabled"):
            self.report_mailer = scheduled_mod.ReportScheduler(log=self.log)
            self.report_mailer.start()
        if self.backup is None and (settings.get("backup") or {}).get("enabled", True):
            self.backup = backup_mod.BackupThread(log=self.log)
            self.backup.start()
        if self.telegram is None and (settings.get("telegram") or {}).get("enabled"):
            self.telegram = telegram_mod.TelegramBot(self, log=self.log)
            self.telegram.start()
        if self.heartbeat is None and (settings.get("heartbeat") or {}).get("enabled"):
            self.heartbeat = hb_mod.Heartbeat(log=self.log)
            self.heartbeat.start()
        if self.wan_watcher is None:
            self.wan_watcher = wan.WanWatcher(self, log=self.log)
            self.wan_watcher.start()
        if self._snmp_poller is None:
            self._snmp_poller = monitor.SnmpPoller(self)
            self._snmp_poller.start()
        if self._local_rate is None:
            self._local_rate = monitor.LocalRatePoller(self)
            self._local_rate.start()
        if self.enable_capture and self._capture is None:
            self._capture = monitor.CapturePoller(self)
            self._capture.start()
        interval = int((cfg.get("discovery") or {}).get("interval_minutes") or 0)
        if interval > 0 and self._auto_scan is None:
            self._auto_scan = threading.Thread(target=self._rescan_loop, args=(interval,),
                                               daemon=True, name="auto-scan")
            self._auto_scan.start()

    def _rescan_loop(self, minutes):
        while True:
            time.sleep(max(120, minutes * 60))
            try:
                self.start_scan()
            except Exception:
                pass

    def stop_monitors(self):
        for thread in (self.poller, self.flow, self.syslog, self.wan_watcher, self.heartbeat,
                       self.backup, self.telegram, self.report_mailer,
                       self.branch_reporter, self.lost_contact,
                       self._snmp_poller, self._capture, self._local_rate):
            if thread is not None:
                try:
                    thread.stop()
                except Exception:
                    pass

    def accept_branch_report(self, payload, token):
        """Hub side: authenticate a branch by token, then store its summary."""
        name = sites.site_for_token(settings.load(), token)
        if not name:
            return {"ok": False, "message": "unknown branch token"}, 403
        payload = dict(payload or {})
        payload["site"] = name
        sites.ingest(payload)
        reply = {"ok": True, "site": name,
                 "hub": settings.get("site_name") or "head office"}
        # tell the branch about a published build it should be running
        from . import upgrade as upgrade_mod
        offer = upgrade_mod.hub_reply(payload.get("version"))
        if offer:
            reply["update"] = offer
        return reply, 200

    def ingest_agent(self, payload):
        """A host agent reported metrics: store them and flag thresholds."""
        cfg = settings.load()
        th = cfg.get("hosts") or {}
        ip = (payload.get("ip") or "").strip()
        host = (payload.get("host") or ip or "host").strip()[:64]
        store.save_host(ip or host, host, payload)

        alerts = []
        cpu = payload.get("cpu_pct")
        if cpu is not None and cpu >= th.get("cpu_warn_pct", 90):
            alerts.append(f"CPU at {cpu}%")
        mem = payload.get("mem_pct")
        if mem is not None and mem >= th.get("mem_warn_pct", 92):
            alerts.append(f"memory at {mem}%")
        for disk in payload.get("disks") or []:
            if (disk.get("used_pct") or 0) >= th.get("disk_warn_pct", 90):
                alerts.append(f"disk {disk.get('mount')} at {disk.get('used_pct')}% "
                              f"({disk.get('free_gb')} GB free)")
        stopped = [s["name"] for s in (payload.get("services") or [])
                   if (s.get("state") or "").lower() in ("stopped", "stop_pending")
                   and any(k in s["name"].lower() for k in
                           ("spooler", "dns", "lanman", "w32time", "w3svc", "sql", "dhcp"))]
        if stopped:
            alerts.append("services stopped: " + ", ".join(stopped[:4]))

        if alerts:
            key = (ip or host, "|".join(sorted(alerts))[:80])
            now = time.time()
            if now - self._host_events.get(key, 0) > 900:      # one event per 15 min
                self._host_events[key] = now
                store.add_event(f"agent {host}", "medium", "; ".join(alerts)[:300])
        with self.lock:
            dev = self.devices.get(ip)
            if dev is not None:
                dev["host"] = payload
        return {"ok": True, "host": host, "alerts": alerts}

    def host_view(self):
        cfg = settings.load()
        th = cfg.get("hosts") or {}
        stale_after = int(th.get("stale_minutes") or 10) * 60
        now = time.time()
        with self.lock:
            devices = {d["ip"]: d for d in self.devices.values()}
        rows = []
        for item in store.hosts():
            payload = item.get("payload") or {}
            age = int(now - (item.get("updated_ts") or 0))
            worst_disk = 0
            for disk in payload.get("disks") or []:
                worst_disk = max(worst_disk, disk.get("used_pct") or 0)
            warnings = []
            if (payload.get("cpu_pct") or 0) >= th.get("cpu_warn_pct", 90):
                warnings.append("cpu")
            if (payload.get("mem_pct") or 0) >= th.get("mem_warn_pct", 92):
                warnings.append("memory")
            if worst_disk >= th.get("disk_warn_pct", 90):
                warnings.append("disk")
            if age > stale_after:
                warnings.append("stale")
            dev = devices.get(item.get("ip"), {})
            rows.append({
                "ip": item.get("ip"), "host": item.get("host"), "age": age,
                "stale": age > stale_after, "warnings": warnings,
                "cpu_pct": payload.get("cpu_pct"), "mem_pct": payload.get("mem_pct"),
                "mem_used_mb": payload.get("mem_used_mb"),
                "mem_total_mb": payload.get("mem_total_mb"),
                "disks": payload.get("disks") or [],
                "worst_disk_pct": round(worst_disk, 1),
                "uptime_hours": payload.get("uptime_hours"),
                "os": payload.get("os"), "top": payload.get("top") or [],
                "services": payload.get("services") or [],
                "device_type": dev.get("type_label", ""),
                "device_name": dev.get("label") or dev.get("hostname") or item.get("host"),
            })
        rows.sort(key=lambda r: (-len(r["warnings"]), r["host"] or ""))
        return rows

    def check_default_passwords(self):
        """Run the factory-password check in the background (it takes seconds per device)."""
        if self.defaults_state.get("state") == "running":
            return self.defaults_state
        cfg = settings.load()
        ok, why = defaults_mod.allowed(cfg, "0.0.0.0")     # config-level guards only
        if not ((cfg.get("defaults_check") or {}).get("enabled")
                and (cfg.get("defaults_check") or {}).get("i_own_this_network")):
            self.defaults_state = {"state": "refused", "checked": 0, "findings": [],
                                   "ts": int(time.time()), "why": why}
            return self.defaults_state

        def worker():
            self.defaults_state = {"state": "running", "checked": 0, "findings": [],
                                   "ts": int(time.time())}
            try:
                with self.lock:
                    devices = list(self.devices.values())
                result = defaults_mod.summary(devices, cfg)
                self.defaults_state = {"state": "done", "checked": result["checked"],
                                       "findings": result["findings"],
                                       "ts": int(time.time())}
                for f in result["findings"]:
                    if f["severity"] == "critical":
                        store.add_event("defaults", "high", f["text"])
            except Exception as exc:
                self.defaults_state = {"state": "error", "checked": 0, "findings": [],
                                       "ts": int(time.time()), "why": str(exc)[:140]}

        threading.Thread(target=worker, daemon=True, name="defaults-check").start()
        return self.defaults_state

    def refresh_topology(self):
        """Walk LLDP/CDP on the switches and APs to rebuild the map."""
        try:
            with self.lock:
                devices = list(self.devices.values())
            self.topology = topology_mod.build(devices)
        except Exception as exc:
            self.topology = dict(self.topology, error=str(exc)[:120])
        return self.topology

    def run_sensors(self, wait=False):
        """Poll the user-defined sensors in their own thread, so a slow website never delays
        the device poll. Returns the changes when wait=True (tests), else None."""
        if getattr(self, "_sensor_thread", None) is not None and self._sensor_thread.is_alive():
            return None
        result = {}

        def work():
            result["changed"] = self._run_sensors_now()
        self._sensor_thread = threading.Thread(target=work, daemon=True, name="sensors")
        self._sensor_thread.start()
        if wait:
            self._sensor_thread.join()
            return result.get("changed", [])
        return None

    def _run_sensors_now(self):
        # 30-day retention for sensor history, applied once a day
        if time.time() - getattr(self, "_sensor_pruned", 0) > 86400:
            self._sensor_pruned = time.time()
            try:
                store.prune_sensor_samples(30)
            except Exception:
                pass
        try:
            changed = self.sensors.run_once()
        except Exception as exc:
            self.log(f"sensor run failed: {exc}")
            return []
        for item in changed:
            if item["state"] in (sensors_mod.DOWN, sensors_mod.WARN):
                down = item["state"] == sensors_mod.DOWN
                try:
                    alerts.notify_incident(settings.load(), {
                        "id": f"SEN-{item['id']}", "severity": "high" if down else "medium",
                        "title": f"{item['name']} is {'down' if down else 'in warning'}",
                        "device_name": item["name"],
                        "device_ip": item.get("target", ""),
                        "diagnosis": {"root_cause": item["message"], "confidence": 100,
                                      "actions": ["Open the Sensors tab for the history",
                                                  "Check the service on the host"]}},
                        log=self.log)
                except Exception:
                    pass
        return changed

    def refresh_wifi(self):
        """Called by the poller every few minutes: read the APs' dot11 counters."""
        try:
            if not (settings.get("wifi") or {}).get("enabled", True):
                return self.wifi_state
            with self.lock:
                devices = list(self.devices.values())
            state = wifi_mod.summary(devices)
            state["ts"] = int(time.time())
            self.wifi_state = state
        except Exception as exc:
            self.wifi_state = dict(self.wifi_state, error=str(exc)[:120])
        return self.wifi_state

    def insights(self):
        """Anomalies, forecasts and the security posture score."""
        out = {"anomalies": [], "forecasts": [], "posture": {"score": 100, "findings": [],
                                                             "counts": {}, "total": 0}}
        try:
            out.update(self.anomaly.view())
        except Exception as exc:
            out["error"] = str(exc)[:120]
        out["wifi"] = self.wifi_state
        out["topology"] = self.topology
        try:
            with self.lock:
                devices = list(self.devices.values())
            out["exposure"] = ports_mod.exposure(devices)
        except Exception as exc:
            out["exposure"] = {"findings": [], "counts": {}, "total": 0, "error": str(exc)[:120]}
        out["defaults"] = self.defaults_state
        try:
            out["sensors"] = self.sensors.view()
        except Exception as exc:
            out["sensors"] = {"sensors": [], "counts": {}, "total": 0, "error": str(exc)[:120]}
        try:
            with self.lock:
                devices = list(self.devices.values())
            cfg = settings.load()
            tls_on = bool((cfg.get("tls") or {}).get("enabled"))
            auth_on = bool((cfg.get("auth") or {}).get("enabled")
                           or (cfg.get("oidc") or {}).get("enabled"))
            self_findings = posture.self_check(
                cfg, tls_on=tls_on, auth_on=auth_on,
                users=store.user_count(), two_factor_users=store.totp_enabled_count())
            self_findings += posture.snmp_version_finding(cfg)
            out["posture"] = posture.summarise(devices, self_findings)
        except Exception as exc:
            out["posture"]["error"] = str(exc)[:120]
        return out

    def audit(self, user, action, target=""):
        try:
            store.add_event(f"audit {user}", "info", f"{action} {target}".strip())
        except Exception:
            pass

    def log(self, message):
        try:
            store.add_event("netsentinel", "info", message)
        except Exception:
            pass

    # ---- views ------------------------------------------------------------

    def snapshot(self):
        with self.lock:
            devices = [dict(d) for d in self.devices.values()]
            devices.sort(key=_sort_key)
            for dev in devices:
                try:
                    dev["remote"] = remote.actions_for(dev)
                except Exception:
                    dev["remote"] = []
                dev["history"] = (dev.get("history") or [])[-60:]
        cfg = settings.load()
        poller = self.poller.snapshot() if self.poller else {}
        health = self.poller.health() if self.poller else _basic_health(devices)
        traffic = self.traffic_view()
        return {
            "local": self.local,
            "public": self.public,
            "status": dict(self.status),
            "devices": devices,
            "counts": _counts(devices),
            "health": health,
            "monitor": {
                "polls": poller.get("polls", 0),
                "last_poll_age": poller.get("last_poll_age"),
                "next_poll_in": poller.get("next_poll_in"),
                "poll_seconds": poller.get("poll_seconds"),
                "interval": cfg.get("poll_interval_seconds"),
                "enabled": bool(self.poller),
            },
            "incidents": poller.get("incidents", []),
            "open_incidents": poller.get("open", []),
            "events": store.events(limit=120),
            "traffic": traffic,
            "sources": self.sources_view(),
            "wan_rate": dict(self.wan_rate),
            "pc_rates": self.pc_rates,
            "snmp_interfaces": self.snmp_interfaces,
            "capture": {"active": self.capture_active, "error": self.capture_error},
            "remote_policy": {"enabled": self.remote_control,
                              "from_other_devices": self.allow_remote_control},
            "internet": self.internet_state,
            "gateway": self.gateway_state,
            "wan": self.wan_watcher.snapshot() if self.wan_watcher else {"ips": []},
            "sites": sites.hub_overview(self),
            "hosts": self.host_view(),
            "insights": self.insights(),
            "heartbeat": self.heartbeat.state if self.heartbeat else {"enabled": False},
            "outbox": store.outbox_stats(),
            "backup": backup_mod.status(),
            "sla_email": {"enabled": bool((settings.get("sla_email") or {}).get("enabled")),
                          "last_sent": (settings.get("sla_email") or {}).get("last_sent", ""),
                          "error": (self.report_mailer.last_error
                                    if self.report_mailer else "")},
            "vault": vault_mod.status(),
            "remediation": remediation_mod.status(),
            "telegram": ({"enabled": True, "handled": self.telegram.handled,
                          "error": self.telegram.last_error} if self.telegram
                         else {"enabled": False}),
            "branch": self.branch_reporter.status() if self.branch_reporter else {},
            "settings": settings.public_view(),
            "users": store.list_users(),
            "site": cfg.get("site_name") or "",
            "warnings": list(self.warnings),
            "started": self.started,
        }

    def sources_view(self):
        out = {}
        if self.flow:
            out["netflow"] = self.flow.status()
        if self.syslog:
            out["syslog"] = self.syslog.status()
        out["snmp"] = {"interfaces": len(self.snmp_interfaces),
                       "gateway_answered": bool(self.snmp_interfaces)}
        out["capture"] = {"active": self.capture_active, "error": self.capture_error}
        return out

    def traffic_view(self):
        """Per-device internet usage, best available source first."""
        rates = {}
        source = "none"
        if self.flow:
            try:
                rates = self.flow.rates()
                if rates:
                    source = "netflow"
            except Exception:
                rates = {}
        if not rates:
            with self.lock:
                for dev in self.devices.values():
                    if dev.get("rx_bps") or dev.get("tx_bps"):
                        rates[dev["ip"]] = {
                            "down_bps": dev.get("rx_bps", 0), "up_bps": dev.get("tx_bps", 0),
                            "down_bytes_today": 0, "up_bytes_today": 0,
                        }
                        source = dev.get("rate_source") or "snmp"
        with self.lock:
            devices = {d["ip"]: d for d in self.devices.values()}
        top = []
        for ip, rate in rates.items():
            dev = devices.get(ip, {})
            top.append({
                "ip": ip,
                "name": dev.get("label") or dev.get("hostname") or "",
                "type_label": dev.get("type_label", ""),
                "down_bps": rate.get("down_bps", 0),
                "up_bps": rate.get("up_bps", 0),
                "down_bytes_today": rate.get("down_bytes_today", 0),
                "up_bytes_today": rate.get("up_bytes_today", 0),
            })
        top.sort(key=lambda r: -(r["down_bps"] + r["up_bps"]))
        exporters = []
        status = {}
        if self.flow:
            status = self.flow.status()
            exporters = status.get("exporters") or []
        return {
            "source": source,
            "active": source != "none",
            "top": top[:25],
            "total_down_bps": sum(r["down_bps"] for r in top),
            "total_up_bps": sum(r["up_bps"] for r in top),
            "exporters": exporters,
            "packets": status.get("packets", 0),
            "last_packet_age": status.get("last_packet_age"),
        }

    def corp_summary(self):
        """Compact state of THIS site, for the Locations table (no snapshot recursion)."""
        with self.lock:
            devices = list(self.devices.values())
        health = self.poller.health() if self.poller else _basic_health(devices)
        traffic = self.traffic_view()
        wan = self.wan_watcher.snapshot() if self.wan_watcher else {}
        incidents = []
        if self.poller:
            with self.poller.lock:
                incidents = [i for i in self.poller.incidents.values()
                             if i.get("state") != "resolved"][:6]
        return {
            "version": __import__("netscan").__version__,
            "health": health,
            "devices": len(devices),
            "gateway": self.gateway_state or {},
            "wan": {"ips": wan.get("ips") or [], "isp": wan.get("isp", ""),
                    "dual": bool(wan.get("dual"))},
            "traffic": {"total_down_bps": traffic.get("total_down_bps", 0),
                        "total_up_bps": traffic.get("total_up_bps", 0)},
            "internet": self.internet_state or [],
            "open_incidents": [{"id": i.get("id"), "title": i.get("title"),
                                "severity": i.get("severity"), "state": i.get("state"),
                                "device_name": i.get("device_name"),
                                "device_ip": i.get("device_ip"),
                                "opened_ts": i.get("opened_ts")} for i in incidents],
        }

    def reports(self, hours=24, days=7):
        """Availability, incident statistics and the worst offenders."""
        avail = store.availability(hours)
        stats = store.incident_stats(days)
        with self.lock:
            devices = {d["ip"]: d for d in self.devices.values()}
        rows = []
        for ip, data in avail.items():
            dev = devices.get(ip, {})
            rows.append(dict(data, ip=ip,
                             name=dev.get("label") or dev.get("hostname") or "",
                             type_label=dev.get("type_label", ""),
                             type=dev.get("type", "")))
        rows.sort(key=lambda r: (r["availability_pct"], r["ip"]))
        worst = [r for r in rows if r["availability_pct"] < 99.5][:10]
        return {
            "window_hours": hours,
            "stats": stats,
            "devices": rows,
            "worst": worst,
            "average_availability": round(
                sum(r["availability_pct"] for r in rows) / len(rows), 2) if rows else 100.0,
            "wan_changes": (self.wan_watcher.snapshot().get("changes") if self.wan_watcher else []),
        }

    def top_talkers(self, limit=5):
        return self.traffic_view()["top"][:limit]

    # ---- actions ----------------------------------------------------------

    def set_label(self, mac, label):
        ok = store.set_label(mac, label)
        with self.lock:
            for dev in self.devices.values():
                if (dev.get("mac") or "").lower() == (mac or "").lower():
                    dev["label"] = label
        return ok

    def update_settings(self, patch):
        cfg = settings.save(settings.drop_masked(patch or {}))
        # thresholds and intervals apply from the next poll; restart the flow/syslog
        # listeners if their ports changed
        for attr, section in (("flow", "netflow"), ("syslog", "syslog")):
            thread = getattr(self, attr)
            new = cfg.get(section) or {}
            if thread is not None and not new.get("enabled", True):
                try:
                    thread.stop()
                except Exception:
                    pass
                setattr(self, attr, None)
        return cfg

    def launch_remote(self, ip, action, from_this_pc=True):
        if not self.remote_control:
            return {"ok": False, "message": "Remote actions are switched off (--no-remote-control)"}
        if not from_this_pc and not self.allow_remote_control:
            return {"ok": False, "message": "Remote actions can only be started from the PC running "
                                            "Prahari. Start it with --allow-remote-control."}
        clean = remote.valid_ip(ip)
        if not clean:
            return {"ok": False, "message": "invalid device address"}
        with self.lock:
            dev = self.devices.get(clean)
        if dev is None:
            return {"ok": False, "message": "that device is not in the current scan result - rescan first"}
        broadcast = (self.local or {}).get("broadcast") or "255.255.255.255"
        result = remote.launch(dev, action, broadcast)
        result["device"] = f"{clean} ({dev.get('type_label', '')})"
        result["action"] = action
        return result

    def dismiss_incident(self, incident_id):
        if not self.poller:
            return False
        with self.poller.lock:
            inc = self.poller.incidents.get(incident_id)
            if not inc:
                return False
            inc.update(state="resolved", closed_ts=int(time.time()),
                       updated_ts=int(time.time()))
            inc["timeline"].append({"ts": int(time.time()), "text": "Acknowledged and closed by the operator"})
            store.save_incident(inc)
        store.add_event("operator", "info", f"Incident closed manually: {inc.get('title')}")
        return True

    # ---- the scan ---------------------------------------------------------

    def _set(self, **kwargs):
        with self.lock:
            self.status.update(kwargs)

    def _scan(self):
        t0 = time.time()
        self.warnings = []
        cfg = settings.load()
        communities = (cfg.get("discovery") or {}).get("snmp_communities") or [self.community]
        try:
            self._set(phase="network", message="Reading local network configuration", done=0, total=0)
            local = netinfo.local_network(self.subnet_override)
            with self.lock:
                self.local = local
                self.status["scan_count"] += 1
            threading.Thread(target=self._public_ip, daemon=True).start()

            network = ipaddress.IPv4Network(local["network"], strict=False)
            if local.get("truncated"):
                self.warnings.append("Subnet is larger than /22 - only the first 1024 addresses were scanned.")

            self._set(phase="sweep", message=f"Sweeping {local['network']} for live hosts",
                      done=0, total=local["host_count"])
            alive = discovery.sweep(network, progress=lambda d, t, _r: self._set(done=d, total=t))

            arp = netinfo.arp_table()
            gateway = local.get("gateway", "")
            self._set(phase="fingerprint",
                      message=f"Identifying {len(alive)} devices (ports, banners, SNMP)",
                      done=0, total=max(1, len(alive)))
            labels = store.labels()
            my_ip = local.get("ip")
            deep = self.deep and (cfg.get("discovery") or {}).get("deep_scan", True)

            def work(ip):
                try:
                    info = discovery.fingerprint_host(ip, is_gateway=(ip == gateway), deep=deep)
                except Exception:
                    info = {"ip": ip, "ports": [], "http": [], "rtsp": {}}
                mac = (arp.get(ip) or "").lower()
                if not mac:
                    try:
                        discovery.tcp_alive(ip, ports=(80, 443, 9100), timeout=0.2)
                        mac = (netinfo.arp_table().get(ip) or "").lower()
                    except Exception:
                        pass
                info["mac"] = mac
                info["vendor"] = oui.vendor_for(mac)
                if not info.get("snmp_community") and 161 in (info.get("ports") or []):
                    for community in communities:
                        descr, comm = None, None
                        try:
                            from . import snmp as snmp_mod
                            descr, comm = snmp_mod.sysdescr(ip)
                        except Exception:
                            pass
                        if descr:
                            info["snmp_descr"] = descr
                            info["snmp_community"] = comm
                        break
                verdict = fingerprint.classify(info)
                prev = self.devices.get(ip, {})
                dev = {
                    "ip": ip, "mac": mac, "vendor": info.get("vendor", ""),
                    "hostname": info.get("hostname", ""),
                    "type": verdict["type"], "type_label": verdict["label"],
                    "confidence": verdict["confidence"], "evidence": verdict["evidence"],
                    "ports": [{"port": p, "service": discovery.PORT_SERVICES.get(p, ""),
                               "proto": "udp" if p in (info.get("udp_ports") or []) else "tcp"}
                              for p in info.get("ports", [])],
                    "upnp_server": info.get("upnp_server", ""),
                    "title": next((h.get("title") for h in info.get("http", []) if h.get("title")), ""),
                    "server": next((h.get("server") for h in info.get("http", []) if h.get("server")), ""),
                    "snmp_descr": info.get("snmp_descr", ""),
                    "snmp_community": info.get("snmp_community", ""),
                    "snmp_name": info.get("snmp_name", ""),
                    "is_gateway": bool(info.get("is_gateway")), "is_self": ip == my_ip,
                    "label": labels.get(mac, "") or prev.get("label", ""),
                    "rx_bps": prev.get("rx_bps", 0), "tx_bps": prev.get("tx_bps", 0),
                    "rate_source": prev.get("rate_source", ""),
                    "state": prev.get("state", "unknown"),
                    "latency_ms": prev.get("latency_ms", 0), "loss_pct": prev.get("loss_pct", 0),
                    "history": prev.get("history", []),
                    "last_seen": time.strftime("%H:%M:%S"),
                }
                store.record(mac, ip, verdict["type"], dev["label"])
                return dev

            done = 0
            with ThreadPoolExecutor(max_workers=max(4, self.workers)) as pool:
                for dev in pool.map(work, alive):
                    done += 1
                    with self.lock:
                        self.devices[dev["ip"]] = dev
                    self._set(done=done, message=f"Identified {done}/{len(alive)} devices")

            self._set(phase="done",
                      message=f"Scan complete - {len(alive)} devices in {time.time() - t0:.1f}s",
                      last_scan=time.strftime("%Y-%m-%d %H:%M:%S"),
                      done=len(alive), total=len(alive))
            self.start_monitors()
        except Exception as exc:
            self._set(phase="error", message=f"Scan failed: {exc}")
            self.warnings.append(f"Scan error: {exc}")
        finally:
            self._set(scan_running=False)

    def _public_ip(self):
        data = netinfo.public_ip()
        with self.lock:
            self.public = data
        if data.get("error") and not data.get("ip"):
            self.warnings.append("Could not reach a public IP service (no internet or firewall).")


def _basic_health(devices):
    monitored = [d for d in devices if d.get("state") in ("up", "degraded", "down")]
    up = sum(1 for d in monitored if d["state"] == "up")
    degraded = sum(1 for d in monitored if d["state"] == "degraded")
    down = sum(1 for d in monitored if d["state"] == "down")
    total = len(monitored)
    return {"score": 100 if not total else max(0, round(100 * (up + 0.5 * degraded) / total)),
            "up": up, "degraded": degraded, "down": down, "monitored": total,
            "open_incidents": 0, "critical": 0}


def _sort_key(dev):
    if dev.get("is_gateway"):
        return (0, 0, _ip_key(dev["ip"]))
    order = fingerprint.TYPE_ORDER
    try:
        rank = order.index(dev.get("type", "unknown")) + 1
    except ValueError:
        rank = len(order)
    return (1, rank, _ip_key(dev["ip"]))


def _ip_key(ip):
    try:
        return tuple(int(p) for p in ip.split("."))
    except Exception:
        return (999, 999, 999, 999)


def _counts(devices):
    counts = {t: 0 for t in fingerprint.TYPES}
    for dev in devices:
        counts[dev.get("type", "unknown")] = counts.get(dev.get("type", "unknown"), 0) + 1
    counts["total"] = len(devices)
    return counts
