"""1.37: sensor templates, wmi/sqlite sensors, escalation, configuration backup."""
import datetime
import os
import sqlite3
import sys
import tempfile
import time
import unittest
from unittest import mock

from tests import _env  # noqa: F401
from netscan import configbackup, escalation, sensors, settings, store


class SensorTemplates(unittest.TestCase):
    def test_every_template_is_a_valid_sensor(self):
        for key, tpl in sensors.TEMPLATES.items():
            s = sensors.from_template(key)
            self.assertIn(s["type"], sensors.KINDS, key)
            self.assertIn(s["type"], sensors.CHECKS, key)
            self.assertTrue(s["target"] and s["name"], key)
            self.assertTrue(tpl["why"] and tpl["ask"], key)

    def test_target_and_port_replaced(self):
        s = sensors.from_template("pms", "10.1.1.5", port=9000)
        self.assertEqual((s["target"], s["port"]), ("10.1.1.5", 9000))
        self.assertIsNone(sensors.from_template("nope"))
        self.assertEqual(len(sensors.templates()), len(sensors.TEMPLATES))

    def test_view_carries_templates(self):
        self.assertTrue(sensors.SensorRunner().view({"sensors": []})["templates"])


class SqliteSensor(unittest.TestCase):
    def setUp(self):
        d = tempfile.mkdtemp()
        self.db = os.path.join(d, "billing.db")
        c = sqlite3.connect(self.db)
        c.execute("CREATE TABLE invoices (id INTEGER, created TEXT)")
        c.executemany("INSERT INTO invoices VALUES (?, datetime('now'))", [(1,), (2,), (3,)])
        c.commit(); c.close()

    def sensor(self, query, **kw):
        return dict({"type": "sqlite", "target": self.db, "query": query,
                     "operator": "<", "warn_value": 5, "crit_value": 1}, **kw)

    def test_counts_and_thresholds(self):
        q = "SELECT COUNT(*) FROM invoices"
        self.assertEqual(sensors.check_sqlite(self.sensor(q))[0], sensors.WARN)       # 3 < 5
        self.assertEqual(sensors.check_sqlite(self.sensor(q, warn_value=2))[0], sensors.UP)
        self.assertEqual(sensors.check_sqlite(
            self.sensor("SELECT COUNT(*) FROM invoices WHERE id > 9"))[0], sensors.DOWN)

    def test_writes_refused(self):
        for q in ("DELETE FROM invoices", "SELECT 1; DELETE FROM invoices",
                  "UPDATE invoices SET id=0"):
            state, _, msg = sensors.check_sqlite(self.sensor(q))
            self.assertEqual(state, sensors.DOWN)
            self.assertIn("SELECT", msg)
        # read-only even if a writing statement slipped through as a CTE
        state, _, _ = sensors.check_sqlite(self.sensor(
            "WITH x AS (SELECT 1) INSERT INTO invoices SELECT 9, 'x' FROM x"))
        self.assertEqual(state, sensors.DOWN)
        c = sqlite3.connect(self.db)
        self.assertEqual(c.execute("SELECT COUNT(*) FROM invoices").fetchone()[0], 3)
        c.close()

    def test_missing_file(self):
        s = self.sensor("SELECT 1", target=self.db + ".missing")
        self.assertEqual(sensors.check_sqlite(s)[0], sensors.DOWN)
        self.assertFalse(os.path.exists(self.db + ".missing"))


class WmiSensor(unittest.TestCase):
    def test_script_quotes_the_target(self):
        evil = "\\X(C:)\\Y'; Remove-Item C:\\ -Recurse; '"
        script = sensors.wmi_script(evil)
        self.assertIn("'\\X(C:)\\Y''; Remove-Item C:\\ -Recurse; '''", script)
        self.assertTrue(sensors.wmi_script("SELECT * FROM Win32_Service").startswith(
            "@(Get-CimInstance -Query 'SELECT"))

    @unittest.skipIf(sys.platform == "win32", "non-Windows behaviour")
    def test_off_windows(self):
        self.assertEqual(sensors.check_wmi({"target": "\\Processor(_Total)\\% Processor Time"})[0],
                         sensors.DOWN)

    @unittest.skipUnless(sys.platform == "win32", "needs Windows")
    def test_free_space_on_windows(self):
        state, value, msg = sensors.check_wmi(sensors.from_template("disk"))
        self.assertIn(state, (sensors.UP, sensors.WARN, sensors.DOWN))
        self.assertTrue(0 <= value <= 100, msg)


class Escalation(unittest.TestCase):
    ESC = {"enabled": True, "max_pages_per_incident": 3, "quiet_hours": "",
           "steps": escalation.clean_steps([
               {"after_minutes": 20, "channels": "email+push", "to": "gm@hotel.in"},
               {"after_minutes": 60, "channels": ["email"], "to": ["owner@hotel.in"]}])}

    def problem(self, age_min, paged=(), severity="high"):
        return {"key": "INC-1", "severity": severity, "opened_ts": 10000 - age_min * 60,
                "paged": list(paged)}

    def test_clean_steps(self):
        steps = escalation.clean_steps([
            {"after_minutes": "60", "channels": "email", "to": "a@b.in; c@d.in"},
            {"after_minutes": 5, "channels": "push", "to": ""},
            {"after_minutes": 10, "channels": "email", "to": ""},     # email to nobody: dropped
            {"after_minutes": "x", "channels": "email", "to": "a@b.in"},
            {"after_minutes": 7, "channels": "fax", "to": "a@b.in"}])
        self.assertEqual([s["after_minutes"] for s in steps], [5, 60])
        self.assertEqual(steps[1]["to"], ["a@b.in", "c@d.in"])

    def test_steps_fire_once_in_order(self):
        plan = escalation.plan
        self.assertEqual(plan([self.problem(10)], self.ESC, now=10000), [])
        out = plan([self.problem(25)], self.ESC, now=10000)
        self.assertEqual([i for _, i, _ in out], [0])
        self.assertEqual(plan([self.problem(25, [0])], self.ESC, now=10000), [])
        self.assertEqual([i for _, i, _ in plan([self.problem(61, [0])], self.ESC, now=10000)], [1])
        self.assertEqual(plan([self.problem(500, [0, 1])], self.ESC, now=10000), [])

    def test_late_start_sends_only_the_top_step(self):
        out = escalation.plan([self.problem(120)], self.ESC, now=10000)
        self.assertEqual([i for _, i, _ in out], [1])
        self.assertEqual(escalation.plan([self.problem(120, [1])], self.ESC, now=10000), [])

    def test_cap_and_disabled(self):
        esc = dict(self.ESC, max_pages_per_incident=1)
        self.assertEqual(escalation.plan([self.problem(61, [0])], esc, now=10000), [])
        self.assertEqual(escalation.plan([self.problem(61)], dict(self.ESC, enabled=False),
                                         now=10000), [])

    def test_quiet_hours(self):
        q = escalation.in_quiet_hours
        self.assertTrue(q("23:00-07:00", datetime.datetime(2026, 1, 1, 2, 0)))
        self.assertTrue(q("23:00-07:00", datetime.datetime(2026, 1, 1, 23, 30)))
        self.assertFalse(q("23:00-07:00", datetime.datetime(2026, 1, 1, 12, 0)))
        self.assertTrue(q("13:00-14:00", datetime.datetime(2026, 1, 1, 13, 30)))
        self.assertFalse(q("", datetime.datetime(2026, 1, 1, 13, 30)))
        esc = dict(self.ESC, quiet_hours="00:00-23:59")
        night = datetime.datetime(2026, 1, 1, 3, 0)
        self.assertEqual(escalation.plan([self.problem(25, severity="medium")], esc,
                                         now=10000, when=night), [])
        self.assertEqual(len(escalation.plan([self.problem(25, severity="critical")], esc,
                                             now=10000, when=night)), 1)

    def test_send_email_to_step_recipients(self):
        cfg = {"email": {"enabled": True, "host": "smtp.x", "to": []}, "telegram": {}}
        with mock.patch("netscan.alerts.send_email", return_value=(True, "ok")) as m:
            sent = escalation.send(cfg, {"key": "INC-9", "kind": "incident", "title": "Core switch is down",
                                         "opened_ts": time.time() - 1500},
                                   {"after_minutes": 20, "channels": ["email", "telegram"],
                                    "to": ["gm@hotel.in"]})
        self.assertTrue(sent["email"]["ok"])
        self.assertFalse(sent["telegram"]["ok"])
        self.assertEqual(m.call_args.kwargs["to"], ["gm@hotel.in"])
        self.assertIn("ESCALATED", m.call_args.args[1])
        self.assertIn("/ack INC-9", m.call_args.args[2])

    def test_scanner_records_in_timeline_and_does_not_repeat(self):
        from netscan import scanner as scanner_mod
        sc = scanner_mod.Scanner(capture=False)

        class P:
            import threading
            lock = threading.RLock()
            incidents = {}
        sc.poller = P()
        inc = {"id": "INC-5", "state": "open", "severity": "high", "title": "AP-3 is down",
               "opened_ts": int(time.time()) - 30 * 60, "timeline": [], "diagnosis": {}}
        P.incidents["INC-5"] = inc
        sid = "S-x"
        sc.sensors.states[sid] = {"id": sid, "name": "Booking page", "state": "down",
                                  "type": "http", "target": "https://x", "message": "HTTP 500",
                                  "since": int(time.time()) - 25 * 60, "ts": int(time.time())}
        settings.save({"escalation": {"enabled": True, "steps": [
            {"after_minutes": 20, "channels": ["email"], "to": ["gm@hotel.in"]}]},
            "email": {"enabled": True, "host": "smtp.x", "to": ["it@hotel.in"]}})
        try:
            with mock.patch("netscan.alerts.send_email", return_value=(True, "ok")) as m, \
                    mock.patch("netscan.store.save_incident"):
                first = sc.run_escalation()
                second = sc.run_escalation()
            self.assertEqual(len(first), 2)
            self.assertEqual(second, [])
            self.assertEqual(m.call_count, 2)
            self.assertEqual(inc["timeline"][-1]["escalation_step"], 0)
            self.assertEqual(sc.sensors.states[sid]["paged"], [0])
            inc["state"] = "resolved"
            self.assertEqual([p["kind"] for p in sc.open_problems()], ["sensor"])
        finally:
            settings.save({"escalation": {"enabled": False, "steps": []}})


class ConfigBackup(unittest.TestCase):
    def setUp(self):
        configbackup.BACKUP_DIR = tempfile.mkdtemp()

    def test_parse_devices(self):
        devs, problems = configbackup.parse_devices(
            "192.168.1.2 cisco Core switch\n10.0.0.1 mikrotik\n8.8.8.8 cisco\n"
            "192.168.1.9 sophos\nnot-an-ip cisco")
        self.assertEqual([(d["ip"], d["kind"], d["name"]) for d in devs],
                         [("192.168.1.2", "cisco", "Core switch"), ("10.0.0.1", "mikrotik", "10.0.0.1")])
        self.assertEqual(len(problems), 3)
        self.assertTrue(any("8.8.8.8" in p for p in problems))

    def test_noise_ignored_and_change_detected(self):
        a = ("Building configuration...\nCurrent configuration : 1234 bytes\n"
             "! Last configuration change at 10:00:01 IST Mon Nov 16 2026\n"
             "hostname core\ninterface Gi1/0/1\n description Lobby AP\n")
        b = a.replace("10:00:01", "11:22:33").replace("1234", "1240")
        c = b.replace("Lobby AP", "Lobby AP + CCTV")
        changed, first, _, _ = configbackup.save_and_compare("192.168.1.2", a, now=1)
        self.assertTrue(first)
        changed, first, diff, _ = configbackup.save_and_compare("192.168.1.2", b, now=2)
        self.assertFalse(changed or first)
        self.assertEqual(len(configbackup.versions("192.168.1.2")), 1)
        changed, first, diff, _ = configbackup.save_and_compare("192.168.1.2", c, now=3)
        self.assertTrue(changed)
        self.assertIn("- description Lobby AP", diff)
        self.assertIn("+ description Lobby AP + CCTV", diff)
        self.assertIn("CCTV", configbackup.diff_latest("192.168.1.2"))

    def test_keep_limit(self):
        for n in range(6):
            configbackup.save_and_compare("10.0.0.1", f"/ip address\nadd address=10.0.0.{n}/24\n",
                                          keep=3, now=1000 + n)
        self.assertEqual(len(configbackup.versions("10.0.0.1")), 3)

    def test_ssh_is_key_only_and_batch(self):
        args = configbackup.ssh_command("192.168.1.2", "backup", "show running-config", "C:/k/id")
        self.assertIn("BatchMode=yes", args)
        self.assertIn("PasswordAuthentication=no", args)
        self.assertEqual(args[-2:], ["backup@192.168.1.2", "show running-config"])

    def test_run_uses_fixed_commands_and_raises_event(self):
        cfg = {"config_backup": {"enabled": True, "user": "backup", "key": "",
                                 "devices": [{"ip": "192.168.1.2", "kind": "cisco", "name": "Core"}]}}
        outputs = iter(["hostname core\ninterface Gi1\n shutdown\n",
                        "hostname core\ninterface Gi1\n no shutdown\n"])
        calls = []

        def fake(host, user, command, key, timeout=25):
            calls.append(command)
            return True, next(outputs)
        with mock.patch.object(configbackup, "_ssh", side_effect=fake), \
                mock.patch.object(store, "add_event") as ev:
            r1 = configbackup.run(cfg)
            r2 = configbackup.run(cfg)
        self.assertEqual(calls, ["show running-config"] * 2)
        self.assertTrue(r1[0]["first_run"] and not r1[0]["changed"])
        self.assertTrue(r2[0]["changed"])
        self.assertTrue(ev.called)
        self.assertEqual(configbackup.run({"config_backup": {"enabled": False}}), [])

    def test_notify_change_emails_the_diff(self):
        cfg = {"email": {"enabled": True, "host": "smtp.x", "to": ["it@hotel.in"]}, "push": {}}
        with mock.patch("netscan.alerts.send_email", return_value=(True, "ok")) as m:
            configbackup.notify_change(cfg, {"name": "Core", "host": "192.168.1.2",
                                             "kind": "cisco", "diff": "+ no shutdown"})
        self.assertIn("Configuration changed", m.call_args.args[1])
        self.assertIn("+ no shutdown", m.call_args.args[2])


if __name__ == "__main__":
    unittest.main()


class CongestionRule(unittest.TestCase):
    """1.37.1: switched-off devices and sleepy printers are not congestion."""
    TH = {"latency_warn_ms": 150, "latency_crit_ms": 300, "loss_warn_pct": 3, "loss_crit_pct": 10}

    def run_rule(self, dev, siblings, gateway=None, internet=None):
        from netscan import diagnose
        return diagnose.diagnose({"device": dev, "state": "degraded", "latency": 400, "loss": 0,
                                  "siblings": siblings, "gateway": gateway or {"state": "up"},
                                  "internet": internet or [{"state": "up"}], "thresholds": self.TH,
                                  "data_sources": {}})

    def sib(self, ip, typ, state):
        return {"ip": ip, "type": typ, "state": state, "monitored": True}

    def test_slow_printer_with_printers_off_is_not_congestion(self):
        """What the Corporate Office saw on 21/11: one slow Canon, four printers switched off."""
        canon = {"ip": "192.168.0.235", "type": "printer", "label": "CANON2C0FC1"}
        sibs = [self.sib("192.168.0.235", "printer", "degraded")] + [
            self.sib(f"192.168.0.{n}", "printer", "down") for n in (12, 18, 231, 246)]
        d = self.run_rule(canon, sibs)
        self.assertNotEqual(d["category"], "congestion")
        self.assertEqual(d["title"], "CANON2C0FC1 is degraded")

    def test_one_slow_server_with_devices_off_is_not_congestion(self):
        srv = {"ip": "10.0.0.5", "type": "server", "label": "Billing"}
        sibs = [self.sib("10.0.0.5", "server", "degraded"), self.sib("10.0.0.6", "server", "down"),
                self.sib("10.0.0.7", "switch", "down")]
        self.assertNotEqual(self.run_rule(srv, sibs)["category"], "congestion")

    def test_two_always_on_devices_slow_is_congestion(self):
        srv = {"ip": "10.0.0.5", "type": "server", "label": "Billing"}
        sibs = [self.sib("10.0.0.5", "server", "degraded"), self.sib("10.0.0.8", "nas", "degraded")]
        self.assertEqual(self.run_rule(srv, sibs)["category"], "congestion")

    def test_slow_device_plus_slow_gateway_is_congestion(self):
        srv = {"ip": "10.0.0.5", "type": "server", "label": "Billing"}
        d = self.run_rule(srv, [self.sib("10.0.0.5", "server", "degraded")],
                          gateway={"state": "degraded"})
        self.assertEqual(d["category"], "congestion")
        self.assertIn("The gateway itself is slow", d["evidence"])

    def test_printers_alone_never_congestion(self):
        p = {"ip": "10.0.0.20", "type": "printer", "label": "P1"}
        sibs = [self.sib(f"10.0.0.{n}", "printer", "degraded") for n in range(20, 26)]
        self.assertNotEqual(self.run_rule(p, sibs)["category"], "congestion")


class RenewalCommandNoShell(unittest.TestCase):
    """1.37.2: the certificate-renewal command never goes through a shell."""

    def test_shell_syntax_refused(self):
        from netscan import certs
        for cmd in ("certbot renew; del C:\\x", "a && b", "a | b", "x > y", "echo $HOME",
                    "echo `id`", "echo %USERNAME%", "a ^& b", "a\nb"):
            args, problem = certs.renewal_args(cmd)
            self.assertIsNone(args, cmd)
            self.assertIn("shell syntax", problem)
            ok, msg = certs.run_renewal(cmd)
            self.assertFalse(ok)

    def test_plain_command_split_into_arguments(self):
        from netscan import certs
        self.assertEqual(certs.renewal_args("certbot renew --quiet")[0], ["certbot", "renew", "--quiet"])
        self.assertEqual(certs.renewal_args("")[0], None)

    def test_runs_without_shell(self):
        from netscan import certs
        with mock.patch("subprocess.run") as run:
            run.return_value = mock.Mock(returncode=0, stdout="renewed", stderr="")
            ok, out = certs.run_renewal("certbot renew --quiet")
        self.assertTrue(ok)
        self.assertEqual(run.call_args.args[0], ["certbot", "renew", "--quiet"])
        self.assertNotIn("shell", run.call_args.kwargs)


class Systems(unittest.TestCase):
    """1.38.0: server CPU / memory / disk."""

    def test_this_pc_has_numbers(self):
        from netscan import systems
        row = systems.local()
        self.assertEqual(row["source"], "local")
        self.assertTrue(row.get("disks"), row)
        self.assertTrue(0 <= row["disks"][0]["used_pct"] <= 100)
        if sys.platform == "win32":                 # the exe bundles psutil; PowerShell is the fallback
            self.assertTrue(0 <= row["cpu_pct"] <= 100, row)
            self.assertTrue(0 < row["mem_used_pct"] <= 100, row)
            self.assertGreater(row["uptime_s"], 0)

    def test_host_resources_rows_windows_style(self):
        """A Windows server over SNMP: RAM and C: from hrStorage, sizes in allocation units."""
        from netscan import systems as sy
        B = "1.3.6.1.2.1.25.2.3.1"
        rows = lambda col, vals: [(f"{B}.{col}.{i}", 2, v) for i, v in vals]
        descrs = rows(3, [(1, "C:\\\\ Label:  Serial Number 1a2b"), (2, "Physical Memory"), (3, "D:\\\\")])
        types = rows(2, [(1, sy.HR_STORAGE_FIXED), (2, sy.HR_STORAGE_RAM), (3, sy.HR_STORAGE_FIXED)])
        units = rows(4, [(1, 4096), (2, 65536), (3, 4096)])
        sizes = rows(5, [(1, 26214400), (2, 262144), (3, 0)])       # C: 100 GiB, RAM 16 GiB, D: empty
        used = rows(6, [(1, 23592960), (2, 196608), (3, 0)])
        out = sy.hr_rows(descrs, types, units, sizes, used)
        self.assertEqual(out["ram"], {"mem_total_mb": 16384, "mem_used_pct": 75.0})
        self.assertEqual(len(out["disks"]), 1)
        self.assertEqual(out["disks"][0]["used_pct"], 90.0)
        self.assertEqual(out["disks"][0]["total_gb"], 107.4)

    def test_windows_server_gets_cpu_and_memory_from_host_resources(self):
        from netscan import systems as sy

        def get(host, oids, community, timeout=1, retries=0):
            return [(sy.OID_SYS_UPTIME, 0x43, 360000), (sy.OID_UCD_CPU_IDLE, 0x80, None)]

        def walk(host, base, community, timeout=1, max_rows=40):
            B = "1.3.6.1.2.1.25.2.3.1"
            data = {sy.OID_HR_LOAD: [(base + ".1", 2, 40), (base + ".2", 2, 60)],
                    sy.OID_HR_STORAGE_DESCR: [(B + ".3.1", 4, "C:\\\\"), (B + ".3.2", 4, "Physical Memory")],
                    sy.OID_HR_STORAGE_TYPE: [(B + ".2.1", 6, sy.HR_STORAGE_FIXED), (B + ".2.2", 6, sy.HR_STORAGE_RAM)],
                    sy.OID_HR_STORAGE_UNITS: [(B + ".4.1", 2, 4096), (B + ".4.2", 2, 65536)],
                    sy.OID_HR_STORAGE_SIZE: [(B + ".5.1", 2, 1000), (B + ".5.2", 2, 1000)],
                    sy.OID_HR_STORAGE_USED: [(B + ".6.1", 2, 950), (B + ".6.2", 2, 500)]}
            return data.get(base, [])
        with mock.patch("netscan.snmp.get", side_effect=get), mock.patch("netscan.snmp.walk", side_effect=walk):
            row = sy.snmp_host("192.168.0.5", "public")
        self.assertEqual(row["cpu_pct"], 50.0)
        self.assertEqual(row["mem_used_pct"], 50.0)
        self.assertEqual(row["uptime_s"], 3600)
        self.assertEqual(row["disks"][0]["used_pct"], 95.0)
        self.assertNotIn("community", row, "the community is not shown in the dashboard")

    def test_only_snmp_servers_are_polled(self):
        from netscan import systems as sy
        devs = [{"ip": "192.168.0.5", "type": "server", "ports": [{"port": 161}]},
                {"ip": "192.168.0.6", "type": "server", "ports": [3389]},
                {"ip": "192.168.0.7", "type": "printer", "snmp_community": "public"},
                {"ip": "192.168.0.8", "type": "nas", "snmp_community": "public"}]
        with mock.patch.object(sy, "snmp_host", return_value={"host": "x"}) as m, \
                mock.patch.object(sy, "local", return_value={"host": "me", "source": "local"}):
            rows = sy.collect(devs)
        self.assertEqual(sorted(c.args[0] for c in m.call_args_list), ["192.168.0.5", "192.168.0.8"])
        self.assertEqual(len(rows), 3)

    def test_alert_after_n_bad_readings_and_on_recovery(self):
        from netscan import systems as sy
        sy._STATE.clear()
        settings.save({"systems": {"enabled": True, "cpu_warn": 90, "mem_warn": 90, "disk_warn": 90,
                                   "bad_polls": 3}})
        sent = []
        notify = lambda host, name, text, bad: sent.append((host, bad, text))
        hot = [{"host": "10.0.0.5", "label": "Billing", "cpu_pct": 97, "disks": [{"used_pct": 40}]}]
        cool = [{"host": "10.0.0.5", "label": "Billing", "cpu_pct": 20, "disks": [{"used_pct": 40}]}]
        self.assertEqual(sy.evaluate(hot, notify=notify), [])
        self.assertEqual(sy.evaluate(cool, notify=notify), [])           # a single spike resets
        sy.evaluate(hot, notify=notify); sy.evaluate(hot, notify=notify)
        open_now = sy.evaluate(hot, notify=notify)
        self.assertEqual(len(open_now), 1)
        self.assertEqual(sent, [("10.0.0.5", True, "Billing: CPU 97%")])
        self.assertEqual(len(sy.evaluate(hot, notify=notify)), 1)
        self.assertEqual(len(sent), 1, "the alert goes out once")
        self.assertEqual(sy.evaluate(cool, notify=notify), [])
        self.assertEqual(sent[-1][1], False)


class LoginTiming(unittest.TestCase):
    def test_unknown_user_costs_a_hash(self):
        from netscan import store as st
        with mock.patch.object(st, "_hash", wraps=st._hash) as h:
            self.assertIsNone(st.check_user("nobody-here", "x"))
        self.assertEqual(h.call_count, 1)
