"""Background mode: --home keeps the data folder; on Windows the task runs as SYSTEM, at boot, with no time limit."""
import os
import subprocess
import sys
import tempfile
import unittest

from tests import _env  # noqa: F401
from netscan import service

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class HomeFolder(unittest.TestCase):
    def test_home_option_puts_the_data_in_that_folder(self):
        home = tempfile.mkdtemp(prefix="prahari-home-")
        env = dict(os.environ)
        r = subprocess.run([sys.executable, os.path.join(ROOT, "netsentinel.py"), "--home", home, "--set-password", "Pw-for-test-123"],
                           capture_output=True, text=True, timeout=120, env=env)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertTrue(os.path.isdir(os.path.join(home, ".netsentinel")), "data written under --home")
        self.assertTrue(os.listdir(os.path.join(home, ".netsentinel")))


@unittest.skipUnless(os.name == "nt" and service.is_admin(), "Windows with administrator rights only (runs on CI)")
class WindowsTask(unittest.TestCase):
    def tearDown(self):
        service.remove()

    def test_task_runs_as_system_at_boot_without_time_limit_and_restarts(self):
        home = tempfile.mkdtemp(prefix="prahari-home-")
        ok, msg, exe = service.install(home, exe=sys.executable, copy=False)
        self.assertTrue(ok, msg)
        self.assertTrue(service.installed())
        code, out = service._ps(
            "$t = Get-ScheduledTask -TaskName 'Prahari';"
            "'{0}|{1}|{2}|{3}|{4}|{5}' -f $t.Principal.UserId, $t.Settings.ExecutionTimeLimit, $t.Settings.RestartCount,"
            " $t.Triggers[0].CimClass.CimClassName, $t.Actions[0].Arguments, $t.Principal.RunLevel")
        self.assertEqual(code, 0, out)
        user, limit, restarts, trigger, arguments, level = out.strip().splitlines()[-1].split("|")
        self.assertIn("SYSTEM", user.upper())
        self.assertEqual(limit, "PT0S", "no 3-day limit")
        self.assertGreaterEqual(int(restarts), 10)
        self.assertIn("Boot", trigger)
        self.assertIn("--background", arguments)
        self.assertIn(home, arguments)
        self.assertEqual(level, "Highest")
        ok, msg = service.remove()
        self.assertTrue(ok, msg)
        self.assertFalse(service.installed())


if __name__ == "__main__":
    unittest.main()
