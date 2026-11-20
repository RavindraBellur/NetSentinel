"""Run Prahari in the background on Windows: a scheduled task that starts at boot as SYSTEM, with no time limit,
restarts within a minute if it stops, and keeps using the data folder of the person who set it up (--home).

Closing the console window then no longer stops monitoring, and nobody has to stay logged in on the server.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys

TASK = "Prahari"
IS_WINDOWS = os.name == "nt"


def supported():
    return IS_WINDOWS


def is_admin():
    if not IS_WINDOWS:
        return False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _run(cmd, timeout=60):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           creationflags=0x08000000 if IS_WINDOWS else 0)   # CREATE_NO_WINDOW
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except Exception as exc:
        return 1, str(exc)


def _ps(script, timeout=90):
    return _run(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script], timeout)


def installed():
    if not IS_WINDOWS:
        return False
    code, _ = _run(["schtasks", "/Query", "/TN", TASK])
    return code == 0


def install_dir():
    return os.path.join(os.environ.get("ProgramData") or r"C:\ProgramData", "Prahari")


def _q(s):
    return "'" + str(s).replace("'", "''") + "'"


def install(home, exe=None, extra_args=(), copy=True):
    """Register (or replace) the background task. Returns (ok, message, exe_path)."""
    if not IS_WINDOWS:
        return False, "Background mode is for Windows.", ""
    if not is_admin():
        return False, "Needs administrator rights: right-click Prahari.exe -> Run as administrator, once.", ""
    exe = exe or sys.executable
    if copy:
        # A fixed place, so the task keeps working if the downloaded file is moved or deleted.
        target = os.path.join(install_dir(), "Prahari.exe")
        try:
            os.makedirs(install_dir(), exist_ok=True)
            if os.path.abspath(exe).lower() != os.path.abspath(target).lower():
                shutil.copy2(exe, target)
            exe = target
        except OSError as exc:
            return False, f"Could not copy Prahari to {install_dir()}: {exc}", ""
    args = " ".join(["--background", "--home", f'"{home}"'] + list(extra_args))
    script = (
        f"$a = New-ScheduledTaskAction -Execute {_q(exe)} -Argument {_q(args)} -WorkingDirectory {_q(os.path.dirname(exe))};"
        "$t = New-ScheduledTaskTrigger -AtStartup;"
        "$s = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 "
        "-RestartInterval (New-TimeSpan -Minutes 1) -StartWhenAvailable -AllowStartIfOnBatteries "
        "-DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew;"
        "$p = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest;"
        f"Register-ScheduledTask -TaskName {_q(TASK)} -Action $a -Trigger $t -Settings $s -Principal $p -Force | Out-Null"
    )
    code, out = _ps(script)
    if code != 0 or not installed():
        return False, "Could not register the background task: " + out.strip()[-300:], exe
    return True, "Prahari will run in the background - at every start of Windows, without anyone logged in.", exe


def start():
    code, out = _run(["schtasks", "/Run", "/TN", TASK])
    return code == 0, out.strip()


def remove():
    if not IS_WINDOWS:
        return False, "Background mode is for Windows."
    if not installed():
        return True, "Background mode was not set up."
    if not is_admin():
        return False, "Needs administrator rights: run this as administrator."
    _run(["schtasks", "/End", "/TN", TASK])
    code, out = _run(["schtasks", "/Delete", "/TN", TASK, "/F"])
    return code == 0, ("Background mode removed - Prahari no longer starts with Windows." if code == 0 else out.strip())


def port_busy(port=8777):
    import socket
    s = socket.socket()
    s.settimeout(0.5)
    try:
        return s.connect_ex(("127.0.0.1", port)) == 0
    finally:
        s.close()
