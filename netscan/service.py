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
    """Background mode needs the Windows exe (the source version runs with Python and run.bat)."""
    return IS_WINDOWS and bool(getattr(sys, "frozen", False))


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


def elevate_install(home, extra_args=()):
    """Ask Windows for administrator rights (the usual 'Allow this app to make changes?' prompt) and run
    Prahari.exe --install-service in that elevated copy. True when the prompt was accepted."""
    if not IS_WINDOWS:
        return False
    try:
        import ctypes
        params = " ".join(["--install-service", "--home", f'"{home}"'] + list(extra_args))
        rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 0)
        return int(rc) > 32
    except Exception:
        return False


def wait_port_free(port=8777, seconds=60):
    import time
    end = time.time() + seconds
    while time.time() < end and port_busy(port):
        time.sleep(1)
    return not port_busy(port)


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


def desktop_dirs():
    """The shared desktop (every user of this PC sees it), else this user's desktop."""
    dirs = []
    public = os.environ.get("PUBLIC")
    if public:
        dirs.append(os.path.join(public, "Desktop"))
    dirs.append(os.path.join(os.path.expanduser("~"), "Desktop"))
    return dirs


def ensure_shortcut(port=8777, exe=None, folder=None):
    """A 'Prahari' icon on the desktop that opens the dashboard. Returns the file written, or ''."""
    content = ("[InternetShortcut]\r\nURL=http://127.0.0.1:%d/\r\nIconFile=%s\r\nIconIndex=0\r\n"
               % (port, exe or os.path.join(install_dir(), "Prahari.exe")))
    for d in ([folder] if folder else desktop_dirs()):
        try:
            if not os.path.isdir(d):
                continue
            path = os.path.join(d, "Prahari.url")
            try:
                with open(path, encoding="utf-8", newline="") as f:
                    if f.read() == content:
                        return path
            except OSError:
                pass
            with open(path, "w", encoding="utf-8", newline="") as f:
                f.write(content)
            return path
        except OSError:
            continue
    return ""


def port_busy(port=8777):
    import socket
    s = socket.socket()
    s.settimeout(0.5)
    try:
        return s.connect_ex(("127.0.0.1", port)) == 0
    finally:
        s.close()
