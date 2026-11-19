"""Automatic updates from the Prahari GitHub releases.

Every published release carries three files next to each other:

    Prahari.exe        the single-file Windows build
    Prahari-app.zip    the app code (netscan/, netsentinel.py, ...) for source installs
    latest.json            {"manifest": "<json text>", "sig": "<base64 Ed25519 signature of that text>"}

    manifest = {"version": "1.17.1", "tag": "v1.17.1",
                "assets": {"exe": {"file": "Prahari.exe", "sha256": "...", "size": n},
                           "app": {"file": "Prahari-app.zip", "sha256": "...", "size": n}}}

latest.json is signed on the publisher's PC with a key that never leaves it (tools/sign_release.py), and
GitHub only serves it once the release is published, so a draft or a tampered asset is never installed: the
signature covers the manifest, and the manifest pins the SHA-256 of every file.

Installing:
  * Windows exe   - download beside the running exe, rename the running exe to Prahari.exe.old
                    (Windows allows renaming a running exe), move the new one into place, restart.
  * source install - back up the files it replaces, unpack the zip over the app folder, restart.
  * .pyz / Mac .app - only reports that a new version is available.
After a restart the new version must keep running for 3 minutes to be accepted. If it exits within
25 seconds of the hand-over, or fails to come up 3 times in a row, the previous version is put back and
that version is skipped.

Only the standard library is imported at module level; cryptography is needed to verify, and without it
nothing is installed.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import platform
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import zipfile

from . import __version__
from .settings import CONFIG_DIR

REPO = "RavindraBellur/NetSentinel"
LATEST_URL = f"https://github.com/{REPO}/releases/latest/download/latest.json"
ASSET_URL = f"https://github.com/{REPO}/releases/download/{{tag}}/{{file}}"
# Testing / private mirror: serve latest.json and the files from one folder. Signatures still apply.
PUBLIC_KEY = "puWgDRWq+YSDNEQgYUcBHBVpzmKhoXA0i7qgkzhG7FE="
if os.environ.get("NETSENTINEL_UPDATE_BASE"):
    _base = os.environ["NETSENTINEL_UPDATE_BASE"].rstrip("/")
    LATEST_URL, ASSET_URL = _base + "/latest.json", _base + "/{file}"
    # Automated tests sign with their own throw-away key. Accepted ONLY for a mirror on this
    # very PC, so it can never be used to accept updates from anywhere else.
    if os.environ.get("NETSENTINEL_UPDATE_TEST_KEY") and \
            _base.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0] in ("127.0.0.1", "localhost"):
        PUBLIC_KEY = os.environ["NETSENTINEL_UPDATE_TEST_KEY"]

CHECK_EVERY = 6 * 3600
FIRST_CHECK_AFTER = 120
HEALTHY_AFTER = 180
HANDOFF_WATCH = 25
MAX_FAILED_STARTS = 3
MAX_SIZE = 80 * 1024 * 1024
APP_TOP = {"netscan", "netsentinel.py", "requirements.txt", "README.md", "EULA.txt", "sbom.json",
           "LIMITS.md"}
IS_WINDOWS = platform.system() == "Windows"
UPDATE_DIR = os.path.join(CONFIG_DIR, "update")
PENDING = os.path.join(UPDATE_DIR, "pending.json")
BAD = os.path.join(UPDATE_DIR, "bad.json")
CURRENT = None  # the running Updater, so a hub request (upgrade.py) can trigger it


def vtuple(v):
    try:
        return tuple(int(x) for x in str(v).lstrip("v").split("."))
    except ValueError:
        return (0,)


def _read(path, default):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return default


def _write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh)
    os.replace(tmp, path)


def _remove(path):
    try:
        os.remove(path)
    except OSError:
        pass


def app_dir():
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def install_mode():
    """'exe', 'source' or 'notify' - how this copy can be updated."""
    if getattr(sys, "frozen", False):
        return "exe" if IS_WINDOWS else "notify"
    here = os.path.abspath(__file__)
    if ".pyz" in here or ".app" + os.sep + "Contents" in here:
        return "notify"
    if not os.path.exists(os.path.join(app_dir(), "netsentinel.py")):
        return "notify"
    return "source"


def relaunch_cmd(argv=None):
    """The command that starts this copy again with the same options, without opening a browser."""
    args = list(sys.argv[1:] if argv is None else argv)
    if "--no-browser" not in args:
        args.append("--no-browser")
    if getattr(sys, "frozen", False):
        return [sys.executable] + args
    return [sys.executable, os.path.join(app_dir(), "netsentinel.py")] + args


def spawn(cmd):
    kwargs = {"close_fds": True, "cwd": os.path.dirname(cmd[1] if not getattr(sys, "frozen", False) else cmd[0])}
    if IS_WINDOWS:
        kwargs["creationflags"] = 0x00000010 | 0x00000200  # CREATE_NEW_CONSOLE | CREATE_NEW_PROCESS_GROUP
    return subprocess.Popen(cmd, **kwargs)


def _get(url, timeout=60, limit=MAX_SIZE, headers=None):
    req = urllib.request.Request(url, headers=dict({"User-Agent": f"Prahari/{__version__}",
                                                    "Cache-Control": "no-cache"}, **(headers or {})))
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read(limit + 1)
    if len(data) > limit:
        raise ValueError("download too large")
    return data


def verify(latest, public_key=None):
    """Return the manifest dict if latest.json is signed by the Prahari update key, else raise."""
    key = public_key or PUBLIC_KEY
    if key.startswith("__"):
        raise ValueError("this build has no update key")
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        raise ValueError("the 'cryptography' package is needed to verify updates (pip install cryptography)")
    text = latest["manifest"]
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(key)).verify(
            base64.b64decode(latest["sig"]), text.encode("utf-8"))
    except Exception:
        raise ValueError("update signature is not valid - ignored")
    manifest = json.loads(text)
    if not isinstance(manifest.get("assets"), dict) or not manifest.get("version"):
        raise ValueError("update manifest is incomplete")
    return manifest


def safe_members(zf):
    out = []
    for info in zf.infolist():
        if info.is_dir():
            continue
        name = info.filename.replace("\\", "/")
        parts = name.split("/")
        if name.startswith("/") or ".." in parts or ":" in name or parts[0] not in APP_TOP:
            raise ValueError(f"unexpected file in update: {name}")
        out.append((info, name))
    return out


# --------------------------------------------------------------------------- start-up / rollback

def _rollback(pending, log):
    mode = pending.get("mode")
    if mode == "exe":
        exe, old = pending["target"], pending["backup"]
        if os.path.exists(old):
            broken = exe + ".bad"
            _remove(broken)
            os.replace(exe, broken)  # renaming a running exe is allowed on Windows
            os.replace(old, exe)
    elif mode == "source":
        base, backup = pending["target"], pending["backup"]
        for root, _dirs, files in os.walk(backup):
            for name in files:
                src = os.path.join(root, name)
                rel = os.path.relpath(src, backup)
                if rel == "_new_files.json":
                    continue
                dst = os.path.join(base, rel)
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                shutil.copy2(src, dst)
        for rel in _read(os.path.join(backup, "_new_files.json"), []):
            _remove(os.path.join(base, rel))
    bad = _read(BAD, [])
    if pending.get("version") not in bad:
        bad.append(pending.get("version"))
    _write(BAD, bad)
    _remove(PENDING)
    log(f"update {pending.get('version')} did not run properly - went back to {pending.get('from')}")


def boot_check(log=print):
    """Call once at start-up. Counts starts of a fresh update and rolls back after repeated failures.

    Returns True when a rollback happened and the caller should start the restored copy and exit."""
    pending = _read(PENDING, None)
    if not pending:
        return False
    if pending.get("version") != __version__:
        # the previous version is running (rolled back by hand, or the swap never happened)
        _remove(PENDING)
        return False
    pending["starts"] = pending.get("starts", 0) + 1
    if pending["starts"] > MAX_FAILED_STARTS:
        try:
            _rollback(pending, log)
            return True
        except Exception as exc:  # keep starting whatever happens
            log(f"rollback problem: {exc}")
            _remove(PENDING)
            return False
    _write(PENDING, pending)
    return False


def rollback_and_relaunch(log=print):
    pending = _read(PENDING, None)
    if pending:
        try:
            _rollback(pending, log)
        except Exception as exc:
            log(f"rollback problem: {exc}")
            return False
    try:
        spawn(relaunch_cmd())
        return True
    except OSError as exc:
        log(f"could not restart the previous version: {exc}")
        return False


# --------------------------------------------------------------------------- the updater

class Updater:
    def __init__(self, cfg_get, log=print, on_restart=None):
        self.cfg_get = cfg_get            # callable -> settings["update"]
        self.log = log
        self.on_restart = on_restart      # called after an install; must stop the dashboard
        self.mode = install_mode()
        self.status = "idle"              # idle|checking|up_to_date|available|updating|restarting|error
        self.latest = None
        self.notes_url = ""
        self.last_check = None
        self.error = ""
        self.restart_requested = False
        self._manifest = None
        self._kick = threading.Event()
        self._install_now = False
        self._lock = threading.Lock()

    # -- settings
    @property
    def cfg(self):
        return self.cfg_get() or {}

    @property
    def auto_install(self):
        return bool(self.cfg.get("auto_install", True)) and self.mode != "notify"

    def snapshot(self):
        return {"version": __version__, "mode": self.mode, "status": self.status,
                "latest": self.latest, "notes_url": self.notes_url, "last_check": self.last_check,
                "error": self.error, "check": bool(self.cfg.get("check", True)),
                "auto_install": self.auto_install, "can_install": self.mode != "notify",
                "skipped": _read(BAD, [])}

    def check_now(self, install=False, source=None):
        """source: None = GitHub; or {"base": hub mirror URL, "headers": {...}} (still signature-checked)."""
        self._install_now = bool(install)
        self._next_source = source
        self._kick.set()

    # -- work
    def check_once(self, install=None, source=None):
        """Check GitHub (or a head-office mirror); install when allowed. Returns True when a restart is due.

        A mirror only changes WHERE the files come from: latest.json must still carry a valid
        signature from the Prahari key, and every file must match the signed checksum."""
        with self._lock:
            self.status, self.error = "checking", ""
            self._source = source
            try:
                try:
                    if source:
                        raw = _get(source["base"].rstrip("/") + "/latest.json", timeout=20, limit=64 * 1024,
                                   headers=source.get("headers"))
                    else:
                        raw = _get(LATEST_URL, timeout=20, limit=64 * 1024)
                except urllib.error.HTTPError as exc:
                    if exc.code == 404:
                        raise ValueError("no signed release published on GitHub yet" if not source
                                         else "the head office has not published a release yet")
                    raise
                manifest = verify(json.loads(raw))
                self.last_check = time.time()
                self.latest = manifest["version"]
                self.notes_url = f"https://github.com/{REPO}/releases/tag/{manifest.get('tag') or 'v' + self.latest}"
                if vtuple(self.latest) <= vtuple(__version__):
                    self.status = "up_to_date"
                    return False
                if self.latest in _read(BAD, []) and not install:
                    self.status = "available"
                    self.error = f"{self.latest} failed here before - install it by hand to retry"
                    return False
                self._manifest = manifest
                if install is None:
                    install = self.auto_install
                if not install or self.mode == "notify":
                    self.status = "available"
                    return False
                self.status = "updating"
                self.install(manifest)
                self.status = "restarting"
                self.restart_requested = True
                return True
            except Exception as exc:  # report and retry next time
                self.status, self.error = "error", str(exc)[:200]
                self.log(f"update check failed: {self.error}")
                return False

    def _asset(self, manifest, key):
        asset = (manifest.get("assets") or {}).get(key)
        if not asset:
            raise ValueError(f"release {manifest['version']} has no {key} build")
        tag = manifest.get("tag") or "v" + manifest["version"]
        source = getattr(self, "_source", None)
        if source:
            data = _get(source["base"].rstrip("/") + "/" + asset["file"], headers=source.get("headers"))
        else:
            data = _get(ASSET_URL.format(tag=tag, file=asset["file"]))
        if hashlib.sha256(data).hexdigest() != asset["sha256"]:
            raise ValueError(f"{asset['file']} does not match the signed checksum - not installed")
        return data

    def install(self, manifest):
        if self.mode == "exe":
            self._install_exe(manifest)
        elif self.mode == "source":
            self._install_source(manifest)
        else:
            raise ValueError("this copy can't update itself - download the new version")
        self.log(f"installed update {manifest['version']} (was {__version__}); restarting")

    def _install_exe(self, manifest):
        data = self._asset(manifest, "exe")
        exe = os.path.abspath(sys.executable)
        new, old = exe + ".new", exe + ".old"
        try:
            with open(new, "wb") as fh:
                fh.write(data)
        except OSError as exc:
            raise ValueError(f"can't write next to {exe} ({exc}) - move Prahari to a folder you can write to")
        _remove(old)
        os.replace(exe, old)
        try:
            os.replace(new, exe)
        except OSError:
            os.replace(old, exe)
            raise
        _write(PENDING, {"version": manifest["version"], "from": __version__, "mode": "exe",
                         "target": exe, "backup": old, "starts": 0, "installed": time.time()})

    def _install_source(self, manifest):
        data = self._asset(manifest, "app")
        zf = zipfile.ZipFile(io.BytesIO(data))
        members = safe_members(zf)
        base = app_dir()
        backup = os.path.join(UPDATE_DIR, "backup", __version__)
        shutil.rmtree(backup, ignore_errors=True)
        os.makedirs(backup)
        new_files = []
        for _info, name in members:  # back up everything first, then write
            dst = os.path.join(base, name)
            if os.path.exists(dst):
                os.makedirs(os.path.dirname(os.path.join(backup, name)), exist_ok=True)
                shutil.copy2(dst, os.path.join(backup, name))
            else:
                new_files.append(name)
        _write(os.path.join(backup, "_new_files.json"), new_files)
        _write(PENDING, {"version": manifest["version"], "from": __version__, "mode": "source",
                         "target": base, "backup": backup, "starts": 0, "installed": time.time()})
        for info, name in members:
            dst = os.path.join(base, name)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            tmp = dst + ".new"
            with zf.open(info) as src, open(tmp, "wb") as out:
                shutil.copyfileobj(src, out)
            os.replace(tmp, dst)

    # -- after the dashboard has stopped
    def handoff(self):
        """Start the new version and make sure it stays up; otherwise put the old one back.

        Called by main() once the web server and monitors are stopped. Returns the exit code."""
        time.sleep(2)  # let the UDP listeners and the dashboard port close
        try:
            child = spawn(relaunch_cmd())
        except OSError as exc:
            self.log(f"could not start the new version ({exc}) - going back")
            rollback_and_relaunch(self.log)
            return 1
        deadline = time.time() + HANDOFF_WATCH
        while time.time() < deadline:
            if child.poll() is not None:
                self.log(f"the new version stopped straight away (exit {child.returncode}) - going back")
                rollback_and_relaunch(self.log)
                return 1
            time.sleep(1)
        self.log("new version is running in its own window; this one is closing")
        return 0

    def mark_healthy_later(self):
        def ok():
            time.sleep(HEALTHY_AFTER)
            pending = _read(PENDING, None)
            if pending and pending.get("version") == __version__:
                _remove(PENDING)
                if pending.get("mode") == "exe":
                    _remove(pending.get("backup") or "")
                    _remove((pending.get("target") or "") + ".bad")
                self.log(f"update {__version__} is running fine")
        threading.Thread(target=ok, daemon=True, name="update-ok").start()

    def loop(self):
        self.mark_healthy_later()
        self._kick.wait(FIRST_CHECK_AFTER)
        while True:
            manual = self._kick.is_set()
            self._kick.clear()
            # "Install now" installs; "Check now" only checks; the timer follows the auto-install setting
            install = True if self._install_now else (False if manual else None)
            source = getattr(self, "_next_source", None) if manual else None
            self._install_now, self._next_source = False, None
            if manual or self.cfg.get("check", True):
                if self.check_once(install=install, source=source) and self.on_restart:
                    self.on_restart()
                    return
            self._kick.wait(CHECK_EVERY)

    def start(self):
        global CURRENT
        CURRENT = self
        threading.Thread(target=self.loop, daemon=True, name="updater").start()
        return self


def selftest():
    """CI check on the Windows runner: can this exe rename itself while running, as an update must?"""
    if not getattr(sys, "frozen", False):
        print("selftest: not a frozen build - nothing to test")
        return 0
    exe = os.path.abspath(sys.executable)
    old = exe + ".selftest"
    try:
        os.replace(exe, old)
        os.replace(old, exe)
    except OSError as exc:
        print(f"selftest: FAILED - the running exe can't be renamed ({exc})")
        return 1
    problems = []
    try:  # Claude SDK bundled and able to build a client (no network call)
        import anthropic
        anthropic.Anthropic(api_key="selftest")
        ai_state = f"anthropic {anthropic.__version__}"
    except Exception as exc:
        ai_state = f"MISSING ({exc.__class__.__name__})"
        problems.append("anthropic")
    try:
        import scapy  # noqa: F401
        problems.append("scapy is bundled (GPL) - it must not be")
    except ImportError:
        pass
    if PUBLIC_KEY.startswith("__"):
        problems.append("update key")
    print(f"selftest: {'ok' if not problems else 'FAILED'} - mode {install_mode()}, "
          f"key {'set' if not PUBLIC_KEY.startswith('__') else 'MISSING'}, AI {ai_state}, scapy not bundled"
          + (f" | problems: {', '.join(problems)}" if problems else ""))
    return 0 if not problems else 1
