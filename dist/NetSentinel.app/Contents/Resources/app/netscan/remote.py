"""Remote access to discovered devices.

NetSentinel deliberately does **not** ship its own remote-desktop server - a
hidden remote-control service inside a scanning tool would be a security hole.
Instead it drives the tools Windows already has, or the one you installed:

    RDP      -> mstsc /v:<ip>            (enable on the target with enable_rdp.bat)
    VNC      -> TightVNC / RealVNC / UltraVNC viewer
    SSH      -> built-in OpenSSH client in a new console window
    Telnet   -> console window
    Web UI   -> default browser (router, DVR, printer, AP admin pages)
    RTSP     -> VLC, for camera / DVR live view
    Wake on LAN -> magic packet, to power a machine on
    Ping     -> continuous ping in a console window

Every action is a fixed command template with a validated IP address. Nothing is
taken from the browser except the device IP and an action id from a whitelist, so
the dashboard cannot be used to run arbitrary commands.
"""

from __future__ import annotations

import ipaddress
import os
import shutil
import socket
import subprocess
import sys
import webbrowser

IS_WINDOWS = os.name == "nt"
CREATE_NEW_CONSOLE = 0x00000010
CREATE_NO_WINDOW = 0x08000000

WEB_PORTS = (443, 8443, 80, 8080, 8000, 8001, 8081, 8888, 9000, 6036)
TLS_PORTS = (443, 8443)

_VNC_PATHS = (
    r"C:\Program Files\TightVNC\tvnviewer.exe",
    r"C:\Program Files (x86)\TightVNC\tvnviewer.exe",
    r"C:\Program Files\RealVNC\VNC Viewer\vncviewer.exe",
    r"C:\Program Files\UltraVNC\vncviewer.exe",
    r"C:\Program Files (x86)\UltraVNC\vncviewer.exe",
)
_VLC_PATHS = (
    r"C:\Program Files\VideoLAN\VLC\vlc.exe",
    r"C:\Program Files (x86)\VideoLAN\VLC\vlc.exe",
)

_cache = {}


def _find(paths, names=()):
    key = paths
    if key in _cache:
        return _cache[key]
    found = ""
    for path in paths:
        if os.path.exists(path):
            found = path
            break
    if not found:
        for name in names:
            found = shutil.which(name) or ""
            if found:
                break
    _cache[key] = found
    return found


def vnc_viewer():
    return _find(_VNC_PATHS, ("vncviewer", "tvnviewer"))


def vlc():
    return _find(_VLC_PATHS, ("vlc",))


def valid_ip(ip):
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except Exception:
        return ""
    if addr.version != 4 or addr.is_multicast or addr.is_loopback or str(addr) == "0.0.0.0":
        return ""
    return str(addr)


def _web_url(dev):
    ports = {p["port"] for p in dev.get("ports", [])}
    for port in WEB_PORTS:
        if port in ports:
            scheme = "https" if port in TLS_PORTS else "http"
            suffix = "" if port in (80, 443) else f":{port}"
            return f"{scheme}://{dev['ip']}{suffix}/"
    return ""


def actions_for(dev):
    """Which remote actions make sense for this device, and are they available?"""
    ports = {p["port"] for p in dev.get("ports", [])}
    out = []

    if 3389 in ports:
        out.append({
            "id": "rdp", "label": "Remote Desktop (RDP)", "detail": "mstsc to port 3389",
            "ok": IS_WINDOWS,
            "why": "" if IS_WINDOWS else "RDP client is Windows only",
        })
    if 5900 in ports:
        out.append({
            "id": "vnc", "label": "VNC screen", "detail": "VNC viewer to port 5900",
            "ok": bool(vnc_viewer()),
            "why": "" if vnc_viewer() else "no VNC viewer found - install TightVNC viewer",
        })
    if 22 in ports:
        out.append({
            "id": "ssh", "label": "SSH terminal", "detail": "ssh to port 22",
            "ok": True, "why": "",
        })
    if 23 in ports:
        out.append({
            "id": "telnet", "label": "Telnet console", "detail": "telnet to port 23",
            "ok": IS_WINDOWS, "why": "" if IS_WINDOWS else "use ssh instead",
        })

    url = _web_url(dev)
    if url:
        out.append({
            "id": "web", "label": "Open admin page", "detail": url,
            "ok": True, "why": "",
        })

    if 554 in ports:
        out.append({
            "id": "rtsp", "label": "Live video (RTSP)", "detail": f"rtsp://{dev['ip']}:554/",
            "ok": bool(vlc()),
            "why": "" if vlc() else "VLC not found - install VLC, or paste the address into any player",
        })

    if dev.get("mac"):
        out.append({
            "id": "wol", "label": "Wake on LAN", "detail": "power on by MAC address",
            "ok": True, "why": "",
        })

    out.append({"id": "ping", "label": "Continuous ping", "detail": "watch it stay reachable",
                "ok": True, "why": ""})
    return out


def _spawn(cmd, new_console=False):
    flags = 0
    if IS_WINDOWS and new_console:
        flags = CREATE_NEW_CONSOLE
    subprocess.Popen(cmd, creationflags=flags, close_fds=True)


def wake_on_lan(mac, broadcast="255.255.255.255"):
    try:
        raw = bytes.fromhex(mac.replace(":", "").replace("-", "").strip())
    except Exception:
        return False, "not a valid MAC address"
    if len(raw) != 6:
        return False, "not a valid MAC address"
    packet = b"\xff" * 6 + raw * 16
    sent = 0
    for target in {broadcast, "255.255.255.255"}:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            for port in (9, 7):
                sock.sendto(packet, (target, port))
                sent += 1
        except Exception:
            pass
        finally:
            sock.close()
    if not sent:
        return False, "could not send the magic packet (firewall?)"
    return True, f"Wake-on-LAN packet sent to {mac}"


def launch(dev, action, broadcast="255.255.255.255"):
    """Run one whitelisted remote action for a known device."""
    ip = valid_ip(dev.get("ip"))
    if not ip:
        return {"ok": False, "message": "invalid device address"}
    ports = {p["port"] for p in dev.get("ports", [])}
    action = (action or "").strip().lower()

    try:
        if action == "rdp":
            if not IS_WINDOWS:
                return {"ok": False, "message": "RDP client is only on Windows"}
            port = 3389
            target = ip if port == 3389 else f"{ip}:{port}"
            _spawn(["mstsc", f"/v:{target}"])
            return {"ok": True, "message": f"Opening Remote Desktop to {target}"}

        if action == "vnc":
            viewer = vnc_viewer()
            if not viewer:
                return {"ok": False, "message": "No VNC viewer installed. Install TightVNC viewer (free) and try again."}
            _spawn([viewer, f"{ip}:5900"])
            return {"ok": True, "message": f"Opening VNC to {ip}:5900"}

        if action == "ssh":
            if IS_WINDOWS:
                _spawn(["cmd", "/k", f"ssh {ip}"], new_console=True)
            else:
                _spawn(["x-terminal-emulator", "-e", f"ssh {ip}"])
            return {"ok": True, "message": f"SSH window opening for {ip} - enter the user name at the prompt"}

        if action == "telnet":
            if not IS_WINDOWS:
                return {"ok": False, "message": "Telnet helper is Windows only"}
            _spawn(["cmd", "/k", f"telnet {ip}"], new_console=True)
            return {"ok": True, "message": f"Telnet window opening for {ip}"}

        if action == "web":
            url = _web_url(dev)
            if not url:
                return {"ok": False, "message": "No web interface port was found on this device"}
            webbrowser.open(url)
            return {"ok": True, "message": f"Opening {url}"}

        if action == "rtsp":
            player = vlc()
            url = f"rtsp://{ip}:554/"
            if player:
                _spawn([player, url])
                return {"ok": True, "message": f"Opening live stream in VLC: {url}"}
            return {"ok": False, "message": f"VLC not found. Copy this into any player: {url}"}

        if action == "wol":
            mac = dev.get("mac") or ""
            if not mac:
                return {"ok": False, "message": "No MAC address known for this device - rescan first"}
            ok, msg = wake_on_lan(mac, broadcast)
            return {"ok": ok, "message": msg}

        if action == "ping":
            if IS_WINDOWS:
                _spawn(["cmd", "/k", f"ping -t {ip}"], new_console=True)
            else:
                _spawn(["x-terminal-emulator", "-e", f"ping {ip}"])
            return {"ok": True, "message": f"Ping window opening for {ip}"}

    except FileNotFoundError:
        return {"ok": False, "message": "The program for this action is not installed on this PC"}
    except Exception as e:
        return {"ok": False, "message": f"could not start: {e}"}

    return {"ok": False, "message": f"unknown action '{action}'"}
