"""Check devices for factory default passwords.

A camera, NVR, printer or access point still answering to admin/admin is the single most
common way a hotel network is taken over: the factory password is published in the manual,
so it is not a secret at all.

What this does, and what it refuses to do:

  * It only ever talks to devices that are already on this LAN and on the allow-list, and
    only when the operator has switched it on and confirmed they own the network.
  * It tries a short, fixed list of *published factory defaults* - one attempt each, a
    pause between attempts, and a hard cap per device. It is not a brute-force tool: there
    are no dictionaries, no wordlists, no repeats and no lockout games.
  * It checks the protocols where success is unambiguous: HTTP Basic/Digest on the admin
    page, RTSP on cameras, anonymous FTP, and the SNMP default community.
  * Form-based logins (the HTML login page of most recorders) are NOT guessed: without the
    vendor's API a wrong guess and a right one look the same, and hammering a form locks the
    account. For those devices the finding says "factory login page - verify by hand".
"""

from __future__ import annotations

import base64
import hashlib
import re
import socket
import time
import urllib.error
import urllib.request

from . import settings, store

# Published factory defaults only - one attempt each, no variations.
DEFAULT_CREDENTIALS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "12345"), ("admin", "1234"),
    ("admin", "admin123"), ("admin", "123456"), ("admin", "888888"), ("admin", "1111"),
    ("admin", ""), ("root", "root"), ("root", "admin"), ("root", "12345"),
    ("user", "user"), ("guest", "guest"), ("support", "support"), ("service", "service"),
    ("cisco", "cisco"), ("ubnt", "ubnt"), ("888888", "888888"), ("666666", "666666"),
]

MAX_ATTEMPTS_PER_DEVICE = 12
PAUSE_SECONDS = 0.35


def _b64(text):
    return base64.b64encode(text.encode()).decode()


def _digest_header(challenge, user, password, method, uri):
    """Answer a Digest challenge (RFC 7616, MD5 - what cameras use)."""
    def field(name):
        m = re.search(rf'{name}="?([^",]+)"?', challenge or "")
        return m.group(1) if m else ""
    realm, nonce, qop = field("realm"), field("nonce"), field("qop")
    ha1 = hashlib.md5(f"{user}:{realm}:{password}".encode()).hexdigest()
    ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
    if "auth" in qop:
        nc, cnonce = "00000001", hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
        resp = hashlib.md5(f"{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}".encode()).hexdigest()
        return (f'Digest username="{user}", realm="{realm}", nonce="{nonce}", uri="{uri}", '
                f'qop=auth, nc={nc}, cnonce="{cnonce}", response="{resp}"')
    resp = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()
    return (f'Digest username="{user}", realm="{realm}", nonce="{nonce}", '
            f'uri="{uri}", response="{resp}"')


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None   # a redirect is an answer in itself; never follow it to a login page


def _ctx(url):
    if not url.startswith("https"):
        return None
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE   # device admin pages are self-signed; nothing secret is sent
    return ctx


def _urlopen(req, timeout, url):
    handlers = [_NoRedirect()]
    ctx = _ctx(url)
    if ctx is not None:
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
    return urllib.request.build_opener(*handlers).open(req, timeout=timeout)


def _open(url, user=None, password=None, timeout=3.0, method="GET"):
    """Request a URL, answering a Basic or Digest challenge once."""
    req = urllib.request.Request(url, method=method,
                                 headers={"User-Agent": "NetSentinel-defaults/1.0"})
    if user is not None:
        req.add_header("Authorization", "Basic " + _b64(f"{user}:{password}"))
    try:
        with _urlopen(req, timeout, url) as resp:
            return resp.status, resp.headers
    except urllib.error.HTTPError as exc:
        challenge = exc.headers.get("WWW-Authenticate") or ""
        if exc.code == 401 and challenge.lower().startswith("digest") and user is not None:
            req2 = urllib.request.Request(url, method=method,
                                          headers={"User-Agent": "NetSentinel-defaults/1.0"})
            req2.add_header("Authorization",
                            _digest_header(challenge, user, password, method, "/"))
            try:
                with _urlopen(req2, timeout, url) as resp2:
                    return resp2.status, resp2.headers
            except urllib.error.HTTPError as exc2:
                return exc2.code, exc2.headers
            except Exception:
                return 0, {}
        return exc.code, exc.headers
    except Exception:
        return 0, {}


def http_demands_login(ip, port, scheme="http", timeout=3.0):
    """True only when the admin page refuses us without credentials (HTTP 401).

    A page that opens, or redirects to a login form, without credentials proves nothing about
    a password - guessing there would report every such device as 'factory login works'."""
    status, _headers = _open(f"{scheme}://{ip}:{port}/", None, None, timeout)
    return status == 401


def check_http(ip, port, user, password, scheme="http", timeout=3.0):
    """True when the admin page accepts these credentials (call http_demands_login first)."""
    status, _headers = _open(f"{scheme}://{ip}:{port}/", user, password, timeout)
    return status in (200, 204)


def check_rtsp(ip, port, user, password, timeout=3.0):
    """True when a camera accepts these credentials on RTSP."""
    uri = f"rtsp://{ip}:{port}/"
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
    except Exception:
        return False
    try:
        request = (f"DESCRIBE {uri} RTSP/1.0\r\nCSeq: 1\r\n"
                   f"Authorization: Basic {_b64(f'{user}:{password}')}\r\n"
                   f"User-Agent: NetSentinel\r\n\r\n")
        sock.sendall(request.encode())
        sock.settimeout(timeout)
        head = sock.recv(256).decode("latin-1", "replace")
        return head.startswith("RTSP/1.0 200")
    except Exception:
        return False
    finally:
        try:
            sock.close()
        except Exception:
            pass


def rtsp_demands_login(ip, port=554, timeout=3.0):
    """True only when the camera answers 401 to a request without credentials."""
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
    except Exception:
        return False
    try:
        sock.sendall(f"DESCRIBE rtsp://{ip}:{port}/ RTSP/1.0\r\nCSeq: 1\r\n"
                     f"User-Agent: NetSentinel\r\n\r\n".encode())
        sock.settimeout(timeout)
        return sock.recv(256).decode("latin-1", "replace").startswith("RTSP/1.0 401")
    except Exception:
        return False
    finally:
        try:
            sock.close()
        except Exception:
            pass


def rtsp_opens_without_login(ip, port=554, timeout=3.0):
    """True when the camera answers 200 to a request without credentials."""
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
    except Exception:
        return False
    try:
        sock.sendall(f"DESCRIBE rtsp://{ip}:{port}/ RTSP/1.0\r\nCSeq: 1\r\n"
                     f"User-Agent: NetSentinel\r\n\r\n".encode())
        sock.settimeout(timeout)
        return sock.recv(256).decode("latin-1", "replace").startswith("RTSP/1.0 200")
    except Exception:
        return False
    finally:
        try:
            sock.close()
        except Exception:
            pass


def check_ftp_anonymous(ip, port=21, timeout=3.0):
    """True when the FTP server accepts anonymous logins."""
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
    except Exception:
        return False
    try:
        sock.settimeout(timeout)
        sock.recv(256)
        sock.sendall(b"USER anonymous\r\n")
        reply = sock.recv(256).decode("latin-1", "replace")
        if not reply.startswith("331"):
            return False
        sock.sendall(b"PASS anonymous@example.com\r\n")
        reply = sock.recv(256).decode("latin-1", "replace")
        return reply.startswith("230")
    except Exception:
        return False
    finally:
        try:
            sock.close()
        except Exception:
            pass


def check_snmp_community(ip, community="public", timeout=1.5):
    """True when the device answers SNMP on that community."""
    from . import snmp
    try:
        return bool(snmp.get(ip, ["1.3.6.1.2.1.1.1.0"], community, timeout))
    except Exception:
        return False


def allowed(cfg, ip):
    """Every guard in one place."""
    conf = cfg.get("defaults_check") or {}
    if not conf.get("enabled"):
        return False, "the factory-password check is off"
    if not conf.get("i_own_this_network"):
        return False, "the operator has not confirmed this network is theirs"
    allow = [x.strip() for x in (conf.get("allow_ips") or []) if x.strip()]
    if allow and ip not in allow:
        return False, f"{ip} is not on the allow-list"
    if not allow:
        return False, "the allow-list is empty (add the device IPs first)"
    if ip != "0.0.0.0":
        from .safety import private_target
        ok, why = private_target(ip)
        if not ok:
            return False, why
    return True, "allowed"


def scan_device(device, cfg=None, log=None):
    """Try the factory list against one device. Returns findings."""
    cfg = cfg or settings.load()
    ip = (device or {}).get("ip")
    name = (device or {}).get("label") or (device or {}).get("hostname") or ip
    if not ip:
        return []
    ok, why = allowed(cfg, ip)
    if not ok:
        if log:
            log(f"factory-password check skipped for {ip}: {why}")
        return []

    conf = cfg.get("defaults_check") or {}
    cap = int(conf.get("max_attempts") or MAX_ATTEMPTS_PER_DEVICE)
    pause = max(0.2, int(conf.get("delay_ms") or 350) / 1000.0)
    ports = {p.get("port") for p in (device.get("ports") or []) if p.get("port")}
    findings = []
    attempts = 0

    def record(severity, rule, text, advice, extra=None):
        finding = {"severity": severity, "rule": rule, "device": name, "ip": ip,
                   "text": text, "advice": advice}
        if extra:
            finding.update(extra)
        findings.append(finding)
        store.add_event("defaults", severity if severity != "critical" else "high",
                        f"{name} ({ip}): {rule}")     # never log the password

    # ---- SNMP community (no login, so it is not a guess at all)
    if 161 in ports:
        if check_snmp_community(ip, "public"):
            record("high", "snmp-public",
                   f"{name} answers SNMP on the factory community 'public'",
                   "Set a long random community or move to SNMPv3 (Settings -> SNMPv3).")

    # ---- anonymous FTP
    if 21 in ports and attempts < cap:
        attempts += 1
        if check_ftp_anonymous(ip):
            record("high", "ftp-anonymous",
                   f"{name} accepts anonymous FTP - anyone can read or replace files",
                   "Disable anonymous access, or turn the FTP server off.")
        time.sleep(pause)

    # ---- web admin: Basic or Digest, one pair at a time
    web_ports = [p for p in (80, 8080, 8000, 81, 8081, 443, 8443) if p in ports]
    unverified_web = []
    for port in web_ports:
        scheme = "https" if port in (443, 8443) else "http"
        if not http_demands_login(ip, port, scheme):
            unverified_web.append(port)   # opens or redirects without a password: form login
            continue
        for user, password in DEFAULT_CREDENTIALS:
            if attempts >= cap:
                break
            attempts += 1
            try:
                hit = check_http(ip, port, user, password, scheme)
            except Exception:
                hit = False
            time.sleep(pause)
            if hit:
                label = password or "(blank)"
                record("critical", "factory-http-password",
                       f"{name} still accepts the factory login {user}/{label} on port {port}",
                       "Change the password now, turn off any remote/cloud access on the "
                       "device, and keep its admin page off the guest network.",
                       extra={"credential": f"{user}/{label}", "port": port})
                break
        if findings and findings[-1]["rule"] == "factory-http-password":
            break

    # ---- cameras over RTSP
    if 554 in ports and rtsp_opens_without_login(ip, 554):
        record("high", "rtsp-open",
               f"{name} streams video on RTSP without asking for any password",
               "Turn on RTSP authentication in the camera settings and set a strong password.")
    elif 554 in ports and rtsp_demands_login(ip, 554):
        for user, password in DEFAULT_CREDENTIALS:
            if attempts >= cap:
                break
            attempts += 1
            hit = check_rtsp(ip, 554, user, password)
            time.sleep(pause)
            if hit:
                label = password or "(blank)"
                record("critical", "factory-rtsp-password",
                       f"{name} streams video to {user}/{label} - the factory RTSP login",
                       "Change the camera password; anyone on the network can watch it.",
                       extra={"credential": f"{user}/{label}", "port": 554})
                break

    # ---- a web admin that we could not test automatically
    if unverified_web and not any(f["rule"].startswith("factory-") for f in findings):
        record("medium", "factory-login-unverified",
               f"{name} has a web admin page; a form login cannot be tested safely",
               "Open it and try the factory password by hand (usually admin/admin, "
               "admin/12345). If it lets you in, change it before anything else.")

    if log:
        log(f"factory-password check on {name}: {attempts} attempt(s), "
            f"{len(findings)} finding(s)")
    return findings


def summary(devices, cfg=None):
    """Run the check across the fleet, within the guards."""
    cfg = cfg or settings.load()
    out = {"enabled": bool((cfg.get("defaults_check") or {}).get("enabled")),
           "confirmed": bool((cfg.get("defaults_check") or {}).get("i_own_this_network")),
           "checked": 0, "findings": []}
    if not out["enabled"] or not out["confirmed"]:
        return out
    for dev in devices or []:
        ok, _why = allowed(cfg, dev.get("ip"))
        if not ok:
            continue
        out["checked"] += 1
        out["findings"].extend(scan_device(dev, cfg))
    return out
