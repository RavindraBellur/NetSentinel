"""Certificate lifecycle: expiry watch, renewal hook, CSR for your own CA.

Prahari does not pretend to be a certificate authority. For a public name you either
let a tool renew (win-acme on Windows, certbot on Linux - both detected automatically) or
your PKI signs a CSR this module generates. What it *does* do is watch the clock: it warns
in the console, in the event log and by alert when the certificate is close to expiring,
runs the renewal command you configure, and can restart itself so the new certificate is
picked up.
"""

from __future__ import annotations

import datetime
import os
import shutil
import subprocess
import sys
import threading
import time

from . import alerts, settings, store


def expiry_info(cert_path):
    """(days_left, not_after, subject, issuer) or None when it cannot be read."""
    try:
        from cryptography import x509
        with open(cert_path, "rb") as fh:
            cert = x509.load_pem_x509_certificate(fh.read())
    except Exception:
        return None
    try:
        not_after = cert.not_valid_after_utc
        now = datetime.datetime.now(datetime.timezone.utc)
    except AttributeError:
        not_after = cert.not_valid_after
        now = datetime.datetime.utcnow()
    days = (not_after - now).days
    return {
        "days_left": days,
        "not_after": not_after.strftime("%Y-%m-%d"),
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "self_signed": cert.subject == cert.issuer,
    }


def find_renewal_tool():
    """Look for the usual ACME clients."""
    for name, args in (("wacs.exe", "win-acme"), ("wacs", "win-acme"),
                       ("certbot", "certbot"), ("lego", "lego")):
        path = shutil.which(name)
        if path:
            return args, path
    return "", ""


def make_csr(domain, out_dir=None, key_path=None, common_name=None):
    """Generate a key + CSR for your CA to sign. Returns (csr_path, key_path)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    out_dir = out_dir or os.path.join(os.path.expanduser("~"), ".netsentinel")
    os.makedirs(out_dir, exist_ok=True)
    csr_path = os.path.join(out_dir, f"{domain}.csr")
    key_path = key_path or os.path.join(out_dir, f"{domain}.key.pem")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name or domain)]))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(domain)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    with open(key_path, "wb") as fh:
        fh.write(key.private_bytes(encoding=serialization.Encoding.PEM,
                                   format=serialization.PrivateFormat.TraditionalOpenSSL,
                                   encryption_algorithm=serialization.NoEncryption()))
    with open(csr_path, "wb") as fh:
        fh.write(csr.public_bytes(serialization.Encoding.PEM))
    try:
        os.chmod(key_path, 0o600)
    except Exception:
        pass
    return csr_path, key_path


SHELL_META = set(";|&<>$`%^\n\r")


def renewal_args(command):
    """Settings text -> (argument list, problem). No shell is ever involved.

    The command is admin-controlled, but Prahari runs as SYSTEM: if it went through a shell, anyone
    who could change a setting could chain any command onto it. So it is split into the program and
    its arguments, and anything that looks like shell syntax is refused outright."""
    command = (command or "").strip()
    if not command:
        return None, "no renewal command configured"
    bad = sorted({ch for ch in command if ch in SHELL_META})
    if bad:
        shown = " ".join("newline" if c in "\r\n" else c for c in bad)
        return None, (f"the renewal command may not contain shell syntax ({shown}) - give the "
                      f"program and its arguments only, e.g. certbot renew --quiet")
    import shlex
    try:
        if os.name == "nt":
            args = [a[1:-1] if len(a) > 1 and a[0] == a[-1] == '"' else a
                    for a in shlex.split(command, posix=False)]
        else:
            args = shlex.split(command)
    except ValueError as exc:
        return None, f"the renewal command could not be read: {exc}"
    if not args:
        return None, "no renewal command configured"
    return args, ""


def run_renewal(command):
    """Run the configured renewal command (never through a shell) and return (ok, output)."""
    args, problem = renewal_args(command)
    if problem:
        return False, problem
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=600,
                              stdin=subprocess.DEVNULL)
        output = ((proc.stdout or "") + (proc.stderr or "")).strip()
        return proc.returncode == 0, output[-1500:]
    except Exception as exc:
        return False, f"{exc.__class__.__name__}: {exc}"


class CertWatcher(threading.Thread):
    """Checks the certificate daily, warns, renews and optionally restarts."""

    def __init__(self, cert_path, log=None, restart=None):
        super().__init__(daemon=True, name="cert-watch")
        self.cert_path = cert_path
        self.log = log or (lambda m: None)
        self.restart = restart
        self._stop = threading.Event()
        self.state = {"days_left": None, "not_after": "", "last_check": 0,
                      "last_renew": 0, "last_result": "", "warned": False}

    def stop(self):
        self._stop.set()

    def check(self):
        cfg = settings.load()
        warn_days = int((cfg.get("certs") or {}).get("renew_days") or 21)
        info = expiry_info(self.cert_path)
        self.state["last_check"] = int(time.time())
        if not info:
            self.state["last_result"] = "certificate could not be read"
            return self.state
        self.state.update(days_left=info["days_left"], not_after=info["not_after"])
        if info["days_left"] > warn_days:
            self.state["warned"] = False
            return self.state

        message = (f"TLS certificate expires in {info['days_left']} day(s) on {info['not_after']}"
                   + (" (self-signed)" if info["self_signed"] else ""))
        if not self.state["warned"]:
            self.state["warned"] = True
            store.add_event("tls", "high", message)
            self.log(message)
            try:
                alerts.send_email(cfg, "[Prahari] " + message,
                                  f"The console certificate at {self.cert_path} expires on "
                                  f"{info['not_after']}.\n\nRenew it and restart Prahari, or "
                                  f"configure certs.renew_command.")
            except Exception:
                pass

        command = (cfg.get("certs") or {}).get("renew_command") or ""
        if command:
            ok, output = run_renewal(command)
            self.state["last_renew"] = int(time.time())
            self.state["last_result"] = ("renewed" if ok else "renewal failed") + f": {output[:300]}"
            store.add_event("tls", "info" if ok else "high",
                            f"certificate renewal {'succeeded' if ok else 'failed'}")
            if ok and (cfg.get("certs") or {}).get("auto_restart", True) and self.restart:
                self.log("restarting to load the renewed certificate")
                time.sleep(2)
                self.restart()
        return self.state

    def run(self):
        self._stop.wait(20)
        while not self._stop.is_set():
            try:
                self.check()
            except Exception as exc:
                self.log(f"certificate check failed: {exc}")
            self._stop.wait(12 * 3600)
