"""HTTPS for the console, and certificate handling.

Two ways to get a certificate, in the order an enterprise wants them:

  1. **Your own certificate** - point `--tls-cert` and `--tls-key` at a PEM pair from
     your PKI (or an exported .pfx converted once). This is the only option a security
     team will accept, because clients must trust the issuer.
  2. **A self-signed certificate** generated locally, for a lab or a first look. Browsers
     will warn unless the certificate is installed as trusted.

Nothing here invents cryptography: key generation and signing use the `cryptography`
package when it is installed, and a clear message is printed when it is not.
"""

from __future__ import annotations

import datetime
import ipaddress
import os
import socket
import ssl

CERT_DIR = os.path.join(os.path.expanduser("~"), ".netsentinel")
DEFAULT_CERT = os.path.join(CERT_DIR, "console-cert.pem")
DEFAULT_KEY = os.path.join(CERT_DIR, "console-key.pem")


def have_crypto():
    try:
        import cryptography  # noqa: F401
        return True
    except Exception:
        return False


def local_names():
    """Every name/IP this certificate should cover."""
    names = {"localhost", socket.gethostname()}
    ips = {"127.0.0.1"}
    try:
        from . import netinfo

        ip = netinfo.primary_ipv4()
        if ip and not ip.startswith("127."):
            ips.add(ip)
    except Exception:
        pass
    return sorted(names), sorted(ips)


def make_self_signed(cert_path=DEFAULT_CERT, key_path=DEFAULT_KEY, days=825,
                     common_name=None):
    """Create a self-signed certificate + key pair. Returns (cert_path, key_path)."""
    if not have_crypto():
        raise RuntimeError(
            "the 'cryptography' package is needed to create a certificate. "
            "Install it (pip install cryptography) or pass --tls-cert/--tls-key "
            "with a certificate from your own PKI."
        )
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    os.makedirs(os.path.dirname(cert_path) or ".", exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    names, ips = local_names()
    cn = common_name or names[0]
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NetSentinel"),
    ])
    san = [x509.DNSName(n) for n in names] + [x509.IPAddress(ipaddress.ip_address(i)) for i in ips]
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName(san), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(
            x509.KeyUsage(digital_signature=True, key_encipherment=True, content_commitment=False,
                          data_encipherment=False, key_agreement=False, key_cert_sign=False,
                          crl_sign=False, encipher_only=False, decipher_only=False),
            critical=True)
        .sign(key, hashes.SHA256())
    )
    with open(key_path, "wb") as fh:
        fh.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()))
    with open(cert_path, "wb") as fh:
        fh.write(cert.public_bytes(serialization.Encoding.PEM))
    for path in (key_path,):
        try:
            os.chmod(path, 0o600)
        except Exception:
            pass
    return cert_path, key_path


def describe(cert_path):
    """Return a short summary of a certificate, for the console banner."""
    info = {"path": cert_path, "subject": "", "issuer": "", "expires": "", "san": [], "self_signed": False}
    try:
        if have_crypto():
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes
            with open(cert_path, "rb") as fh:
                cert = x509.load_pem_x509_certificate(fh.read())
            info["subject"] = cert.subject.rfc4514_string()
            info["issuer"] = cert.issuer.rfc4514_string()
            try:
                info["expires"] = cert.not_valid_after_utc.strftime("%Y-%m-%d")
            except AttributeError:
                info["expires"] = cert.not_valid_after.strftime("%Y-%m-%d")
            info["self_signed"] = cert.subject == cert.issuer
            try:
                san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                info["san"] = [str(v) for v in san.get_values_for_type(x509.DNSName)]
                info["san"] += [str(v) for v in san.get_values_for_type(x509.IPAddress)]
            except Exception:
                pass
    except Exception:
        pass
    return info


def context(cert_path=None, key_path=None, allow_self_signed=True):
    """Build a server SSLContext from a PEM pair."""
    cert_path = cert_path or DEFAULT_CERT
    key_path = key_path or DEFAULT_KEY
    if not (os.path.exists(cert_path) and os.path.exists(key_path)):
        raise FileNotFoundError(f"certificate not found: {cert_path} / {key_path}")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.options |= ssl.OP_NO_COMPRESSION
    try:
        ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM")
    except Exception:
        pass
    ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    return ctx
