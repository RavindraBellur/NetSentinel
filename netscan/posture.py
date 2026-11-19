"""Security posture: what is badly configured on this network.

This does not exploit anything. It grades what the scan already saw - open management
ports, admin pages on plain HTTP, the default SNMP community, CCTV and printer admin
interfaces - and it grades the console itself (TLS, allow-list, 2FA, heartbeat).

For a hotel the CCTV findings matter most: an NVR whose web page answers on port 80 with
the factory password is the single most common way a property ends up on the internet.
"""

from __future__ import annotations

HIGH, MEDIUM, LOW, INFO = "high", "medium", "low", "info"
WEIGHT = {HIGH: 10, MEDIUM: 5, LOW: 2, INFO: 0}

ADMIN_PORTS = {80, 81, 8080, 8000, 8001, 8081, 8888, 9000}
TLS_PORTS = {443, 8443}
CCTV_TYPES = {"dvr", "nvr", "camera"}


def _ports(device):
    return {p.get("port") for p in (device.get("ports") or []) if p.get("port")}


def check_device(device):
    """Findings for one discovered device."""
    out = []
    ports = _ports(device)
    name = device.get("label") or device.get("hostname") or device.get("ip")
    dev_type = device.get("type") or ""
    has_tls = bool(ports & TLS_PORTS)
    http_admin = sorted(ports & ADMIN_PORTS)

    def add(severity, rule, text, advice):
        out.append({"severity": severity, "rule": rule, "device": name,
                    "ip": device.get("ip"), "text": text, "advice": advice})

    if 23 in ports:
        add(HIGH, "telnet-open",
            f"{name} accepts Telnet (23) - passwords cross the network in clear text",
            "Turn Telnet off; use SSH. On switches, disable the Telnet server.")

    if http_admin and not has_tls:
        sev = HIGH if dev_type in CCTV_TYPES else MEDIUM
        add(sev, "admin-http-only",
            f"{name} serves its admin page over plain HTTP ({http_admin[0]}) with no HTTPS",
            "Enable HTTPS on the device, or keep its management interface on a separate "
            "VLAN that staff cannot reach.")

    if (device.get("snmp_community") or "").lower() == "public":
        add(MEDIUM, "snmp-default-community",
            f"{name} answers SNMP on the default community 'public' - anyone can read its "
            "configuration and port counters",
            "Change the community to a long random string, or move to SNMPv3 with auth+priv.")

    if dev_type in CCTV_TYPES and http_admin:
        add(HIGH, "cctv-admin-exposed",
            f"{name} is a recorder/camera with a web admin interface - the classic way a "
            "hotel's cameras end up on the internet",
            "Change the factory password, turn off UPnP/P2P cloud on the NVR, and never "
            "port-forward it. Reach it over VPN or Tailscale instead.")

    if 3389 in ports:
        add(MEDIUM, "rdp-open",
            f"{name} accepts Remote Desktop from the whole LAN",
            "Restrict RDP to an admin subnet or a VPN, and enable Network Level "
            "Authentication (enable_rdp.bat does this).")

    if 445 in ports and dev_type in ("server", "unknown"):
        add(LOW, "smb-open",
            f"{name} exposes SMB (445) - keep it patched, SMB is a favourite target",
            "Restrict file sharing to the subnets that need it.")

    if 21 in ports:
        add(LOW, "ftp-open",
            f"{name} runs FTP (21) - unencrypted file transfer",
            "Use SFTP/SCP instead, or restrict FTP to a management VLAN.")

    if dev_type in ("printer", "kot_printer") and 9100 in ports:
        add(INFO, "print-port-open",
            f"{name} accepts raw print jobs from any host on the LAN",
            "Acceptable inside a trusted VLAN; do not route it from guest Wi-Fi.")

    if dev_type in ("printer", "kot_printer") and http_admin and not has_tls:
        add(LOW, "printer-admin-http",
            f"{name} has an HTTP admin page - printer admin pages have been used to reach "
            "the rest of the network",
            "Set an admin password on the printer and keep it off the guest network.")
    return out


def self_check(cfg, tls_on=False, auth_on=False, two_factor_users=0, users=0):
    """Findings about the console itself."""
    out = []
    access = cfg.get("access") or {}
    tls_cfg = cfg.get("tls") or {}
    hb = cfg.get("heartbeat") or {}
    dash = cfg.get("dashboard") or {}

    def add(severity, rule, text, advice):
        out.append({"severity": severity, "rule": rule, "device": "this console",
                    "ip": "console", "text": text, "advice": advice})

    if not (tls_on or tls_cfg.get("enabled")):
        add(HIGH, "console-no-tls",
            "The console is served over plain HTTP - passwords and session cookies cross "
            "the network in clear text",
            "Run with --tls and a certificate from your PKI (or tailscale cert).")
    if not (access.get("allow_cidrs") or []):
        add(MEDIUM, "console-no-allowlist",
            "No IP allow-list is set - any address that can reach the port gets the login page",
            "Set --allow-cidr to your admin networks, or keep the console on the VPN only.")
    if not auth_on:
        add(MEDIUM, "console-no-auth",
            "Sign-in is off (localhost-only mode). That is fine on one PC, not on a shared one",
            "Start with --auth, or --lan which turns sign-in on automatically.")
    if users and not two_factor_users:
        add(MEDIUM, "console-no-2fa",
            "No account uses two-factor authentication",
            "Enrol your admin account (Users → 2FA) or switch to SSO.")
    if not hb.get("enabled"):
        add(LOW, "console-no-heartbeat",
            "No heartbeat is configured, so nobody is told when this whole site goes dark",
            "Set --heartbeat-url to a free healthchecks.io check.")
    if int(dash.get("port") or 8777) in (80, 8080):
        add(INFO, "console-common-port",
            f"The console listens on {dash.get('port')} - a port scanners look at first",
            "Keep it on a high port and put it behind the VPN or a reverse proxy.")
    return out


def snmp_version_finding(cfg):
    """Community-based SNMP is a finding when v3 is not in use."""
    v3 = cfg.get("snmp_v3") or {}
    if v3.get("enabled") and v3.get("user"):
        return []
    communities = ((cfg.get("monitoring") or {}).get("snmp_communities")
                   or (cfg.get("discovery") or {}).get("snmp_communities") or ["public"])
    if not communities:
        return []
    return [{"severity": MEDIUM, "rule": "snmp-v2c",
             "device": "this console", "ip": "console",
             "text": f"SNMP is polled with community '{communities[0]}' - the community "
                     "string crosses the network in clear text",
             "advice": "Enable SNMPv3 (Settings -> SNMPv3) with auth+priv; every modern "
                       "switch and AP supports it."}]


def summarise(devices, self_findings=None):
    """Grade the whole network plus the console."""
    findings = []
    for device in devices or []:
        try:
            findings.extend(check_device(device))
        except Exception:
            continue
    findings.extend(self_findings or [])
    counts = {HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    penalty = sum(WEIGHT.get(f["severity"], 0) for f in findings)
    import math as _math
    score = round(100 * _math.exp(-penalty / 80.0))   # soft curve: never a meaningless 0
    order = {HIGH: 0, MEDIUM: 1, LOW: 2, INFO: 3}
    findings.sort(key=lambda f: (order.get(f["severity"], 9), f.get("device") or ""))
    return {"score": score, "counts": counts, "findings": findings[:80],
            "total": len(findings)}
