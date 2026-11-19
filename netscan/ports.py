"""Open-port exposure, and what to do about each one.

Every port the scanner finds is looked up here: what the service is, why an open port
matters, and the exact steps to close it on Windows, on Linux, on the router, or on the
device itself. The output is a hardening plan a technician can follow line by line.

Nothing here exploits anything: it is a catalogue plus the scan results.
"""

from __future__ import annotations

HIGH, MEDIUM, LOW, INFO = "high", "medium", "low", "info"

# port -> (service, risk, why it matters, how to close it, when it is legitimate)
CATALOGUE = {
    21: ("FTP", HIGH,
         "Usernames and passwords travel in clear text, and anonymous FTP is common on old "
         "NAS boxes and DVRs.",
         "Disable the FTP server: Windows -> 'Turn Windows features on or off' -> untick "
         "'Internet Information Services > FTP Server'. Router/NAS -> administration page -> "
         "FTP/SMB service -> off. Use SFTP or a file share instead.",
         "Almost never. Replace with SFTP/SCP."),
    22: ("SSH", INFO,
         "Encrypted remote shell - fine, but it is a login door and gets brute-forced.",
         "Keep it, but: key-only auth (PasswordAuthentication no), fail2ban, and limit it to "
         "an admin VLAN or the VPN.",
         "Yes - this is how you manage Linux devices."),
    23: ("Telnet", HIGH,
         "Every keystroke, including the admin password, is sent in clear text. Anyone on the "
         "guest Wi-Fi can capture it.",
         "On switches/APs: `no ip telnet server` (Cisco), `ip service disable telnet` "
         "(MikroTik /ip service disable telnet), or untick Telnet in the web UI (Aruba, "
         "TP-Link, D-Link). On Windows: 'Turn Windows features on or off' -> untick 'Telnet "
         "Server'. Use SSH instead.",
         "Never on a modern network."),
    25: ("SMTP", MEDIUM,
         "An open mail relay gets your public IP blacklisted and used to send spam.",
         "Disable the mail service on devices that do not send mail. If a printer needs SMTP, "
         "point it at your real mail server, not at a local relay.",
         "Only if you deliberately run a mail server."),
    53: ("DNS", LOW,
         "An open resolver can be used in DNS amplification attacks.",
         "On the router: enable 'DNS relay only', or restrict port 53 to the LAN subnets. "
         "Never port-forward 53 from the internet.",
         "Yes, on the domain controller or router only."),
    69: ("TFTP", MEDIUM,
         "No authentication at all - anyone can read or overwrite files, and it is how "
         "firmware and configs get stolen.",
         "Turn off the TFTP server after firmware upgrades: Windows -> stop the 'TFTP "
         "service'; Cisco -> `no tftp-server`; PBX/NVR -> disable in its settings.",
         "Only while actively loading firmware."),
    80: ("HTTP", LOW,
         "A web admin page with no encryption: session cookies and passwords are readable on "
         "the LAN, and on CCTV gear it is the classic way in.",
         "Enable HTTPS on the device and turn the HTTP listener off (most devices have "
         "'redirect HTTP to HTTPS'). If the device has no HTTPS, keep its admin page on a "
         "management VLAN that staff and guests cannot reach.",
         "Yes, if it redirects to HTTPS."),
    111: ("rpcbind", MEDIUM,
         "Reveals NFS mount points and has a history of amplification abuse.",
         "Linux: `systemctl disable --now rpcbind`. Only needed by NFS clients.",
         "Only with NFS in use."),
    135: ("MS RPC", MEDIUM,
         "Windows management endpoint; a favourite for lateral movement and exploit kits.",
         "Windows Firewall -> Advanced -> Inbound Rules -> block 'Remote WMI'/'RPC' from "
         "non-admin subnets. It cannot be switched off entirely on a domain member.",
         "Yes on Windows, restricted to admins."),
    139: ("NetBIOS", MEDIUM,
         "Legacy Windows file sharing, leaks host names and shares, and is not needed on a "
         "modern network.",
         "Network adapter -> IPv4 -> Advanced -> WINS -> 'Disable NetBIOS over TCP/IP'. Then "
         "block 137-139 inbound in Windows Firewall.",
         "Rarely - only for very old clients."),
    161: ("SNMP", MEDIUM,
         "v2c sends the community string in clear text; 'public' means anyone can read the "
         "whole configuration and rewrite it with 'private'.",
         "Switch to SNMPv3 with auth+priv (Prahari: Settings -> SNMPv3). If you must keep v2c, "
         "change the community to a long random string and allow only the monitoring host.",
         "Yes, for monitoring - over v3."),
    389: ("LDAP", LOW,
         "Directory queries; plain LDAP is unencrypted.",
         "Use LDAPS (636) or StartTLS, and restrict 389 to domain controllers.",
         "Yes, on the domain controller."),
    443: ("HTTPS", INFO,
         "Encrypted web admin - the good case.",
         "Keep it. Make sure the certificate is not expired and the device is not using a "
         "self-signed cert for remote access.",
         "Yes."),
    445: ("SMB", MEDIUM,
         "File sharing, and the service WannaCry and friends used. Never expose it to the "
         "internet.",
         "Windows: disable 'File and Printer Sharing' in the adapter's properties if the PC "
         "does not share files. Restrict 445 to the subnets that need it. Never port-forward "
         "445 on the router.",
         "Yes, on file servers only."),
    512: ("rexec", HIGH,
         "Remote execution with clear-text passwords, from 1980.",
         "Linux: comment out the `exec`/`login`/`shell` lines in /etc/inetd.conf and restart "
         "inetd; `systemctl disable --now rsh.socket`.",
         "Never."),
    513: ("rlogin", HIGH, "Clear-text remote login.", "As above: disable rsh/rlogin services.",
         "Never."),
    514: ("rsh / syslog", HIGH,
         "rsh runs commands without a password; the same port carries syslog.",
         "Disable rsh; for syslog, restrict the listener to your collector's IP.",
         "Only as a syslog receiver."),
    873: ("rsync", MEDIUM,
         "Unauthenticated rsync modules can leak entire directories.",
         "Set `auth users` and `secrets file` in rsyncd.conf, or run rsync over SSH only and "
         "close the daemon.",
         "Only over SSH."),
    1433: ("MS SQL", HIGH,
         "A database port open to the LAN is a direct path to guest and billing data.",
         "Bind SQL Server to localhost or the app subnet only (SQL Server Configuration "
         "Manager -> Protocols -> TCP/IP -> IP Addresses -> specific IPs). Block 1433 at the "
         "firewall for everything else.",
         "Only from the application server."),
    1521: ("Oracle", HIGH, "Same as MS SQL: direct database exposure.",
         "Restrict the listener (`listener.ora` HOST) and firewall 1521 to the app server.",
         "Only from the application server."),
    2049: ("NFS", HIGH,
         "Unencrypted, host-based authentication only, and a common ransomware target.",
         "Export only to named hosts in /etc/exports with `ro` where possible; use NFSv4 with "
         "Kerberos, or move to SMB with signing.",
         "Only inside a trusted server VLAN."),
    3306: ("MySQL", HIGH,
         "Database exposure. Default installs listen on all interfaces.",
         "`bind-address = 127.0.0.1` in my.cnf, restart, then firewall 3306.",
         "Only from the app server."),
    3389: ("RDP", HIGH,
         "The single most attacked Windows service. Ransomware crews scan for it constantly.",
         "Never port-forward it. Restrict it to an admin subnet, enable Network Level "
         "Authentication (Prahari: enable_rdp.bat does this), require MFA, and prefer VPN or "
         "Tailscale for remote access.",
         "Yes, but only behind VPN/MFA."),
    5432: ("PostgreSQL", HIGH, "Database exposure.",
         "`listen_addresses = 'localhost'` in postgresql.conf plus pg_hba.conf host rules, "
         "then firewall 5432.",
         "Only from the app server."),
    5900: ("VNC", HIGH,
         "Often has no password at all, and the ones that do are brute-forced in minutes.",
         "Disable the VNC server when not in use; if needed, tunnel it over SSH and set a "
         "strong password. macOS: System Settings -> Sharing -> Screen Sharing -> off.",
         "Rarely - prefer RDP/SSH tunnels."),
    6379: ("Redis", HIGH,
         "By default there is no authentication, and a reachable Redis is a common way to "
         "write a cron job and take the host.",
         "`bind 127.0.0.1` and `requirepass` in redis.conf, then firewall 6379.",
         "Only from the app server."),
    8080: ("HTTP alt", LOW,
         "A second web admin listener, often a camera/NVR or an app server.",
         "Identify it (`http://host:8080`) and either enable HTTPS or move it to a management "
         "VLAN.",
         "Sometimes - treat it like port 80."),
    8443: ("HTTPS alt", INFO, "Encrypted admin listener.", "Keep it; check the certificate.",
         "Yes."),
    9100: ("JetDirect print", LOW,
         "Anyone on the LAN can send print jobs, including a page of garbage that empties the "
         "toner.",
         "Restrict 9100 to the POS/KOT subnet at the switch ACL, or use IPP with "
         "authentication (631).",
         "Yes, inside a trusted VLAN."),
    9200: ("Elasticsearch", HIGH,
         "No authentication by default; a reachable node exposes every indexed document.",
         "`xpack.security.enabled: true`, bind to 127.0.0.1, firewall 9200.",
         "Only from the app server."),
    27017: ("MongoDB", HIGH,
         "Historically open by default; thousands of databases have been wiped this way.",
         "`bindIp: 127.0.0.1` and `security.authorization: enabled` in mongod.conf.",
         "Only from the app server."),
    5555: ("ADB / misc", MEDIUM,
         "Android debug bridge or a vendor service; ADB allows installing apps on the device.",
         "Turn off USB/network debugging on Android devices and set-top boxes; block 5555 at "
         "the firewall.",
         "Almost never."),
    7547: ("TR-069 CWMP", HIGH,
         "The ISP remote-management protocol that the Mirai botnet used to build its army.",
         "On the router: disable TR-069/CWMP remote management unless the ISP requires it; if "
         "required, restrict it to the ISP's management server.",
         "Only if the ISP insists."),
    8291: ("MikroTik Winbox", MEDIUM,
         "Full router administration; MikroTik devices are heavily targeted.",
         "/ip service disable winbox (use Winbox over MAC or SSH instead), and firewall 8291 "
         "to admin IPs.",
         "Only from an admin subnet."),
    554: ("RTSP", HIGH,
          "Video streaming. Many cameras and recorders accept an unauthenticated stream, so "
          "anyone on the network can watch.",
          "Require authentication on the stream (most cameras have 'anonymous RTSP' in their "
          "settings), and keep cameras on a separate VLAN from guest Wi-Fi.",
          "Yes, with authentication, inside a CCTV VLAN."),
    631: ("IPP printing", LOW,
          "Network printing with an admin surface that has had path-traversal bugs.",
          "Restrict to the POS/KOT subnet, and keep the printer firmware updated.",
          "Yes, inside a trusted VLAN."),
    137: ("NetBIOS name", MEDIUM,
          "Legacy Windows name service: leaks host names and workgroup structure.",
          "Adapter -> IPv4 -> Advanced -> WINS -> disable NetBIOS over TCP/IP.",
          "Rarely."),
    138: ("NetBIOS datagram", MEDIUM, "Legacy Windows browsing.",
          "Same as 137: disable NetBIOS over TCP/IP, then block 137-139.",
          "Rarely."),
    123: ("NTP", INFO,
          "Time sync. An open NTP server can be used in amplification attacks.",
          "Restrict to the LAN, or point devices at the router's NTP service only.",
          "Yes, on the router or domain controller."),
    587: ("SMTP submission", LOW, "Authenticated mail submission.",
          "Restrict to the mail server; devices that send mail should use it with credentials.",
          "Only on the mail server."),
    993: ("IMAPS", INFO, "Encrypted mail access.", "Keep it; restrict to the mail server.",
          "Yes, on the mail server."),
    995: ("POP3S", INFO, "Encrypted mail access.", "Keep it; restrict to the mail server.",
          "Yes, on the mail server."),
    8000: ("HTTP alt (DVR)", LOW,
          "Very common second web port on recorders and cameras - often the same admin page "
          "with no encryption.",
          "Enable HTTPS on the device and disable the extra listener, or keep it on a CCTV "
          "VLAN that staff and guests cannot reach.",
          "Only inside a CCTV VLAN."),
    8081: ("HTTP alt", LOW, "A second web listener, often a camera or app server.",
          "Identify it, enable HTTPS, or move it to a management VLAN.",
          "Sometimes - treat it like port 80."),
    8888: ("HTTP alt", LOW, "A third web listener; on DVRs this is frequently the admin UI.",
          "Identify it, enable HTTPS, restrict to a management VLAN.",
          "Sometimes."),
    9000: ("HTTP alt / SonarQube", LOW, "Web UI or a dev tool that should not be exposed.",
          "Identify it and either firewall it or move it off the flat network.",
          "Only if deliberately used."),
    1900: ("UPnP", HIGH,
          "UPnP lets any device on the LAN open ports on the router by itself - the classic way "
          "a camera ends up reachable from the internet.",
          "Router -> disable UPnP (NAT-PMP/UPnP) entirely. On cameras and NVRs turn off "
          "'P2P'/'cloud' access.",
          "Never on a business network."),
    5353: ("mDNS", INFO, "Local discovery (Bonjour/AirPlay).",
           "Harmless on the LAN; do not route it to the guest network unless you want AirPlay "
           "to work across it.", "Yes, on the LAN."),
    8728: ("MikroTik API", MEDIUM, "Scriptable full admin access.",
         "/ip service disable api; use api-ssl (8729) with certificates if you need it.",
         "Only from the management host."),
}

# extra risk by device type: the same port matters more on some kit
TYPE_MULTIPLIER = {"dvr": "high", "nvr": "high", "camera": "high", "printer": "low",
                   "kot_printer": "low", "router": "high", "firewall": "high"}


def describe(port, device_type=""):
    entry = CATALOGUE.get(int(port))
    if not entry:
        return {"port": int(port), "service": "unknown", "risk": LOW,
                "why": "Not in the catalogue - identify it before deciding.",
                "how": "Open the port in a browser or with `nc -v host port` to see what "
                       "answers, then either firewall it or document why it is needed.",
                "keep": "Unknown."}
    service, risk, why, how, keep = entry
    if device_type in ("dvr", "nvr", "camera") and risk in (LOW, INFO) and int(port) in (80, 8080, 8000):
        risk = HIGH
        why += (" On a recorder or camera this is the exact combination attackers look for.")
    return {"port": int(port), "service": service, "risk": risk, "why": why, "how": how,
            "keep": keep}


def exposure(devices):
    """Every open port on every device, with its hardening advice."""
    findings = []
    for dev in devices or []:
        protos = {}
        for p in dev.get("ports") or []:
            if p.get("port"):
                protos[p["port"]] = p.get("proto") or "tcp"
        for port in sorted(protos):
            info = describe(port, dev.get("type") or "")
            if port == 1900 and dev.get("upnp_server"):
                info["why"] += f" This device announces itself as: {dev['upnp_server']}."
            findings.append(dict(info, device=dev.get("label") or dev.get("hostname")
                                 or dev.get("ip"), ip=dev.get("ip"), proto=protos[port],
                                 type=dev.get("type") or ""))
    order = {HIGH: 0, MEDIUM: 1, LOW: 2, INFO: 3}
    findings.sort(key=lambda f: (order.get(f["risk"], 9), f["device"] or "", f["port"]))
    counts = {HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0}
    for f in findings:
        counts[f["risk"]] = counts.get(f["risk"], 0) + 1
    return {"findings": findings, "counts": counts, "total": len(findings)}


def plan(devices, limit=60):
    """An ordered, printable hardening plan grouped by device."""
    data = exposure(devices)
    by_device = {}
    for f in data["findings"]:
        if f["risk"] == INFO:
            continue
        by_device.setdefault(f["device"], {"ip": f["ip"], "type": f["type"], "items": []})
        by_device[f["device"]]["items"].append(f)
    lines = ["# Hardening plan", ""]
    if not by_device:
        lines.append("No risky open port was found.")
        return "\n".join(lines)
    lines.append(f"{len(by_device)} device(s) with ports worth closing. Work top to bottom; "
                 "each step says exactly what to switch off.")
    lines.append("")
    for name, block in list(by_device.items())[:limit]:
        lines.append(f"## {name}  ({block['ip']}{', ' + block['type'] if block['type'] else ''})")
        for item in block["items"]:
            lines.append(f"- **Port {item['port']} / {item['service']}** "
                         f"({item['risk']})")
            lines.append(f"  - Why: {item['why']}")
            lines.append(f"  - How: {item['how']}")
            lines.append(f"  - Keep it open only if: {item['keep']}")
        lines.append("")
    lines.append("After each change, rescan from the Devices page and confirm the port is gone.")
    return "\n".join(lines)
