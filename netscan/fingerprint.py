"""Turn raw scan evidence into a device type.

Scoring model: every piece of evidence adds points to one or more device types.
Highest score wins. Every verdict carries the evidence lines so the operator can
see *why* NetSentinel called something a KOT printer rather than a printer.
"""

from __future__ import annotations

TYPES = {
    "router": "Router / Firewall",
    "switch": "Network Switch",
    "access_point": "Access Point",
    "kot_printer": "KOT / Receipt Printer",
    "printer": "Printer",
    "scanner": "Scanner",
    "dvr": "DVR",
    "nvr": "NVR",
    "camera": "IP Camera",
    "server": "Server / PC",
    "nas": "NAS / Storage",
    "phone": "Phone / Tablet",
    "iot": "IoT / Other",
    "unknown": "Unknown device",
}

TYPE_ORDER = [
    "router", "switch", "access_point", "dvr", "nvr", "camera",
    "kot_printer", "printer", "scanner", "nas", "server", "phone", "iot", "unknown",
]

# port -> [(type, weight, reason)]
PORT_RULES = {
    9100: [("printer", 26, "RAW/JetDirect print port 9100 open"),
           ("kot_printer", 20, "RAW print port 9100 open (typical of POS thermal printers)")],
    515: [("printer", 20, "LPD print service on 515"),
          ("kot_printer", 14, "LPD on 515 (POS printers commonly expose it)")],
    631: [("printer", 20, "IPP print service on 631"),
          ("scanner", 8, "IPP/MFP on 631 (many MFPs also scan)")],
    37777: [("dvr", 50, "Dahua SDK port 37777"),
            ("nvr", 45, "Dahua SDK port 37777")],
    34567: [("dvr", 45, "DVR client port 34567"),
            ("nvr", 35, "DVR/NVR client port 34567")],
    6036: [("dvr", 30, "DVR media port 6036")],
    554: [("camera", 18, "RTSP video stream on 554"),
          ("nvr", 12, "RTSP on 554 (NVR/camera)"),
          ("dvr", 12, "RTSP on 554 (DVR/camera)")],
    8000: [("dvr", 26, "Hikvision SDK port 8000"),
           ("nvr", 26, "Hikvision SDK port 8000")],
    23: [("switch", 16, "Telnet management on 23"),
         ("access_point", 10, "Telnet management on 23"),
         ("router", 8, "Telnet management on 23")],
    22: [("server", 6, "SSH on 22"),
         ("access_point", 6, "SSH on 22"),
         ("switch", 6, "SSH on 22")],
    161: [("switch", 14, "SNMP agent on 161"),
          ("access_point", 12, "SNMP agent on 161"),
          ("printer", 8, "SNMP agent on 161")],
    5357: [("printer", 12, "WSD print/web services on 5357"),
           ("scanner", 12, "WSD device on 5357")],
    445: [("server", 8, "SMB file sharing on 445"),
          ("nas", 10, "SMB on 445")],
    3389: [("server", 6, "RDP on 3389")],
    53: [("router", 16, "DNS server on 53")],
    7547: [("router", 26, "TR-069 (ISP-managed CPE) on 7547")],
    1883: [("iot", 20, "MQTT broker on 1883")],
    3702: [("printer", 6, "WS-Discovery on 3702")],
}

# keyword -> [(type, weight, reason)]
KEYWORD_RULES = [
    # DVR / NVR
    ("hikvision", [("dvr", 34, "Hikvision identity in banner"), ("nvr", 30, "Hikvision identity")]),
    ("dahua", [("dvr", 34, "Dahua identity in banner"), ("nvr", 30, "Dahua identity")]),
    ("cp plus", [("dvr", 34, "CP Plus identity"), ("nvr", 28, "CP Plus identity")]),
    ("cpplus", [("dvr", 34, "CP Plus identity"), ("nvr", 28, "CP Plus identity")]),
    ("uniview", [("nvr", 30, "Uniview identity"), ("dvr", 26, "Uniview identity")]),
    ("xvr", [("dvr", 40, "XVR (hybrid DVR) identity")]),
    ("nvr", [("nvr", 40, "NVR named in banner")]),
    ("dvr", [("dvr", 40, "DVR named in banner")]),
    ("netSurveillance".lower(), [("dvr", 30, "NetSurveillance web UI (DVR)")]),
    ("network video recorder", [("nvr", 40, "banner says network video recorder")]),
    ("digital video recorder", [("dvr", 40, "banner says digital video recorder")]),
    # Cameras
    ("ipcam", [("camera", 30, "IP camera UI")]),
    ("ip camera", [("camera", 34, "IP camera UI")]),
    ("netwave", [("camera", 26, "Netwave camera firmware")]),
    ("onvif", [("camera", 18, "ONVIF camera service")]),
    # POS / KOT printers
    ("epson tm", [("kot_printer", 45, "Epson TM series receipt printer")]),
    ("tm-t", [("kot_printer", 34, "Epson TM-T thermal printer")]),
    ("tvs", [("kot_printer", 34, "TVS receipt printer")]),
    ("posiflex", [("kot_printer", 45, "Posiflex POS terminal/printer")]),
    ("bixolon", [("kot_printer", 45, "Bixolon receipt printer")]),
    ("star micronics", [("kot_printer", 45, "Star Micronics receipt printer")]),
    ("citizen", [("kot_printer", 30, "Citizen receipt printer")]),
    ("rongta", [("kot_printer", 40, "Rongta POS printer")]),
    ("xprinter", [("kot_printer", 40, "Xprinter POS printer")]),
    ("gprinter", [("kot_printer", 40, "Gprinter POS printer")]),
    ("thermal", [("kot_printer", 30, "thermal/receipt printer in banner")]),
    ("receipt printer", [("kot_printer", 45, "receipt printer in banner")]),
    ("kot", [("kot_printer", 26, "name/banner mentions KOT")]),
    ("kitchen", [("kot_printer", 18, "name/banner mentions kitchen")]),
    ("pos printer", [("kot_printer", 45, "POS printer in banner")]),
    # Printers
    ("laserjet", [("printer", 40, "HP LaserJet")]),
    ("officejet", [("printer", 40, "HP OfficeJet")]),
    ("deskjet", [("printer", 40, "HP DeskJet")]),
    ("designjet", [("printer", 40, "HP DesignJet")]),
    ("hewlett", [("printer", 26, "Hewlett-Packard device")]),
    ("brother", [("printer", 34, "Brother device")]),
    ("ricoh", [("printer", 34, "Ricoh device")]),
    ("kyocera", [("printer", 34, "Kyocera device")]),
    ("xerox", [("printer", 34, "Xerox device")]),
    ("lexmark", [("printer", 34, "Lexmark device")]),
    ("pantum", [("printer", 34, "Pantum device")]),
    ("konica", [("printer", 34, "Konica Minolta device")]),
    ("toshiba tec", [("printer", 30, "Toshiba printer")]),
    ("printer", [("printer", 26, "banner mentions printer")]),
    ("jetdirect", [("printer", 30, "HP JetDirect print server")]),
    ("print server", [("printer", 30, "print server in banner")]),
    ("mfp", [("printer", 18, "MFP (print/scan/copy)")]),
    # Scanners
    ("scanner", [("scanner", 34, "banner mentions scanner")]),
    ("scansnap", [("scanner", 45, "Fujitsu ScanSnap")]),
    ("canoscan", [("scanner", 45, "Canon scanner")]),
    ("epson scan", [("scanner", 40, "Epson scanner service")]),
    ("kodak alaris", [("scanner", 45, "Kodak Alaris scanner")]),
    # Access points
    ("unifi", [("access_point", 40, "Ubiquiti UniFi")]),
    ("airmax", [("access_point", 40, "Ubiquiti AirMax")]),
    ("airos", [("access_point", 40, "Ubiquiti AirOS")]),
    ("access point", [("access_point", 45, "banner says access point")]),
    ("accesspoint", [("access_point", 40, "banner says accesspoint")]),
    ("aironet", [("access_point", 40, "Cisco Aironet")]),
    ("aruba", [("access_point", 34, "Aruba device")]),
    ("ruckus", [("access_point", 34, "Ruckus device")]),
    ("omada", [("access_point", 30, "TP-Link Omada")]),
    ("eap", [("access_point", 14, "TP-Link EAP naming")]),
    ("wireless", [("access_point", 16, "wireless device in banner")]),
    ("cap-ac", [("access_point", 30, "TP-Link CAP AC")]),
    # Switches
    ("procurve", [("switch", 45, "HP ProCurve switch")]),
    ("catalyst", [("switch", 40, "Cisco Catalyst")]),
    ("edgeswitch", [("switch", 40, "Ubiquiti EdgeSwitch")]),
    ("unifi switch", [("switch", 40, "Ubiquiti UniFi switch")]),
    ("netgear", [("switch", 20, "Netgear device")]),
    ("dgs-", [("switch", 34, "D-Link DGS switch")]),
    ("des-", [("switch", 30, "D-Link DES switch")]),
    ("tl-sg", [("switch", 34, "TP-Link TL-SG switch")]),
    ("sg-", [("switch", 22, "switch model prefix")]),
    ("switch", [("switch", 40, "banner says switch")]),
    ("etherswitch", [("switch", 40, "banner says etherswitch")]),
    # Routers / gateways
    ("routeros", [("router", 45, "MikroTik RouterOS")]),
    ("mikrotik", [("router", 40, "MikroTik device")]),
    ("openwrt", [("router", 40, "OpenWrt firmware")]),
    ("dd-wrt", [("router", 40, "DD-WRT firmware")]),
    ("archer", [("router", 34, "TP-Link Archer")]),
    ("dir-", [("router", 30, "D-Link DIR router")]),
    ("router", [("router", 34, "banner says router")]),
    ("gateway", [("router", 26, "banner says gateway")]),
    ("ont", [("router", 20, "ONT/fibre modem")]),
    ("syrotech", [("router", 30, "Syrotech ONT")]),
    ("netlink", [("router", 26, "Netlink ONT")]),
    ("hg8245", [("router", 34, "Huawei HG8245 ONT")]),
    ("airtel", [("router", 30, "Airtel router")]),
    ("jio", [("router", 30, "Jio router")]),
    ("bsnl", [("router", 30, "BSNL router")]),
    ("firewall", [("router", 26, "firewall in banner")]),
    ("pfsense", [("router", 40, "pfSense firewall")]),
    ("fortigate", [("router", 34, "FortiGate firewall")]),
    ("sonicwall", [("router", 34, "SonicWall firewall")]),
    # Servers / NAS / phones / IoT
    ("synology", [("nas", 45, "Synology NAS")]),
    ("diskstation", [("nas", 45, "Synology DiskStation")]),
    ("qnap", [("nas", 45, "QNAP NAS")]),
    ("windows server", [("server", 34, "Windows Server")]),
    ("ubuntu", [("server", 8, "Linux host")]),
    ("debian", [("server", 8, "Linux host")]),
    ("android", [("phone", 26, "Android device")]),
    ("iphone", [("phone", 30, "iPhone")]),
    ("chromecast", [("iot", 30, "Chromecast")]),
    ("smart tv", [("iot", 30, "Smart TV")]),
    ("espressif", [("iot", 20, "ESP IoT module")]),
]

# MAC vendor -> [(type, weight, reason)]
VENDOR_RULES = {
    "Hikvision": [("dvr", 24, "Hikvision MAC vendor"), ("nvr", 20, "Hikvision MAC vendor")],
    "Dahua": [("dvr", 24, "Dahua MAC vendor"), ("nvr", 20, "Dahua MAC vendor")],
    "Epson": [("printer", 16, "Epson MAC vendor"), ("kot_printer", 12, "Epson MAC vendor (receipt printers)")],
    "Zebra": [("printer", 26, "Zebra MAC vendor")],
    "Brother": [("printer", 20, "Brother MAC vendor")],
    "Canon": [("printer", 18, "Canon MAC vendor"), ("scanner", 8, "Canon MAC vendor")],
    "HP": [("printer", 16, "HP MAC vendor")],
    "Ricoh": [("printer", 20, "Ricoh MAC vendor")],
    "Kyocera": [("printer", 20, "Kyocera MAC vendor")],
    "Xerox": [("printer", 20, "Xerox MAC vendor")],
    "Ubiquiti": [("access_point", 24, "Ubiquiti MAC vendor")],
    "Aruba": [("access_point", 20, "Aruba MAC vendor")],
    "Ruckus": [("access_point", 20, "Ruckus MAC vendor")],
    "MikroTik": [("router", 20, "MikroTik MAC vendor")],
    "Cisco": [("switch", 10, "Cisco MAC vendor"), ("access_point", 8, "Cisco MAC vendor")],
    "TP-Link": [("access_point", 6, "TP-Link MAC vendor"), ("router", 6, "TP-Link MAC vendor")],
    "Netgear": [("switch", 8, "Netgear MAC vendor")],
    "D-Link": [("switch", 6, "D-Link MAC vendor"), ("router", 4, "D-Link MAC vendor")],
    "Synology": [("nas", 26, "Synology MAC vendor")],
    "QNAP": [("nas", 26, "QNAP MAC vendor")],
    "Apple": [("phone", 8, "Apple MAC vendor")],
    "Samsung": [("phone", 6, "Samsung MAC vendor")],
    "Xiaomi": [("phone", 6, "Xiaomi MAC vendor")],
    "Espressif (IoT)": [("iot", 18, "ESP IoT module")],
}

INFRA_TYPES = {"router", "switch", "access_point"}


def classify(info: dict) -> dict:
    """Score the evidence and return {type, label, confidence, evidence}."""
    scores = {}
    evidence = {}
    kot_hard = False  # POS-specific evidence, not just an open print port

    def add(dev_type, weight, reason):
        if weight <= 0:
            return
        scores[dev_type] = scores.get(dev_type, 0) + weight
        evidence.setdefault(dev_type, [])
        if reason not in evidence[dev_type]:
            evidence[dev_type].append(reason)

    ports = set(info.get("ports") or [])
    for port in ports:
        for dev_type, weight, reason in PORT_RULES.get(port, []):
            add(dev_type, weight, reason)

    haystack_parts = []
    for h in info.get("http") or []:
        haystack_parts.append(h.get("title", ""))
        haystack_parts.append(h.get("server", ""))
        haystack_parts.append(h.get("location", ""))
    rtsp = info.get("rtsp") or {}
    haystack_parts.append(rtsp.get("server", ""))
    haystack_parts.append(info.get("snmp_descr") or "")
    haystack_parts.append(info.get("snmp_name") or "")
    haystack_parts.append(info.get("hostname") or "")
    haystack_parts.append(info.get("upnp_server") or "")   # UPnP SERVER header names the vendor/model
    haystack = " ".join(haystack_parts).lower()

    for keyword, rules in KEYWORD_RULES:
        if keyword and keyword in haystack:
            for dev_type, weight, reason in rules:
                add(dev_type, weight, reason)
                if dev_type == "kot_printer":
                    kot_hard = True

    vendor = info.get("vendor") or ""
    for key, rules in VENDOR_RULES.items():
        if key.lower() in vendor.lower():
            for dev_type, weight, reason in rules:
                add(dev_type, weight, reason)
                if dev_type == "kot_printer":
                    kot_hard = True

    if info.get("is_gateway"):
        add("router", 55, "this is the default gateway of the network")

    # A box with a print port that also looks like a POS printer is a KOT printer,
    # not a plain printer - nudge it so kitchens show up correctly.
    if "kot_printer" in scores and 9100 in ports:
        add("kot_printer", 10, "print port 9100 + POS/thermal evidence")

    # Video devices without a clear DVR/NVR verdict are probably cameras.
    if scores.get("camera", 0) and scores.get("dvr", 0) == 0 and scores.get("nvr", 0) == 0:
        if 554 in ports and (8000 in ports or 34567 in ports or 37777 in ports):
            add("nvr", 20, "multiple video ports open (recorder)")

    if not scores:
        dev_type = "unknown"
        label = TYPES[dev_type]
        confidence = "low"
        reasons = ["no identifying ports or banners answered"]
        if ports:
            reasons = ["open ports: " + ", ".join(str(p) for p in sorted(ports)[:8])]
        return {"type": dev_type, "label": label, "confidence": confidence, "evidence": reasons}

    # Infrastructure beats a printer when the box also claims switch ports
    best_type = max(
        scores.items(),
        key=lambda kv: (kv[1], -TYPE_ORDER.index(kv[0]) if kv[0] in TYPE_ORDER else -99),
    )[0]
    top = scores[best_type]
    runner = sorted(
        ((t, s) for t, s in scores.items() if t != best_type), key=lambda kv: -kv[1]
    )
    if runner and runner[0][1] >= top:
        # tie: prefer the earlier type in TYPE_ORDER (infrastructure first)
        for candidate in TYPE_ORDER:
            if scores.get(candidate, 0) >= top:
                best_type = candidate
                top = scores[candidate]
                break

    if top >= 60:
        confidence = "high"
    elif top >= 35:
        confidence = "medium"
    else:
        confidence = "low"

    label = TYPES.get(best_type, best_type)
    ambiguous = False

    # An open 9100 port alone does not make a box a KOT printer - it might be any
    # laser printer. Say "printer / possible KOT" and let the operator name it.
    if best_type == "kot_printer" and not kot_hard:
        best_type = "printer"
        label = "Printer / possible KOT"
        evidence["printer"] = list(evidence.get("kot_printer", [])) + [
            "only print-port evidence - name it if it is the kitchen printer"
        ]
        ambiguous = True
    # DVR and NVR look identical from the network side - say so instead of guessing.
    if best_type in ("dvr", "nvr"):
        other = "nvr" if best_type == "dvr" else "dvr"
        if scores.get(other, 0) >= 30 and abs(scores.get(other, 0) - top) <= 12:
            label = "DVR / NVR (recorder)"
            ambiguous = True

    reasons = list(evidence.get(best_type, []))[:6]
    if ambiguous:
        reasons.append("DVR vs NVR cannot be separated from the network - check the device label")

    return {
        "type": best_type,
        "label": label,
        "confidence": confidence,
        "evidence": reasons,
        "ambiguous": ambiguous,
        "score": top,
        "alternatives": [{"type": t, "score": s} for t, s in runner[:2]],
    }
