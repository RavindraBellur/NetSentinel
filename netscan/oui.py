"""MAC address to vendor lookup.

Two layers:
  1. a built-in table of prefixes commonly seen on Indian small/medium office
     and restaurant networks (best effort hints, not authoritative);
  2. an optional download of the official IEEE OUI registry, cached on disk and
     used when present (see `refresh_oui()`), which is authoritative.
"""

from __future__ import annotations

import csv
import io
import os
import urllib.request

# Best-effort hints. Format: "AABBCC": "Vendor"
_BUILTIN = {
    "00000C": "Cisco", "001B54": "Cisco", "001AA1": "Cisco", "F4CFE2": "Cisco",
    "000B86": "Aruba (HPE)", "6CF37F": "Aruba (HPE)", "24DEC6": "Aruba (HPE)", "84D47E": "Aruba (HPE)",
    "24C9A1": "Ruckus / CommScope", "2C5D93": "Ruckus / CommScope", "C4017C": "Ruckus / CommScope",
    "000C42": "MikroTik", "4C5E0C": "MikroTik", "2CC81B": "MikroTik", "6C3B6B": "MikroTik",
    "DC2C6E": "MikroTik", "744D28": "MikroTik", "18FD74": "MikroTik", "B869F4": "MikroTik",
    "50C7BF": "TP-Link", "14CC20": "TP-Link", "98DAC4": "TP-Link", "6032B1": "TP-Link",
    "002719": "TP-Link", "A42BB0": "TP-Link", "C46E1F": "TP-Link", "1027F5": "TP-Link",
    "F0F336": "TP-Link", "B4B024": "TP-Link", "1C61B4": "TP-Link", "AC84C6": "TP-Link",
    "00095B": "Netgear", "00146C": "Netgear", "A040A0": "Netgear", "2C3033": "Netgear",
    "000FB5": "Netgear", "20E52A": "Netgear", "9C3DCF": "Netgear",
    "00055D": "D-Link", "001B11": "D-Link", "1C7EE5": "D-Link", "14D64D": "D-Link",
    "78321B": "D-Link", "0022B0": "D-Link", "C8BE19": "D-Link", "3C1E04": "D-Link",
    "00E0FC": "Huawei", "4846FB": "Huawei", "70723C": "Huawei", "00259E": "Huawei",
    "8C34FD": "Huawei", "D4B709": "Huawei", "00E04C": "Realtek", "525400": "QEMU/VM",
    "4419B6": "Hikvision", "BCAD28": "Hikvision", "C056E3": "Hikvision", "4CBD8F": "Hikvision",
    "28D127": "Hikvision", "B4A382": "Hikvision", "9C8ECD": "Hikvision",
    "3CEF8C": "Dahua", "9002A9": "Dahua", "4C11BF": "Dahua", "E0508B": "Dahua",
    "001CE5": "Dahua", "D0431E": "Dahua", "B8871E": "Dahua",
    "000048": "Epson", "44D244": "Epson", "A4EE57": "Epson", "649EF3": "Epson",
    "001E0B": "HP", "3CD92B": "HP", "9CB654": "HP", "001B78": "HP", "3464A9": "HP",
    "008077": "Brother", "30055C": "Brother", "001BA9": "Brother", "803049": "Brother",
    "000085": "Canon", "2C9EFC": "Canon", "001E8F": "Canon", "889FFA": "Canon",
    "0000AA": "Xerox", "9C934E": "Xerox", "000074": "Ricoh", "002673": "Ricoh",
    "00C0EE": "Kyocera", "0021B7": "Kyocera", "00074D": "Zebra", "001570": "Zebra",
    "000393": "Apple", "3C15C2": "Apple", "F0766F": "Apple", "9C35EB": "Apple",
    "001B21": "Intel", "3C970E": "Intel", "A4C494": "Intel", "8C1645": "Intel",
    "0012FB": "Samsung", "8C7712": "Samsung", "B0DF3A": "Samsung",
    "64CC2E": "Xiaomi", "7811DC": "Xiaomi", "508F4C": "Xiaomi",
    "C83A35": "Tenda", "0495E6": "Tenda", "C46E1E": "Tenda",
    "001422": "Dell", "B82A72": "Dell", "18DBF2": "Dell",
    "240AC4": "Espressif (IoT)", "84F3EB": "Espressif (IoT)", "30AEA4": "Espressif (IoT)",
    "B827EB": "Raspberry Pi", "DCA632": "Raspberry Pi", "E45F01": "Raspberry Pi",
    "74C246": "Amazon", "F0272D": "Amazon", "0C47C9": "Amazon",
    "005056": "VMware", "000C29": "VMware", "080027": "VirtualBox",
}

_CACHE_DIR = os.path.join(os.path.expanduser("~"), ".netsentinel")
_CACHE_FILE = os.path.join(_CACHE_DIR, "oui.csv")
_registry = None
_registry_loaded = False


def _load_registry():
    global _registry, _registry_loaded
    if _registry_loaded:
        return _registry
    _registry_loaded = True
    _registry = {}
    try:
        if os.path.exists(_CACHE_FILE) and os.path.getsize(_CACHE_FILE) > 1000:
            with open(_CACHE_FILE, "r", encoding="utf-8", errors="ignore") as fh:
                for row in csv.reader(fh):
                    if len(row) >= 2 and len(row[0].strip()) == 6:
                        _registry[row[0].strip().upper()] = row[1].strip()
    except Exception:
        _registry = {}
    return _registry


def refresh_oui(timeout=60):
    """Download the IEEE OUI registry to the local cache. Returns (ok, message)."""
    url = "https://standards-oui.ieee.org/oui/oui.csv"
    try:
        os.makedirs(_CACHE_DIR, exist_ok=True)
        req = urllib.request.Request(url, headers={"User-Agent": "NetSentinel/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = r.read()
        if len(data) < 1000:
            return False, "download looked empty"
        with open(_CACHE_FILE, "wb") as fh:
            fh.write(data)
        global _registry_loaded
        _registry_loaded = False
        _load_registry()
        return True, f"{len(_registry)} vendors cached"
    except Exception as e:
        return False, str(e)[:200]


def vendor_for(mac: str) -> str:
    if not mac:
        return ""
    key = mac.replace(":", "").replace("-", "").upper()[:6]
    reg = _load_registry()
    if key in reg:
        return reg[key]
    if key in _BUILTIN:
        return _BUILTIN[key]
    # locally administered / randomised MAC
    try:
        if int(key[0:2], 16) & 0x02:
            return "Randomised MAC (private)"
    except Exception:
        pass
    return ""
