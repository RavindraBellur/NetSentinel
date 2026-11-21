"""Server and system monitoring: CPU, memory, disks, uptime and load per host.

Two sources, no agent to install:

  * **This PC** - psutil when it is available, `/proc` on Linux, PowerShell on Windows.
  * **Other servers** - standard SNMP: the UCD-SNMP MIB (`ssCpuIdle`, `memTotalReal`,
    `dskTable`, `laLoad`) that `snmpd` exposes on Linux, and the HOST-RESOURCES MIB
    (`hrSystemUptime`, `hrProcessorLoad`, `hrStorage`) that Windows' SNMP service and most
    appliances expose. Nothing vendor-specific.

Thresholds come from Settings: CPU, memory and disk percentages, and how many consecutive
breaches raise an alert - one spike at backup time should not page anybody. A host that stays
over a limit is also an open problem for escalation (Settings -> Escalation).

Only devices the scan found answering SNMP (or with port 161 open) are polled, so a server
without SNMP costs nothing. Windows: Settings -> Apps -> Optional features -> SNMP, then allow
the Prahari PC and set a community in the SNMP Service's Security tab.
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
import time

from . import settings, store

IS_WINDOWS = os.name == "nt"

# ---- SNMP OIDs -------------------------------------------------------------
OID_SYS_UPTIME = "1.3.6.1.2.1.1.3.0"            # sysUpTime (hundredths)
OID_HR_UPTIME = "1.3.6.1.2.1.25.1.1.0"          # hrSystemUptime
OID_HR_LOAD = "1.3.6.1.2.1.25.3.3.1.2"          # hrProcessorLoad (per CPU)
OID_HR_STORAGE_TYPE = "1.3.6.1.2.1.25.2.3.1.2"  # hrStorageType
OID_HR_STORAGE_DESCR = "1.3.6.1.2.1.25.2.3.1.3" # hrStorageDescr
OID_HR_STORAGE_UNITS = "1.3.6.1.2.1.25.2.3.1.4"
OID_HR_STORAGE_SIZE = "1.3.6.1.2.1.25.2.3.1.5"
OID_HR_STORAGE_USED = "1.3.6.1.2.1.25.2.3.1.6"
HR_STORAGE_RAM = "1.3.6.1.2.1.25.2.1.2"
HR_STORAGE_FIXED = "1.3.6.1.2.1.25.2.1.4"
OID_UCD_CPU_IDLE = "1.3.6.1.4.1.2021.11.11.0"
OID_UCD_MEM_TOTAL = "1.3.6.1.4.1.2021.4.5.0"
OID_UCD_MEM_AVAIL = "1.3.6.1.4.1.2021.4.6.0"
OID_UCD_DSK_PATH = "1.3.6.1.4.1.2021.9.1.2"
OID_UCD_DSK_TOTAL = "1.3.6.1.4.1.2021.9.1.6"
OID_UCD_DSK_AVAIL = "1.3.6.1.4.1.2021.9.1.7"
OID_UCD_LOAD1 = "1.3.6.1.4.1.2021.10.1.3.1"


def _cfg():
    conf = settings.load().get("systems") or {}
    out = {"enabled": True, "cpu_warn": 90, "mem_warn": 90, "disk_warn": 90,
           "bad_polls": 3, "interval_seconds": 120, "snmp": True}
    out.update({k: v for k, v in conf.items() if v is not None})
    return out


# ---- this PC ---------------------------------------------------------------

def _proc_metrics():
    """Linux without psutil: /proc is enough for the four numbers that matter."""
    out = {}
    try:
        with open("/proc/loadavg") as fh:
            out["load"] = [float(x) for x in fh.read().split()[:3]]
    except OSError:
        pass
    try:
        with open("/proc/uptime") as fh:
            out["uptime_s"] = int(float(fh.read().split()[0]))
    except OSError:
        pass
    try:
        with open("/proc/meminfo") as fh:
            info = {}
            for line in fh:
                key, _, rest = line.partition(":")
                info[key] = float(rest.strip().split()[0]) / 1024.0     # MiB
        total = info.get("MemTotal") or 0
        avail = info.get("MemAvailable") or info.get("MemFree") or 0
        if total:
            out["mem_total_mb"] = round(total)
            out["mem_used_pct"] = round(100.0 * (total - avail) / total, 1)
    except OSError:
        pass
    try:
        with open("/proc/stat") as fh:
            parts = [float(x) for x in fh.readline().split()[1:]]
        idle, total = parts[3] + (parts[4] if len(parts) > 4 else 0), sum(parts)
        prev = _PROC_PREV.get("stat")
        _PROC_PREV["stat"] = (idle, total)
        if prev and total > prev[1]:
            out["cpu_pct"] = round(100.0 * (1 - (idle - prev[0]) / (total - prev[1])), 1)
    except (OSError, ValueError):
        pass
    try:
        disks = []
        candidates = [m for m in ("/", "/var", "/home") if os.path.ismount(m)] or ["/"]
        for mount in candidates:
            usage = shutil.disk_usage(mount)
            disks.append({"mount": mount, "total_gb": round(usage.total / 1e9, 1),
                          "used_pct": round(100.0 * usage.used / usage.total, 1)})
        out["disks"] = disks
    except OSError:
        pass
    return out


_PROC_PREV = {}


def _psutil_metrics():
    try:
        import psutil
    except Exception:
        return {}
    out = {}
    try:
        out["cpu_pct"] = psutil.cpu_percent(interval=0.3)
        mem = psutil.virtual_memory()
        out["mem_total_mb"] = round(mem.total / 1048576)
        out["mem_used_pct"] = mem.percent
        out["uptime_s"] = int(time.time() - psutil.boot_time())
        out["load"] = list(os.getloadavg()) if hasattr(os, "getloadavg") else []
        disks = []
        for part in psutil.disk_partitions(all=False):
            try:
                usage = psutil.disk_usage(part.mountpoint)
            except Exception:
                continue
            disks.append({"mount": part.mountpoint, "total_gb": round(usage.total / 1e9, 1),
                          "used_pct": round(usage.percent, 1)})
        out["disks"] = disks[:6]
    except Exception:
        return {}
    return out


def _windows_metrics():
    """PowerShell, because it ships with Windows and needs nothing installed."""
    script = (
        "$cpu=(Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage "
        "-Average).Average;"
        "$os=Get-CimInstance Win32_OperatingSystem;"
        "$mem=100-($os.FreePhysicalMemory/$os.TotalVisibleMemorySize*100);"
        "$up=(Get-Date)-$os.LastBootUpTime;"
        "$d=Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object {"
        "'{0}|{1}|{2}' -f $_.DeviceID, [math]::Round($_.Size/1GB,1),"
        "[math]::Round(100*($_.Size-$_.FreeSpace)/$_.Size,1)};"
        "Write-Output ('CPU='+[math]::Round($cpu,1));"
        "Write-Output ('MEM='+[math]::Round($mem,1));"
        "Write-Output ('UP='+[int]$up.TotalSeconds);"
        "$d | ForEach-Object { Write-Output ('DISK='+$_) }"
    )
    try:
        proc = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                              capture_output=True, text=True, timeout=25,
                              creationflags=0x08000000 if IS_WINDOWS else 0)
    except Exception:
        return {}
    out = {"disks": []}
    for line in (proc.stdout or "").splitlines():
        line = line.strip()
        if line.startswith("CPU="):
            out["cpu_pct"] = float(line[4:] or 0)
        elif line.startswith("MEM="):
            out["mem_used_pct"] = float(line[4:] or 0)
        elif line.startswith("UP="):
            out["uptime_s"] = int(float(line[3:] or 0))
        elif line.startswith("DISK="):
            parts = line[5:].split("|")
            if len(parts) == 3:
                out["disks"].append({"mount": parts[0], "total_gb": float(parts[1] or 0),
                                     "used_pct": float(parts[2] or 0)})
    return out


def local():
    """Metrics for the machine running this console."""
    metrics = _psutil_metrics()
    fallback = _windows_metrics() if IS_WINDOWS else _proc_metrics()
    if not metrics:
        metrics = fallback
    else:
        # psutil can miss filesystems (containers, unusual mounts): fill the gaps
        for key, value in fallback.items():
            if key not in metrics or metrics.get(key) in (None, [], 0):
                metrics[key] = value
    metrics["host"] = platform.node() or "this-pc"
    metrics["os"] = f"{platform.system()} {platform.release()}"
    metrics["role"] = "console"
    metrics["source"] = "local"
    metrics["ts"] = int(time.time())
    return metrics


# ---- other servers over SNMP ----------------------------------------------

def _num(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def snmp_host(host, community=None):
    """CPU, memory, disks and uptime of a server over standard SNMP.

    Linux snmpd answers UCD-SNMP; Windows' SNMP service and most appliances answer only
    HOST-RESOURCES. Both are tried, and whatever one leaves empty the other fills."""
    from . import discovery, snmp
    communities = [community] if community else discovery.snmp_communities()[:4]
    for candidate in communities:
        rows = snmp.get(host, [OID_SYS_UPTIME, OID_HR_UPTIME, OID_UCD_CPU_IDLE, OID_UCD_MEM_TOTAL,
                               OID_UCD_MEM_AVAIL, OID_UCD_LOAD1],
                        candidate, timeout=1.5, retries=0)
        if not rows:
            continue
        values = {oid: value for oid, tag, value in rows if tag not in (0x80, 0x81, 0x82)}
        out = {"host": host, "source": "snmp", "ts": int(time.time()), "role": "server"}
        idle = _num(values.get(OID_UCD_CPU_IDLE))
        if idle is not None:
            out["cpu_pct"] = round(max(0.0, 100.0 - idle), 1)
        total = _num(values.get(OID_UCD_MEM_TOTAL))
        avail = _num(values.get(OID_UCD_MEM_AVAIL))
        if total and avail is not None:
            out["mem_total_mb"] = int(total / 1024)
            out["mem_used_pct"] = round(100.0 * (total - avail) / total, 1)
        for key in (OID_HR_UPTIME, OID_SYS_UPTIME):
            ticks = _num(values.get(key))
            if ticks:
                out["uptime_s"] = int(ticks / 100.0)
                break
        load1 = _num(values.get(OID_UCD_LOAD1))
        if load1 is not None:
            out["load"] = [load1]
        if "cpu_pct" not in out:
            loads = [_num(v) for _o, _t, v in
                     (snmp.walk(host, OID_HR_LOAD, candidate, timeout=1.2, max_rows=128) or [])]
            loads = [x for x in loads if x is not None]
            if loads:
                out["cpu_pct"] = round(sum(loads) / len(loads), 1)
        storage = _hr_storage(host, candidate)
        if "mem_used_pct" not in out and storage.get("ram"):
            out.update(storage["ram"])
        out["disks"] = _ucd_disks(host, candidate) or storage.get("disks") or []
        return out
    return {}


def _ucd_disks(host, community):
    from . import snmp
    paths = snmp.walk(host, OID_UCD_DSK_PATH, community, timeout=1.2, max_rows=24) or []
    total = snmp.walk(host, OID_UCD_DSK_TOTAL, community, timeout=1.2, max_rows=24) or []
    avail = snmp.walk(host, OID_UCD_DSK_AVAIL, community, timeout=1.2, max_rows=24) or []
    totals = {oid.rsplit(".", 1)[-1]: _num(v) for oid, _t, v in total}
    frees = {oid.rsplit(".", 1)[-1]: _num(v) for oid, _t, v in avail}
    disks = []
    for oid, _t, value in paths:
        index = oid.rsplit(".", 1)[-1]
        size, free = totals.get(index), frees.get(index)
        if not size or free is None:
            continue
        disks.append({"mount": str(value)[:24], "total_gb": round(size / 1048576, 1),
                      "used_pct": round(100.0 * (size - free) / size, 1)})
    return disks[:8]


def hr_rows(descrs, types, units, sizes, used):
    """HOST-RESOURCES storage rows -> {"ram": {...}, "disks": [...]} (pure; tested)."""
    idx = lambda rows: {oid.rsplit(".", 1)[-1]: v for oid, _t, v in rows}
    kind, unit, size, use = idx(types), idx(units), idx(sizes), idx(used)
    out = {"ram": None, "disks": []}
    for oid, _t, label in descrs:
        i = oid.rsplit(".", 1)[-1]
        total, taken, block = _num(size.get(i)), _num(use.get(i)), _num(unit.get(i)) or 1
        if not total or taken is None:
            continue
        pct = round(100.0 * taken / total, 1)
        if str(kind.get(i)) == HR_STORAGE_RAM and out["ram"] is None:
            out["ram"] = {"mem_total_mb": int(total * block / 1048576), "mem_used_pct": pct}
        elif str(kind.get(i)) == HR_STORAGE_FIXED and len(out["disks"]) < 8:
            out["disks"].append({"mount": str(label)[:24],
                                 "total_gb": round(total * block / 1e9, 1), "used_pct": pct})
    return out


def _hr_storage(host, community):
    from . import snmp
    walk = lambda oid: snmp.walk(host, oid, community, timeout=1.2, max_rows=40) or []
    descrs = walk(OID_HR_STORAGE_DESCR)
    if not descrs:
        return {}
    return hr_rows(descrs, walk(OID_HR_STORAGE_TYPE), walk(OID_HR_STORAGE_UNITS),
                   walk(OID_HR_STORAGE_SIZE), walk(OID_HR_STORAGE_USED))


def collect(devices, log=None):
    """Poll every server-ish device over SNMP, plus this PC. Returns a list of host rows."""
    conf = _cfg()
    if not conf.get("enabled", True):
        return []
    rows = [local()]
    if conf.get("snmp", True):
        for device in devices or []:
            if (device.get("type") or "") not in ("server", "nas"):
                continue
            host = device.get("ip")
            if not host or device.get("is_self"):
                continue
            ports = device.get("ports") or []
            ports = {p.get("port") if isinstance(p, dict) else p for p in ports}
            if not device.get("snmp_community") and 161 not in ports:
                continue                    # no sign of SNMP: do not spend seconds timing out
            try:
                metrics = snmp_host(host, device.get("snmp_community") or None)
            except Exception as exc:
                if log:
                    log(f"systems: {host}: {exc}")
                continue
            if metrics:
                metrics["label"] = device.get("label") or device.get("hostname") or host
                metrics["type"] = device.get("type_label") or device.get("type")
                rows.append(metrics)
    return rows


def evaluate(rows, log=None, notify=None, now=None):
    """Count breaches per host; after `bad_polls` in a row raise an alert once, and say when it
    is over. Returns the hosts that are over a limit right now (an open problem)."""
    conf = _cfg()
    now = now or time.time()
    bad_polls = max(1, int(conf.get("bad_polls") or 3))
    open_now = []
    for row in rows:
        host = row.get("host")
        name = row.get("label") or host
        worst_disk = max([d.get("used_pct") or 0 for d in row.get("disks") or []] or [0])
        breaches = []
        if (row.get("cpu_pct") or 0) >= float(conf["cpu_warn"]):
            breaches.append(f"CPU {row['cpu_pct']}%")
        if (row.get("mem_used_pct") or 0) >= float(conf["mem_warn"]):
            breaches.append(f"memory {row['mem_used_pct']}%")
        if worst_disk >= float(conf["disk_warn"]):
            breaches.append(f"disk {worst_disk}% full")
        state = _STATE.setdefault(host, {"count": 0, "open": False, "since": 0})
        if breaches:
            state["count"] += 1
            state["text"] = f"{name}: " + ", ".join(breaches)
            if state["count"] >= bad_polls and not state["open"]:
                state.update(open=True, since=int(now))
                store.add_event("systems", "high", state["text"])
                if log:
                    log(state["text"])
                if notify:
                    notify(host, name, state["text"], True)
        elif state["open"]:
            state.update(count=0, open=False)
            store.add_event("systems", "info", f"{name}: back under the limits")
            if notify:
                notify(host, name, f"{name} is back under the limits", False)
        else:
            state["count"] = 0
        row["over"] = breaches
        if state["open"]:
            item = state.setdefault("item", {})
            item.update(host=host, name=name, text=state["text"], since=state["since"])
            item.setdefault("paged", [])
            open_now.append(item)
        else:
            state.pop("item", None)
    return open_now


_STATE = {}


def status(rows=None):
    conf = _cfg()
    rows = rows or []
    return {"enabled": bool(conf.get("enabled", True)),
            "hosts": len(rows),
            "thresholds": {"cpu": conf["cpu_warn"], "memory": conf["mem_warn"],
                           "disk": conf["disk_warn"]},
            "interval": conf.get("interval_seconds") or 120, "bad_polls": conf.get("bad_polls") or 3,
            "note": ("this PC plus any server answering SNMP" if conf.get("snmp", True)
                     else "this PC only")}
