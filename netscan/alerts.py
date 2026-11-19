"""Alert delivery: email (SMTP) and a generic webhook (Slack/Teams/anything JSON).

Nothing is sent unless the operator turns it on and fills in the server details.
Failed sends are logged as events, never retried in a loop.
"""

from __future__ import annotations

import json
import smtplib
import ssl
import threading
import urllib.request
from email.message import EmailMessage

from . import diagnose, push, store

_send_lock = threading.Lock()


def _severity_ok(severity, minimum):
    return diagnose.at_least(severity, minimum or "medium")


def _email_ready(cfg):
    e = cfg.get("email") or {}
    return bool(e.get("enabled") and e.get("host") and (e.get("to") or []))


def _recipients(cfg):
    to = (cfg.get("email") or {}).get("to") or []
    if isinstance(to, str):
        to = [x.strip() for x in to.replace(";", ",").split(",") if x.strip()]
    return to


def _queue_email(subject, body, to):
    try:
        store.queue_alert("email", {"subject": subject, "body": body, "to": list(to or [])})
        return True
    except Exception:
        return False


def flush(cfg, log=None):
    """Send anything that was queued while the internet was down."""
    sent = failed = 0
    for item in store.pending_alerts():
        payload = item.get("payload") or {}
        try:
            if item["kind"] == "email":
                subject = payload.get("subject", "(queued alert)")
                body = payload.get("body", "")
                when = item.get("ts")
                import time as _time
                stamp = _time.strftime("%d/%m/%Y %H:%M", _time.localtime(when)) if when else "earlier"
                ok, msg = send_email(
                    cfg, subject.replace("[NetSentinel]", "[NetSentinel] (delayed)"),
                    f"{body}\n\n--\nThis alert was raised at {stamp} but could not be sent "
                    f"then (no internet at the site). It is being delivered now.",
                    to=payload.get("to") or None)
            elif item["kind"] == "webhook":
                ok, msg = send_webhook(cfg, payload)
            else:
                ok, msg = True, "unknown kind dropped"
        except Exception as exc:
            ok, msg = False, f"{exc.__class__.__name__}: {exc}"
        if ok:
            store.drop_alert(item["id"])
            sent += 1
        else:
            store.note_alert_failure(item["id"], msg)
            failed += 1
            if (item.get("attempts") or 0) > 200:
                store.drop_alert(item["id"])
    if log and (sent or failed):
        log(f"outbox: {sent} delivered late, {failed} still waiting")
    return {"sent": sent, "failed": failed}


def send_email(cfg, subject, body, to=None):
    """Send one email. `to` overrides the configured recipient list (per-site routing)."""
    e = cfg.get("email") or {}
    recipients = [x.strip() for x in (to or []) if x and "@" in x] or _recipients(cfg)
    if not (e.get("enabled") and e.get("host") and recipients):
        return False, "email is not configured"
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = e.get("from") or e.get("username") or "netsentinel@localhost"
    msg["To"] = ", ".join(recipients)
    msg.set_content(body)
    host = e.get("host")
    port = int(e.get("port") or 465)
    timeout = 20
    try:
        if e.get("ssl", True) and port != 587:
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(host, port, timeout=timeout, context=context) as smtp:
                if e.get("username"):
                    smtp.login(e["username"], e.get("password") or "")
                smtp.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=timeout) as smtp:
                smtp.ehlo()
                if e.get("starttls"):
                    smtp.starttls(context=ssl.create_default_context())
                    smtp.ehlo()
                if e.get("username"):
                    smtp.login(e["username"], e.get("password") or "")
                smtp.send_message(msg)
        return True, "sent"
    except Exception as exc:
        queued = _queue_email(subject, body, recipients)
        return False, (f"{exc.__class__.__name__}: {exc}"
                       + (" - queued for delivery when the link is back" if queued else ""))


def send_webhook(cfg, payload):
    w = cfg.get("webhook") or {}
    if not (w.get("enabled") and w.get("url")):
        return False, "webhook is not configured"
    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            w["url"], data=data,
            headers={"Content-Type": "application/json", "User-Agent": "NetSentinel/1.3"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            return 200 <= resp.status < 300, f"HTTP {resp.status}"
    except Exception as exc:
        queued = _queue_email(subject, body, recipients)
        return False, (f"{exc.__class__.__name__}: {exc}"
                       + (" - queued for delivery when the link is back" if queued else ""))


CEF_SEV = {"info": 1, "low": 3, "medium": 5, "high": 8, "critical": 10}
VERSION = "1.7"


def _cef_escape(text):
    return (str(text or "").replace("\\", "\\\\").replace("|", "\\|")
            .replace("\n", " ").replace("\r", " ")[:1000])


def format_cef(inc):
    """ArcSight CEF line, which Splunk/QRadar/Sentinel all understand."""
    d = inc.get("diagnosis") or {}
    sev = inc.get("severity", "medium")
    name = _cef_escape(inc.get("title", "incident"))
    ext = (
        f"dvchost={_cef_escape(inc.get('device_name', ''))} "
        f"src={_cef_escape(inc.get('device_ip', ''))} "
        f"cs1Label=RootCause cs1={_cef_escape(d.get('root_cause', ''))} "
        f"cs2Label=Category cs2={_cef_escape(d.get('category_label', ''))} "
        f"cs3Label=State cs3={_cef_escape(inc.get('state', ''))} "
        f"cn1Label=Confidence cn1={d.get('confidence', 0)} "
        f"msg={_cef_escape(inc.get('device_name', '') + ' ' + inc.get('state', ''))}"
    )
    return (f"CEF:0|NetSentinel|NetSentinel|{VERSION}|{_cef_escape(sev)}|{name}|"
            f"{CEF_SEV.get(sev, 5)}|{ext}")


def format_rfc5424(inc, facility=13):
    """Plain RFC 5424 syslog line for a collector that does not want CEF."""
    sev_map = {"critical": 2, "high": 3, "medium": 4, "low": 5, "info": 6}
    pri = facility * 8 + sev_map.get(inc.get("severity"), 4)
    import socket as _socket
    import time as _time
    host = _socket.gethostname()
    stamp = _time.strftime("%Y-%m-%dT%H:%M:%S.000Z", _time.gmtime())
    msg = (f"severity={inc.get('severity')} state={inc.get('state')} "
           f"device={inc.get('device_name')} ip={inc.get('device_ip')} "
           f"title={inc.get('title')}")
    return f"<{pri}>1 {stamp} {host} netsentinel - - - {msg[:900]}"


def send_syslog(cfg, line):
    """Send one line to the SIEM over UDP or TCP."""
    siem = cfg.get("siem") or {}
    host = siem.get("host")
    port = int(siem.get("port") or 514)
    if not (siem.get("enabled") and host):
        return False, "SIEM forwarding is not configured"
    data = (line.rstrip("\n") + "\n").encode("utf-8", "replace")
    try:
        import socket
        if (siem.get("proto") or "udp").lower() == "tcp":
            with socket.create_connection((host, port), timeout=8) as sock:
                sock.sendall(data)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.sendto(data, (host, port))
            finally:
                sock.close()
        return True, f"{siem.get('format', 'cef')} -> {host}:{port}/{(siem.get('proto') or 'udp').lower()}"
    except Exception as exc:
        queued = _queue_email(subject, body, recipients)
        return False, (f"{exc.__class__.__name__}: {exc}"
                       + (" - queued for delivery when the link is back" if queued else ""))


def _post_json(url, payload, timeout=12):
    import urllib.request
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return 200 <= resp.status < 300, f"HTTP {resp.status}"


def send_slack(cfg, inc, text):
    slack = cfg.get("slack") or {}
    if not (slack.get("enabled") and slack.get("webhook_url")):
        return False, "Slack is not configured"
    d = inc.get("diagnosis") or {}
    colour = {"critical": "#d9534f", "high": "#e0a02c", "medium": "#d8b23a",
              "low": "#3d8bfd", "info": "#8899ab"}.get(inc.get("severity"), "#8899ab")
    blocks = [
        {"type": "header", "text": {"type": "plain_text",
                                    "text": f"{inc.get('severity', '').upper()}: {inc.get('title', '')}"[:150]}},
        {"type": "section", "fields": [
            {"type": "mrkdwn", "text": f"*Device*\n{inc.get('device_name', '')} ({inc.get('device_ip', '')})"},
            {"type": "mrkdwn", "text": f"*State*\n{inc.get('state', '')}"},
            {"type": "mrkdwn", "text": f"*Root cause*\n{(d.get('root_cause') or 'n/a')[:200]}"},
            {"type": "mrkdwn", "text": f"*Confidence*\n{d.get('confidence', 0)}%"},
        ]},
    ]
    actions = d.get("recommended_actions") or []
    if actions:
        blocks.append({"type": "section", "text": {"type": "mrkdwn",
            "text": "*Do this*\n" + "\n".join(f"{i+1}. {a}" for i, a in enumerate(actions[:4]))}})
    blocks.append({"type": "context", "elements": [{"type": "mrkdwn",
        "text": f"NetSentinel · {cfg.get('site_name') or 'site'} · {text[:120]}"}]})
    try:
        ok, msg = _post_json(slack["webhook_url"],
                             {"text": f"{inc.get('title')} - {inc.get('device_name')}",
                              "attachments": [{"color": colour, "blocks": blocks}]})
        return ok, msg
    except Exception as exc:
        queued = _queue_email(subject, body, recipients)
        return False, (f"{exc.__class__.__name__}: {exc}"
                       + (" - queued for delivery when the link is back" if queued else ""))


def send_teams(cfg, inc, text):
    teams = cfg.get("teams") or {}
    if not (teams.get("enabled") and teams.get("webhook_url")):
        return False, "Teams is not configured"
    d = inc.get("diagnosis") or {}
    colour = {"critical": "d9534f", "high": "e0a02c", "medium": "d8b23a",
              "low": "3d8bfd", "info": "8899ab"}.get(inc.get("severity"), "8899ab")
    facts = [
        {"name": "Device", "value": f"{inc.get('device_name', '')} ({inc.get('device_ip', '')})"},
        {"name": "State", "value": str(inc.get("state", ""))},
        {"name": "Root cause", "value": (d.get("root_cause") or "n/a")[:300]},
        {"name": "Confidence", "value": f"{d.get('confidence', 0)}%"},
    ]
    for i, action in enumerate((d.get("recommended_actions") or [])[:3], 1):
        facts.append({"name": f"Step {i}", "value": action[:250]})
    card = {
        "@type": "MessageCard", "@context": "https://schema.org/extensions",
        "themeColor": colour,
        "summary": inc.get("title", "NetSentinel incident"),
        "title": f"{inc.get('severity', '').upper()}: {inc.get('title', '')}",
        "sections": [{"activityTitle": cfg.get("site_name") or "NetSentinel",
                      "activitySubtitle": text[:160], "facts": facts, "markdown": True}],
    }
    try:
        ok, msg = _post_json(teams["webhook_url"], card)
        return ok, msg
    except Exception as exc:
        queued = _queue_email(subject, body, recipients)
        return False, (f"{exc.__class__.__name__}: {exc}"
                       + (" - queued for delivery when the link is back" if queued else ""))


def incident_text(inc):
    d = inc.get("diagnosis") or {}
    lines = [
        f"{inc.get('severity', 'medium').upper()}  {inc.get('title', '')}",
        f"Device : {inc.get('device_name', '')} ({inc.get('device_ip', '')})",
        f"State  : {inc.get('state', '')}",
        f"Opened : {inc.get('opened_human', '')}",
        "",
        "Root cause:",
        "  " + (d.get("root_cause") or "n/a"),
        f"  confidence {d.get('confidence', 0)}%  ({d.get('category_label', '')})",
        "",
    ]
    if d.get("evidence"):
        lines.append("Evidence:")
        lines += ["  - " + e for e in d["evidence"][:6]]
        lines.append("")
    if d.get("recommended_actions"):
        lines.append("Do this:")
        lines += [f"  {i + 1}. {a}" for i, a in enumerate(d["recommended_actions"][:6])]
        lines.append("")
    if d.get("user_impact"):
        lines += ["Impact:", "  " + d["user_impact"], ""]
    if d.get("data_gaps"):
        lines += ["Data that would raise confidence:"]
        lines += ["  - " + g for g in d["data_gaps"][:4]]
        lines.append("")
    lines.append("-- NetSentinel")
    return "\n".join(lines)


def notify_incident(cfg, inc, log=None):
    """Send one incident notification through every configured channel."""
    severity = inc.get("severity", "medium")
    state = inc.get("state", "open")
    prefix = {"open": "OPEN", "escalated": "ESCALATED", "resolved": "RESOLVED"}.get(state, state.upper())
    subject = f"[NetSentinel] {prefix} {severity.upper()}: {inc.get('title', '')}"
    body = incident_text(inc)
    results = {}
    with _send_lock:
        e = cfg.get("email") or {}
        if _email_ready(cfg) and _severity_ok(severity, e.get("min_severity")):
            ok, msg = send_email(cfg, subject, body)
            results["email"] = msg
            if log:
                log(f"alert email {'sent' if ok else 'failed'}: {msg}")
        w = cfg.get("webhook") or {}
        if w.get("enabled") and _severity_ok(severity, w.get("min_severity")):
            payload = {
                "text": f"{prefix} {severity.upper()}: {inc.get('title')}\n{body}",
                "severity": severity,
                "state": state,
                "device": inc.get("device_name"),
                "ip": inc.get("device_ip"),
                "root_cause": (inc.get("diagnosis") or {}).get("root_cause"),
                "confidence": (inc.get("diagnosis") or {}).get("confidence"),
                "site": cfg.get("site_name") or "",
            }
            ok, msg = send_webhook(cfg, payload)
            results["webhook"] = msg
            if log:
                log(f"alert webhook {'sent' if ok else 'failed'}: {msg}")

        siem = cfg.get("siem") or {}
        if siem.get("enabled") and _severity_ok(severity, siem.get("min_severity")):
            line = (format_rfc5424(inc, int(siem.get("facility") or 13))
                    if (siem.get("format") or "cef").lower() == "rfc5424"
                    else format_cef(inc))
            ok, msg = send_syslog(cfg, line)
            results["siem"] = msg
            if log:
                log(f"SIEM forward {'sent' if ok else 'failed'}: {msg}")

        pcfg = cfg.get("push") or {}
        if pcfg.get("enabled") and _severity_ok(severity, pcfg.get("min_severity")):
            title = f"{severity.upper()}: {inc.get('title', 'incident')}"
            body = (f"{inc.get('device_name', '')} ({inc.get('device_ip', '')})\n"
                    f"{(inc.get('diagnosis') or {}).get('root_cause', '')[:300]}")
            ok, msg = push.send(cfg, title, body, severity)
            results["push"] = msg
            if log:
                log(f"phone push {'sent' if ok else 'failed'}: {msg}")

        for name, sender in (("slack", send_slack), ("teams", send_teams)):
            channel = cfg.get(name) or {}
            if channel.get("enabled") and _severity_ok(severity, channel.get("min_severity")):
                ok, msg = sender(cfg, inc, body)
                results[name] = msg
                if log:
                    log(f"{name} alert {'sent' if ok else 'failed'}: {msg}")
    return results


def test_channels(cfg):
    """Used by the Settings page: prove the email/webhook works."""
    out = {}
    ok, msg = send_email(cfg, "[NetSentinel] test message",
                         "This is a test from NetSentinel. If you are reading it, alerts will work.")
    out["email"] = {"ok": ok, "message": msg}
    ok, msg = send_webhook(cfg, {"text": "NetSentinel test message", "severity": "info"})
    out["webhook"] = {"ok": ok, "message": msg}
    sample = {"severity": "high", "state": "open", "title": "Test incident from NetSentinel",
              "device_name": "test-device", "device_ip": "192.168.1.99",
              "diagnosis": {"root_cause": "This is a test message", "confidence": 100,
                            "category_label": "Test",
                            "recommended_actions": ["Nothing to do - this is a test"]}}
    siem = cfg.get("siem") or {}
    if siem.get("enabled"):
        line = (format_rfc5424(sample) if (siem.get("format") or "cef") == "rfc5424"
                else format_cef(sample))
        ok, msg = send_syslog(cfg, line)
        out["siem"] = {"ok": ok, "message": msg}
    for name, sender in (("slack", send_slack), ("teams", send_teams)):
        if (cfg.get(name) or {}).get("enabled"):
            ok, msg = sender(cfg, sample, "test")
            out[name] = {"ok": ok, "message": msg}
    if (cfg.get("push") or {}).get("enabled"):
        ok, msg = push.send(cfg, "Test from NetSentinel", "Phone alerts are working.",
                            "info")
        out["push"] = {"ok": ok, "message": msg}
    return out
