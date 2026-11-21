"""Escalation: if nobody reacts, tell the next person.

An alert that nobody reads is the same as no alert. This watches open problems - device and
internet incidents, and sensors that are down - and when one has been open past a step's
threshold without being acknowledged, it tells the next people in the chain. Each step fires
once per problem, there is a cap per problem, and quiet hours hold back the non-urgent ones.

The chain is data in Settings:

    escalation:
      enabled: true
      steps:
        - after_minutes: 20   channels: [email, push]       to: [gm@hotel.in]
        - after_minutes: 60   channels: [email, telegram]   to: [owner@hotel.in]
      max_pages_per_incident: 3
      quiet_hours: "23:00-07:00"     only critical/high problems page inside this window

The first alert is the normal one (Settings -> Email / Phone alerts). Acknowledging an incident
(Incidents -> close, or /ack on Telegram) closes it and stops the chain. Every page is written
into the incident's timeline, so "nobody told us" can be answered.

`plan()` is pure - it decides, the caller records - which keeps it testable without a clock or
a mail server.
"""

from __future__ import annotations

import datetime
import time

from . import settings

DEFAULTS = {"enabled": False, "steps": [], "max_pages_per_incident": 3, "quiet_hours": ""}
CHANNELS = ("email", "push", "telegram")
URGENT = ("critical", "high")


def config(cfg=None):
    cfg = cfg if cfg is not None else settings.load()
    esc = dict(DEFAULTS)
    esc.update(cfg.get("escalation") or {})
    esc["steps"] = clean_steps(esc.get("steps"))
    return esc


def clean_steps(steps):
    """Steps as typed in Settings -> a tidy, sorted list. Bad rows are dropped."""
    out = []
    for raw in steps or []:
        if not isinstance(raw, dict):
            continue
        try:
            after = max(1, int(float(raw.get("after_minutes") or 0)))
        except (TypeError, ValueError):
            continue
        to = raw.get("to") or []
        if isinstance(to, str):
            to = [x.strip() for x in to.replace(";", ",").split(",")]
        to = [x for x in to if x and "@" in x]
        channels = raw.get("channels") or ["email"]
        if isinstance(channels, str):
            channels = [x.strip() for x in channels.replace("+", ",").split(",")]
        channels = [c.lower() for c in channels if c and c.lower() in CHANNELS]
        if not channels:
            continue
        if "email" in channels and not to and channels == ["email"]:
            continue                      # an email step with nobody to email does nothing
        out.append({"after_minutes": after, "channels": channels, "to": to})
    out.sort(key=lambda s: s["after_minutes"])
    return out


def in_quiet_hours(window, when=None):
    """'23:00-07:00' - windows across midnight work."""
    if not window or "-" not in str(window):
        return False
    try:
        start_s, end_s = str(window).split("-", 1)
        sh, sm = (int(x) for x in start_s.strip().split(":"))
        eh, em = (int(x) for x in end_s.strip().split(":"))
    except Exception:
        return False
    now = when or datetime.datetime.now()
    minutes = now.hour * 60 + now.minute
    start, end = sh * 60 + sm, eh * 60 + em
    if start == end:
        return False
    if start < end:
        return start <= minutes < end
    return minutes >= start or minutes < end


def plan(problems, esc, now=None, when=None):
    """Which problems need which step now.

    problems: [{key, severity, opened_ts, paged: [step indexes already sent]}]
    Returns [(problem, step_index, step)] - at most one step per problem per pass, the
    highest one that is due (so a Prahari restarted after two hours does not send three
    pages in a row)."""
    now = now or time.time()
    steps = esc.get("steps") or []
    if not esc.get("enabled") or not steps:
        return []
    limit = max(1, int(esc.get("max_pages_per_incident") or 3))
    quiet = in_quiet_hours(esc.get("quiet_hours") or "", when)
    out = []
    for problem in problems:
        paged = set(problem.get("paged") or [])
        if len(paged) >= limit:
            continue
        if quiet and (problem.get("severity") or "") not in URGENT:
            continue
        age_min = (now - float(problem.get("opened_ts") or now)) / 60.0
        due = [i for i, s in enumerate(steps) if age_min >= s["after_minutes"]]
        if not due:
            continue
        top = max(due)
        if top in paged or any(i > top for i in paged):
            continue
        out.append((problem, top, steps[top]))
    return out


def message(problem, step, now=None):
    now = now or time.time()
    minutes = int((now - float(problem.get("opened_ts") or now)) / 60)
    site = (settings.get("site_name") or "").strip()
    title = f"[Prahari] ESCALATED: {problem.get('title') or 'a problem'}"
    if site:
        title += f" - {site}"
    body = (f"{problem.get('title') or 'A problem'} has been open for {minutes} minutes and "
            f"nobody has acknowledged it.\n\n"
            f"Location: {site or '-'}\n"
            f"What: {problem.get('what') or '-'}\n"
            f"Severity: {problem.get('severity') or '-'}\n"
            f"Likely cause: {problem.get('cause') or 'unknown'}\n\n"
            + (f"Open the Prahari dashboard to look at it and acknowledge it, or reply /ack "
               f"{problem.get('key')} on Telegram."
               if problem.get("kind") == "incident" else
               "Open the Prahari dashboard (Sensors). This stops when the check passes again."))
    return title, body


def send(cfg, problem, step, log=None):
    """Deliver one step. Returns {channel: {ok, message}}."""
    from . import alerts
    title, body = message(problem, step)
    sent = {}
    for channel in step.get("channels") or []:
        try:
            if channel == "email":
                e = cfg.get("email") or {}
                if not (e.get("enabled") and e.get("host")):
                    ok, msg = False, "email is not set up (Settings -> Email)"
                else:
                    ok, msg = alerts.send_email(cfg, title, body, to=step.get("to") or None)
            elif channel == "push":
                from . import push
                ok, msg = push.send(cfg, title, body, problem.get("severity") or "high")
            elif channel == "telegram":
                from . import telegram
                tg = cfg.get("telegram") or {}
                chats = tg.get("chat_ids") or []
                if not (tg.get("enabled") and tg.get("token") and chats):
                    ok, msg = False, "Telegram is not set up"
                else:
                    ok, msg = True, "sent"
                    for chat in chats:
                        r_ok, r_msg = telegram.send(tg["token"], chat, f"{title}\n\n{body}")
                        if not r_ok:
                            ok, msg = False, r_msg
            else:
                ok, msg = False, f"unknown channel {channel}"
        except Exception as exc:
            ok, msg = False, f"{exc.__class__.__name__}: {exc}"
        sent[channel] = {"ok": bool(ok), "message": str(msg)[:120]}
        if log:
            log(f"escalation {problem.get('key')} step {step.get('after_minutes')} min via "
                f"{channel}: {'sent' if ok else msg}")
    return sent


def status(cfg=None, recent=None):
    esc = config(cfg)
    return {"enabled": bool(esc.get("enabled")), "steps": esc.get("steps") or [],
            "max_pages": esc.get("max_pages_per_incident"),
            "quiet_hours": esc.get("quiet_hours") or "",
            "in_quiet_hours": in_quiet_hours(esc.get("quiet_hours") or ""),
            "recent": list(recent or [])[-10:]}
