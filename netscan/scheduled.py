"""Send the monthly service report by email, without anyone remembering to.

On the configured day of the month (default the 1st) at the configured hour, this builds the
report for the previous month and mails it to the list, with the PDF attached. The last send
is recorded in settings, so a restart cannot mail the same month twice.
"""

from __future__ import annotations

import datetime
import os
import tempfile
import threading
import time

from . import alerts, settings, sla


def due(cfg, now=None):
    """Is the report due? Returns (due, month_to_report)."""
    conf = cfg.get("sla_email") or {}
    if not (conf.get("enabled") and (conf.get("to") or [])):
        return False, None
    now = now or datetime.datetime.now()
    day = int(conf.get("day") or 1)
    hour = int(conf.get("hour") or 7)
    if now.day < day or now.hour < hour:
        return False, None
    prev = (now.replace(day=1) - datetime.timedelta(days=1))
    month = prev.strftime("%Y-%m")
    if (conf.get("last_sent") or "") == month:
        return False, month
    return True, month


def send(month=None, to=None, log=None):
    """Build the report for `month` and email it."""
    cfg = settings.load()
    conf = cfg.get("sla_email") or {}
    recipients = to or [x for x in (conf.get("to") or []) if "@" in x]
    if not recipients:
        return False, "no recipients configured"
    out_dir = os.path.join(tempfile.gettempdir(), "netsentinel-sla")
    path = sla.render(month or None, out_dir=out_dir)
    site = cfg.get("site_name") or "this site"
    start, end, label = sla.month_range(month or None)
    body = (f"The monthly service report for {site} - {label} - is attached.\n\n"
            "It covers availability, incidents, mean time to resolve, latency, packet loss, "
            "disk trends and the security score, with a page explaining how each number was "
            "measured.\n\n"
            "This message was produced automatically by NetSentinel.")
    ok, msg = alerts.send_email(cfg, f"Monthly service report - {site} - {label}",
                                body, to=recipients, attachments=[path])
    if ok:
        settings.save({"sla_email": {"last_sent": month or label}})
        if log:
            log(f"monthly report mailed to {', '.join(recipients)}")
    elif log:
        log(f"monthly report failed: {msg}")
    return ok, msg


class ReportScheduler(threading.Thread):
    """Checks once an hour whether the report is due."""

    def __init__(self, log=None):
        super().__init__(daemon=True, name="sla-email")
        self.log = log or (lambda m: None)
        self._stop = threading.Event()
        self.last_error = ""

    def stop(self):
        self._stop.set()

    def run(self):
        self._stop.wait(90)
        while not self._stop.is_set():
            try:
                cfg = settings.load()
                is_due, month = due(cfg)
                if is_due:
                    ok, msg = send(month, log=self.log)
                    self.last_error = "" if ok else msg
            except Exception as exc:
                self.last_error = f"{exc.__class__.__name__}: {exc}"[:140]
            self._stop.wait(3600)
