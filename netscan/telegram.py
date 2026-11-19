"""Telegram bot: ask the console from your phone, acknowledge incidents from the sofa.

    /status          health, open incidents, internet line
    /incidents       the open ones with their ids
    /ack INC-123     acknowledge (closes) an incident
    /sites           every location on the hub, one line each
    /help

Only chat ids listed in Settings can use it; anyone else gets a polite reply telling them
their chat id, so you can add it deliberately.
"""

from __future__ import annotations

import json
import threading
import time
import urllib.parse
import urllib.request

from . import settings, sites as sites_mod

API = "https://api.telegram.org/bot"


def _call(token, method, payload, timeout=30):
    url = f"{API}{token}/{method}"
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def send(token, chat_id, text):
    try:
        _call(token, "sendMessage", {"chat_id": chat_id, "text": text[:4000],
                                     "disable_web_page_preview": True})
        return True, "sent"
    except Exception as exc:
        return False, f"{exc.__class__.__name__}: {exc}"[:140]


def _fmt_status(scanner):
    snap = scanner.snapshot()
    h = snap.get("health") or {}
    inc = snap.get("open_incidents") or []
    wan = (snap.get("wan") or {}).get("ips") or []
    lines = [f"*{(snap.get('site') or 'Prahari')}*",
             f"health {h.get('score')}%  ·  {h.get('up')} up / {h.get('degraded')} degraded / {h.get('down')} down",
             f"open incidents: {len(inc)}"]
    if wan:
        lines.append("internet: " + ", ".join(wan))
    for i in inc[:3]:
        lines.append(f"  · {i.get('severity','?')} — {i.get('title','')[:70]}")
    return "\n".join(lines)


def _fmt_incidents(scanner):
    inc = scanner.snapshot().get("open_incidents") or []
    if not inc:
        return "Nothing open. Every monitored device is answering."
    out = []
    for i in inc[:10]:
        out.append(f"{i.get('id')}  [{i.get('severity')}]  {i.get('title','')[:60]}")
    out.append("\nacknowledge with: /ack <id>")
    return "\n".join(out)


def _fmt_sites(scanner):
    ov = sites_mod.hub_overview(scanner)
    if not (ov.get("enabled")):
        return "This console is not a hub. Run it with --hub to collect locations."
    rows = ov.get("branches") or []
    if not rows:
        return "No site has reported yet."
    out = []
    for b in rows[:25]:
        kind = "CORP " if b.get("kind") == "corp" else "     "
        flag = "" if b.get("online") else "  NO CONTACT"
        h = (b.get("health") or {}).get("score")
        out.append(f"{kind}{b['name'][:32]:<32} {str(h)+'%' if h is not None else '—':>4}"
                   f"  inc {len(b.get('incidents') or []):<2}{flag}")
    if len(rows) > 25:
        out.append(f"... and {len(rows)-25} more")
    return "\n".join(out)


def handle(scanner, text, chat_id, allowed):
    """Return the reply for one message."""
    text = (text or "").strip()
    if allowed and str(chat_id) not in [str(a) for a in allowed]:
        return (f"This chat ({chat_id}) is not authorised. Add that number in "
                f"Prahari → Settings → Telegram to allow it.")
    cmd = text.split()[0].lower() if text else ""
    args = text.split()[1:]
    if cmd in ("/start", "/help"):
        return ("Prahari — commands:\n"
                "/status — health and open incidents\n"
                "/incidents — the open ones with ids\n"
                "/ack <id> — acknowledge an incident\n"
                "/sites — all locations (hub only)")
    if cmd == "/status":
        return _fmt_status(scanner)
    if cmd == "/incidents":
        return _fmt_incidents(scanner)
    if cmd == "/sites":
        return _fmt_sites(scanner)
    if cmd == "/ack":
        if not args:
            return "Usage: /ack INC-1234567890-0001  (get the id from /incidents)"
        ok = scanner.dismiss_incident(args[0])
        if ok:
            scanner.audit(f"telegram:{chat_id}", "incident closed", args[0])
            return f"Closed {args[0]}."
        return f"No open incident called {args[0]}."
    if not cmd:
        return "Say /help."
    return f"Unknown command {cmd}. Try /help."


class TelegramBot(threading.Thread):
    def __init__(self, scanner, log=None):
        super().__init__(daemon=True, name="telegram")
        self.scanner = scanner
        self.log = log or (lambda m: None)
        self._stop = threading.Event()
        self.offset = 0
        self.handled = 0
        self.last_error = ""

    def stop(self):
        self._stop.set()

    def poll_once(self, timeout=20):
        cfg = settings.load()
        tg = cfg.get("telegram") or {}
        token = (tg.get("token") or "").strip()
        if not (tg.get("enabled") and token):
            return 0
        allowed = tg.get("chat_ids") or []
        try:
            data = _call(token, "getUpdates",
                         {"offset": self.offset, "timeout": timeout}, timeout=timeout + 15)
        except Exception as exc:
            self.last_error = f"{exc.__class__.__name__}: {exc}"[:140]
            return 0
        count = 0
        for update in data.get("result") or []:
            self.offset = max(self.offset, int(update.get("update_id", 0)) + 1)
            msg = update.get("message") or update.get("edited_message") or {}
            chat = (msg.get("chat") or {}).get("id")
            text = msg.get("text") or ""
            if not chat or not text:
                continue
            try:
                reply = handle(self.scanner, text, chat, allowed)
            except Exception as exc:
                reply = f"Sorry, that failed: {exc.__class__.__name__}"
            send(token, chat, reply)
            self.handled += 1
            count += 1
        return count

    def run(self):
        self._stop.wait(5)
        while not self._stop.is_set():
            try:
                self.poll_once()
            except Exception as exc:
                self.last_error = str(exc)[:140]
            self._stop.wait(2)
