"""Claude incident diagnosis and "Ask the AI", with the rule-based engine as the safety net.

How it fits:
  * When an incident opens or escalates, the rule-based diagnosis (diagnose.py) is attached and
    the alert goes out at once - nothing waits on the internet.
  * In the background Claude reads the same evidence (device, neighbours, gateway, internet
    targets, recent events, traffic, which data sources exist) and returns a structured
    diagnosis. If it succeeds it replaces the rule-based one (engine "claude") and a line is
    added to the incident timeline. If anything fails - no key, no internet, budget reached,
    refusal, malformed answer - the rule-based diagnosis simply stays.
  * Data only leaves the site when an administrator has switched Claude on and entered a key.

Uses the official `anthropic` SDK. Without it installed, the module reports itself unavailable.
"""

from __future__ import annotations

import json
import os
import threading
import time

from . import settings

try:  # optional dependency
    import anthropic
except Exception:  # pragma: no cover - exercised when the package is missing
    anthropic = None

DEFAULT_MODEL = "claude-opus-5-5"

CATEGORIES = ["isp_wan", "firewall_gateway", "wifi", "lan_switch", "server", "endpoint",
              "power_or_site_down", "cctv", "printer", "monitoring_host", "unknown"]

DIAGNOSIS_SCHEMA = {
    "type": "object",
    "properties": {
        "title": {"type": "string", "description": "Short headline, under 80 characters"},
        "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
        "category": {"type": "string", "enum": CATEGORIES},
        "root_cause": {"type": "string", "description": "Most likely root cause, 1-3 sentences"},
        "confidence": {"type": "integer", "description": "0-100, calibrated to the evidence"},
        "evidence": {"type": "array", "items": {"type": "string"}},
        "alternative_causes": {"type": "array", "items": {"type": "string"}},
        "user_impact": {"type": "string"},
        "recommended_actions": {"type": "array", "items": {"type": "string"},
                                "description": "Ordered steps, most useful first"},
        "needs_onsite_visit": {"type": "boolean"},
        "data_gaps": {"type": "array", "items": {"type": "string"},
                      "description": "Missing data that would raise confidence"},
    },
    "required": ["title", "severity", "category", "root_cause", "confidence", "evidence",
                 "alternative_causes", "user_impact", "recommended_actions",
                 "needs_onsite_visit", "data_gaps"],
    "additionalProperties": False,
}

SYSTEM_PROMPT = """You are the diagnosis engine of Prahari, a network monitoring console that runs on one PC
inside a small or mid-size office or hotel (often in India, often with no IT person on site). You receive the
evidence for one incident and produce a diagnosis for the person who has to fix it.

How to reason:
- Localise the fault along the path: this monitoring PC -> LAN switch -> device, and LAN -> gateway/firewall ->
  ISP -> internet. If the gateway answers but internet targets fail, suspect the ISP/WAN. If the gateway itself is
  unreachable, suspect the gateway, its power, or the LAN path to it. If most monitored devices failed at the same
  moment, suspect a shared switch, power, or this monitoring PC's own network link.
- A Wi-Fi access point answering ping only proves it is powered and wired; it says nothing about radio quality.
- Use the history (state, latency, loss, recent events) to tell a sudden failure from a slow degradation or a
  flapping link. Firewall/switch syslog lines are strong evidence when present; quote the relevant part.
- The rule-based engine's verdict is included. Agree with it when the evidence supports it; say so plainly when it
  does not.
- Confidence must match the evidence. With only ping data, rarely exceed 85. List the missing data in data_gaps.
- Recommended actions must be concrete and doable by a small team: what to check, where, what to tell the ISP.
  Never suggest anything that attacks or scans networks the operator does not own.
- Severity: critical = site or core service fully down; high = major degradation for most users;
  medium = partial or intermittent; low = minor, no clear user impact.
- Only use the data provided. Never invent devices, numbers or log lines.
"""

CHAT_SYSTEM = """You are the assistant inside Prahari, a network monitoring console for an office or hotel.
The person asking is IT or operations staff. Each question comes with the live monitoring data they are allowed to
see.

How to answer:
- Plain, simple English. Lead with the answer in one sentence, then short bullet points only if needed.
- Name the exact device and location with the numbers that matter (latency in ms, loss %, how long ago).
- Give concrete next steps a small team can do.
- Only use the data provided. If it does not show something, say so and say what would show it. Never invent
  devices, numbers or incidents. If everything is healthy, say so clearly.
"""


class Diagnoser:
    """One per process. Reads its settings live, so changes in Settings apply immediately."""

    def __init__(self, log=print, client_factory=None):
        self.log = log
        self._client = None
        self._client_key = None
        self._client_factory = client_factory  # tests inject a fake
        self._calls = []
        self._lock = threading.Lock()
        self.last_error = ""
        self.last_ok = None
        self.diagnosed = 0

    # ---- configuration -------------------------------------------------
    @property
    def cfg(self):
        return settings.get("ai") or {}

    def _key(self):
        return (self.cfg.get("api_key") or os.environ.get("ANTHROPIC_API_KEY") or "").strip()

    @property
    def enabled(self):
        return bool(self.cfg.get("enabled"))

    def client(self):
        if not self.enabled:
            return None
        key = self._key()
        if not key:
            self.last_error = "no API key - add one in Settings -> Claude AI"
            return None
        if self._client is not None and self._client_key == key:
            return self._client
        if self._client_factory:
            self._client = self._client_factory(key)
        elif anthropic is None:
            self.last_error = "the 'anthropic' package is not installed (pip install anthropic)"
            return None
        else:
            self._client = anthropic.Anthropic(api_key=key, max_retries=2, timeout=120.0)
        self._client_key = key
        return self._client

    @property
    def available(self):
        return self.client() is not None

    def status(self):
        return {"enabled": self.enabled, "available": self.available,
                "sdk": anthropic is not None or self._client_factory is not None,
                "model": self.cfg.get("model") or DEFAULT_MODEL,
                "last_error": self.last_error, "last_ok": self.last_ok,
                "diagnosed": self.diagnosed, "calls_last_hour": len(self._recent())}

    def _recent(self):
        now = time.time()
        with self._lock:
            self._calls = [t for t in self._calls if now - t < 3600]
            return list(self._calls)

    def _budget_ok(self):
        limit = int(self.cfg.get("max_per_hour") or 20)
        with self._lock:
            now = time.time()
            self._calls = [t for t in self._calls if now - t < 3600]
            if len(self._calls) >= limit:
                return False
            self._calls.append(now)
            return True

    # ---- the one place that talks to the API ---------------------------
    def _create(self, max_tokens, messages, system, effort, output_format=None):
        client = self.client()
        output_config = {"effort": effort}
        if output_format:
            output_config["format"] = output_format
        response = client.beta.messages.create(
            model=self.cfg.get("model") or DEFAULT_MODEL,
            max_tokens=max_tokens,
            betas=["server-side-fallback-2026-07-01"],
            fallbacks="default",
            output_config=output_config,
            system=[{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}],
            messages=messages,
        )
        if response.stop_reason == "refusal":
            raise RuntimeError("the model declined this request")
        if response.stop_reason == "max_tokens":
            raise RuntimeError("the answer was cut off (max_tokens)")
        return "".join(b.text for b in response.content if getattr(b, "type", "") == "text")

    def _fail(self, exc):
        if anthropic is not None and isinstance(exc, anthropic.AuthenticationError):
            msg = "Claude API key rejected"
        elif anthropic is not None and isinstance(exc, anthropic.PermissionDeniedError):
            msg = "API key lacks permission (billing or workspace)"
        elif anthropic is not None and isinstance(exc, anthropic.RateLimitError):
            msg = "Claude API rate limited - try again shortly"
        elif anthropic is not None and isinstance(exc, anthropic.APIStatusError):
            msg = f"Claude API error {exc.status_code}"
        elif anthropic is not None and isinstance(exc, anthropic.APIConnectionError):
            msg = "cannot reach api.anthropic.com from this PC (internet or proxy?)"
        else:
            msg = f"{exc.__class__.__name__}: {exc}"[:160]
        self.last_error = msg
        self.log("AI: " + msg)
        return msg

    # ---- features ------------------------------------------------------
    def test(self):
        """Tiny request to prove the key works. Returns (ok, message)."""
        if not self.enabled:
            return False, "Claude AI is switched off"
        if not self.available:
            return False, self.last_error or "not available"
        try:
            self._create(64, [{"role": "user", "content": "Reply with exactly: OK"}],
                         "You are a connectivity check.", "low")
            self.last_error, self.last_ok = "", time.time()
            return True, "Connected - Claude answered"
        except Exception as exc:
            return False, self._fail(exc)

    def diagnose(self, ctx, rule_diag=None):
        """Return a Claude diagnosis dict, or None (caller keeps the rule-based one)."""
        if not self.available:
            return None
        if not self._budget_ok():
            self.last_error = "hourly AI limit reached - rule-based diagnosis kept"
            return None
        payload = dict(ctx)
        payload["rule_based_diagnosis"] = {k: (rule_diag or {}).get(k) for k in
                                           ("title", "category", "root_cause", "confidence")}
        prompt = ("Diagnose this incident. Evidence (JSON):\n\n"
                  + json.dumps(payload, indent=1, default=str)[:150000])
        try:
            text = self._create(16000, [{"role": "user", "content": prompt}], SYSTEM_PROMPT,
                                self.cfg.get("effort") or "high",
                                {"type": "json_schema", "schema": DIAGNOSIS_SCHEMA})
            diag = json.loads(text)
            diag["confidence"] = max(0, min(100, int(diag.get("confidence") or 0)))
            diag["category_label"] = diag.get("category", "").replace("_", " ")
            diag["engine"] = "claude"
            self.last_error, self.last_ok = "", time.time()
            self.diagnosed += 1
            return diag
        except Exception as exc:
            self._fail(exc)
            return None

    def ask(self, question, snapshot, history=None):
        """Free-form question about the live data. Returns (answer, source)."""
        question = (question or "").strip()[:2000]
        if not question:
            return "Ask a question about the network.", "none"
        if not self.available:
            return ("Claude AI is not set up on this console (Settings -> Claude AI). "
                    + (self.last_error or "")).strip(), "off"
        if not self._budget_ok():
            return "The hourly AI limit is reached. Try again later or raise it in Settings.", "limit"
        msgs = []
        for m in (history or [])[-8:]:
            if m.get("role") in ("user", "assistant") and m.get("content"):
                msgs.append({"role": m["role"], "content": str(m["content"])[:4000]})
        msgs.append({"role": "user", "content": "Live monitoring data right now (JSON):\n"
                     + json.dumps(snapshot, default=str)[:150000] + "\n\nQuestion: " + question})
        try:
            answer = self._create(8000, msgs, CHAT_SYSTEM, "medium")
            self.last_error, self.last_ok = "", time.time()
            return answer, "claude"
        except Exception as exc:
            return f"The AI request failed: {self._fail(exc)}", "error"


_instance = None
_instance_lock = threading.Lock()


def get(log=print):
    global _instance
    with _instance_lock:
        if _instance is None:
            _instance = Diagnoser(log=log)
        return _instance


def refine_in_background(inc, ctx, save, log=print):
    """Ask Claude about an incident without blocking the poller; update it when the answer arrives."""
    dz = get(log)
    if not dz.enabled:
        return None

    def work():
        diag = dz.diagnose(ctx, inc.get("diagnosis"))
        if not diag:
            return
        inc["diagnosis"] = diag
        if diag.get("title"):
            inc["title"] = diag["title"]
        inc.setdefault("timeline", []).append(
            {"ts": int(time.time()),
             "text": f"Claude diagnosis ({diag['confidence']}% confident): {diag.get('root_cause', '')[:200]}"})
        try:
            save(inc)
        except Exception as exc:
            log(f"AI: could not save the diagnosis: {exc}")

    t = threading.Thread(target=work, daemon=True, name="ai-diagnose")
    t.start()
    return t


def compact_snapshot(snap):
    """The part of the dashboard state worth sending with a question (no secrets, bounded size)."""
    snap = snap or {}
    devices = [{k: d.get(k) for k in ("ip", "label", "hostname", "type", "type_label", "vendor", "state",
                                       "latency_ms", "loss_pct", "monitored", "rx_bps", "tx_bps")}
               for d in (snap.get("devices") or [])[:150]]
    incidents = [{k: i.get(k) for k in ("id", "title", "severity", "state", "device_name", "device_ip",
                                         "opened_human")} | {"root_cause": (i.get("diagnosis") or {}).get("root_cause")}
                 for i in (snap.get("incidents") or [])[:30]]
    return {"site": snap.get("site"), "health": snap.get("health"), "gateway": snap.get("gateway"),
            "internet": snap.get("internet"), "public": snap.get("public"), "local": snap.get("local"),
            "devices": devices, "incidents": incidents,
            "events": (snap.get("events") or [])[:30], "traffic": snap.get("traffic"),
            "wan": snap.get("wan")}
