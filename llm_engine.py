"""
llm_engine.py  —  AI explanation engine powered by a local Ollama instance.

If Ollama is unreachable, a deterministic rule-based fallback is returned
so the rest of the system keeps working in offline/demo mode.
"""

import json
import requests

OLLAMA_URL   = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "llama3"          # swap to "mistral", "phi3", etc. as needed
TIMEOUT      = 30                # seconds


# ── Core call ──────────────────────────────────────────────────────────────
def _ollama(prompt: str) -> str:
    payload = {
        "model":  OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
    }
    resp = requests.post(OLLAMA_URL, json=payload, timeout=TIMEOUT)
    resp.raise_for_status()
    return resp.json().get("response", "").strip()


# ── Threat explanation ─────────────────────────────────────────────────────
EXPLAIN_TEMPLATE = """You are a cybersecurity analyst AI embedded in AegisX, a real-time threat monitoring platform.
A pattern-detection engine has raised the following alert. Respond ONLY with a JSON object — no markdown, no prose outside the JSON.

Alert details:
  pattern_type : {pattern_type}
  ip           : {ip}
  event_count  : {event_count}
  severity     : {severity}
  timestamp    : {timestamp}

Required JSON structure:
{{
  "explanation"  : "<2-3 sentence plain-English explanation of what is happening and why it is dangerous>",
  "severity_reason": "<1 sentence justifying the severity level>",
  "mitigation"   : ["<step 1>", "<step 2>", "<step 3>"]
}}
"""


def explain_alert(alert: dict) -> dict:
    """
    Returns a dict with keys: explanation, severity_reason, mitigation (list).
    Falls back to rule-based answers if Ollama is unavailable.
    """
    try:
        prompt = EXPLAIN_TEMPLATE.format(
            pattern_type = alert.get("pattern_type", "unknown"),
            ip           = alert.get("ip", "unknown"),
            event_count  = alert.get("event_count", 0),
            severity     = alert.get("severity", "unknown"),
            timestamp    = alert.get("timestamp", "unknown"),
        )
        raw = _ollama(prompt)
        # Strip possible markdown fences
        raw = raw.strip().lstrip("```json").lstrip("```").rstrip("```").strip()
        return json.loads(raw)
    except Exception as exc:
        print(f"[LLM] Ollama unavailable ({exc}), using fallback.")
        return _fallback(alert)


# ── Chat endpoint ─────────────────────────────────────────────────────────
CHAT_SYSTEM = (
    "You are Sentinel AI, a cybersecurity assistant embedded in AegisX. "
    "Answer clearly and concisely in plain English. "
    "Focus on practical threat analysis and mitigation advice."
)

def chat(question: str) -> str:
    """Answer a free-form cybersecurity question."""
    try:
        prompt = f"{CHAT_SYSTEM}\n\nUser question: {question}\n\nAnswer:"
        return _ollama(prompt)
    except Exception as exc:
        print(f"[LLM] chat fallback ({exc})")
        return _chat_fallback(question)


# ── Rule-based fallbacks ───────────────────────────────────────────────────
def _fallback(alert: dict) -> dict:
    pt = alert.get("pattern_type", "")
    ip = alert.get("ip", "unknown")
    n  = alert.get("event_count", 0)

    RULES = {
        "brute_force": {
            "explanation": (
                f"This appears to be a brute-force attack: {n} failed login attempts "
                f"were recorded within 60 seconds from {ip}. "
                "Automated tools are cycling through credentials to gain unauthorised access."
            ),
            "severity_reason": "High attempt frequency combined with a single source IP indicates automation.",
            "mitigation": [
                f"Block {ip} at the firewall immediately.",
                "Enforce account lockout after 5 failed attempts.",
                "Enable MFA across all accounts targeted from this IP.",
            ],
        },
        "port_scan": {
            "explanation": (
                f"{ip} probed {n} distinct ports in under 30 seconds. "
                "This is a classic TCP reconnaissance scan designed to map the attack surface "
                "before a targeted intrusion attempt."
            ),
            "severity_reason": "Port scanning almost always precedes a direct attack.",
            "mitigation": [
                f"Block {ip} and add it to your threat-intelligence feed.",
                "Audit all open ports; close anything not strictly required.",
                "Enable port-scan detection on your IDS/IPS.",
            ],
        },
        "geo_anomaly": {
            "explanation": (
                "The same account authenticated from two geographically distant countries "
                "within 5 minutes — physically impossible without account sharing or compromise."
            ),
            "severity_reason": "Impossible travel is a strong indicator of credential theft.",
            "mitigation": [
                "Lock the affected account immediately.",
                "Force a password reset and MFA enrollment.",
                "Contact the account owner to confirm they did not travel.",
            ],
        },
        "odd_time": {
            "explanation": (
                f"A login from {ip} occurred outside normal business hours (00:00–05:00 UTC). "
                "While not conclusive alone, combined with other signals this warrants review."
            ),
            "severity_reason": "Off-hours logins are a weak but meaningful anomaly signal.",
            "mitigation": [
                "Review the account for additional suspicious activity.",
                "Notify the account owner of the off-hours login.",
                "Consider enforcing time-based access controls.",
            ],
        },
    }
    return RULES.get(pt, {
        "explanation":    f"Anomalous activity detected from {ip} ({n} events).",
        "severity_reason": "Multiple correlated signals raised the risk score.",
        "mitigation":     ["Investigate the source IP.", "Review affected accounts.", "Escalate to your SOC."],
    })


def _chat_fallback(q: str) -> str:
    ql = q.lower()
    if "brute" in ql:
        return (
            "Brute-force attacks are detected when the same IP produces more than 5 failed "
            "logins within a 60-second sliding window. AegisX tracks this with a per-IP "
            "failure counter and fires an alert the moment the threshold is crossed."
        )
    if "port scan" in ql or "portscan" in ql:
        return (
            "Port scans are flagged when a single IP accesses more than 10 distinct ports "
            "within 30 seconds. Sequential port patterns receive a confidence bonus, "
            "raising the risk score further."
        )
    if "geo" in ql:
        return (
            "Geo-anomaly detection compares login locations for the same user account. "
            "If the same account appears from two countries within 5 minutes "
            "(impossible travel), the account is likely compromised."
        )
    if "risk" in ql or "score" in ql:
        return (
            "Risk scores: Brute Force +40, Port Scan +30, Geo Anomaly +70, "
            "Odd-Time Login +30. Scores are clamped to 100. "
            "Alerts fire at ≥40 (medium), ≥60 (high), ≥80 (critical)."
        )
    return (
        "AegisX monitors your infrastructure in real-time, correlating login failures, "
        "port probes, geo anomalies and off-hours activity into actionable alerts. "
        "Ask me about a specific attack pattern for a detailed breakdown."
    )
