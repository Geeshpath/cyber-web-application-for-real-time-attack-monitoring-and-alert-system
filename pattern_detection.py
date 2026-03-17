"""
pattern_detection.py  —  Real-time attack pattern detection engine.

Detection rules (sliding 60-second window unless noted):
  brute_force   : > 5 failed logins from the same IP
  port_scan     : > 10 distinct ports accessed from the same IP (30-s window)
  geo_anomaly   : same user_id from 2 different countries within 5 minutes
  odd_time      : login between 00:00 – 05:00 UTC or 'odd_time' in extra field

Each alert is assigned a risk score and stored in the alerts table.
Registered callbacks are fired so the Flask app can push via WebSocket.
"""

import threading
import time
from collections import defaultdict
from datetime import datetime, timezone

from database import get_conn

# ── Tuning parameters ──────────────────────────────────────────────────────
BRUTE_WINDOW    = 60    # seconds
BRUTE_THRESHOLD = 5     # failed logins

PORT_WINDOW     = 30    # seconds
PORT_THRESHOLD  = 10    # distinct ports

GEO_WINDOW      = 300   # seconds (5 min)

ODD_HOUR_START  = 0     # UTC hours 00–04 are "odd"
ODD_HOUR_END    = 5

POLL_INTERVAL   = 5     # seconds between scans

# ── In-memory state ────────────────────────────────────────────────────────
# ip → [(timestamp, status)]
_login_fails: dict = defaultdict(list)

# ip → [(timestamp, port)]
_port_accesses: dict = defaultdict(list)

# user_id → [(timestamp, country)]
_geo_events: dict = defaultdict(list)

# Prevent duplicate alerts being fired in rapid succession
_recent_alerts: dict = defaultdict(float)   # key → last_fired epoch
COOLDOWN = 120   # seconds between same-key alerts

_callbacks: list = []
_running = False
_thread  = None
_lock    = threading.Lock()


# ── Helpers ────────────────────────────────────────────────────────────────
def _ts() -> float:
    return time.time()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _severity(score: int) -> str:
    if score >= 80: return "critical"
    if score >= 60: return "high"
    if score >= 40: return "medium"
    return "low"


def _can_fire(key: str) -> bool:
    now = _ts()
    if now - _recent_alerts[key] > COOLDOWN:
        _recent_alerts[key] = now
        return True
    return False


def _store_and_notify(ip: str, pattern: str, score: int,
                      event_count: int, explanation: str = "",
                      mitigation: str = "") -> dict:
    sev = _severity(score)
    alert = {
        "ip":           ip,
        "pattern_type": pattern,
        "severity":     sev,
        "score":        score,
        "event_count":  event_count,
        "explanation":  explanation,
        "mitigation":   mitigation,
        "timestamp":    _now_iso(),
    }
    conn = get_conn()
    conn.execute(
        """INSERT INTO alerts
           (ip, pattern_type, severity, score, event_count,
            explanation, mitigation, timestamp)
           VALUES (?,?,?,?,?,?,?,?)""",
        (ip, pattern, sev, score, event_count,
         explanation, mitigation, _now_iso()),
    )
    conn.commit()
    conn.close()
    for cb in _callbacks:
        try:
            cb(alert)
        except Exception:
            pass
    return alert


# ── Ingest a new log event ─────────────────────────────────────────────────
def ingest(log: dict):
    """
    Called by log_generator (via callback) or the Flask /simulate endpoint
    after a log row has been written to the DB.
    """
    now      = _ts()
    ip       = log.get("ip", "")
    evt      = log.get("event_type", "")
    uid      = log.get("user_id", "")
    country  = log.get("location", "")
    extra    = log.get("extra", "") or ""
    port     = log.get("port")

    with _lock:
        # ── Brute-force tracking
        if evt == "login_fail" or "fail" in extra.lower():
            _login_fails[ip].append(now)

        # ── Port-scan tracking
        if evt == "port_access" and port:
            _port_accesses[ip].append((now, port))

        # ── Geo tracking
        if evt in ("login_success", "login_fail") and uid and country:
            _geo_events[uid].append((now, country))

        # ── Odd-time (immediate check)
        if evt in ("login_success", "login_fail"):
            hour = datetime.now(timezone.utc).hour
            if "odd_time" in extra.lower() or (ODD_HOUR_START <= hour < ODD_HOUR_END):
                key = f"odd_time_{ip}"
                if _can_fire(key):
                    _store_and_notify(
                        ip=ip, pattern="odd_time", score=30,
                        event_count=1,
                        explanation=(
                            f"Login from {ip} detected at {hour:02d}:00 UTC — "
                            "outside normal business hours."
                        ),
                        mitigation=(
                            "Review this account for potential compromise. "
                            "Enforce MFA. Notify the account owner."
                        ),
                    )


# ── Periodic scan ──────────────────────────────────────────────────────────
def _scan():
    now = _ts()
    with _lock:
        # ── Brute force
        for ip, times in list(_login_fails.items()):
            window = [t for t in times if now - t <= BRUTE_WINDOW]
            _login_fails[ip] = window
            if len(window) > BRUTE_THRESHOLD:
                key = f"brute_{ip}"
                if _can_fire(key):
                    _store_and_notify(
                        ip=ip, pattern="brute_force",
                        score=min(40 + (len(window) - BRUTE_THRESHOLD) * 5, 100),
                        event_count=len(window),
                        explanation=(
                            f"{len(window)} failed login attempts from {ip} "
                            f"within the last {BRUTE_WINDOW} seconds. "
                            "This is consistent with an automated brute-force or "
                            "credential-stuffing attack."
                        ),
                        mitigation=(
                            f"Immediately block {ip} at the firewall. "
                            "Enable account lockout after 5 failures. "
                            "Enable MFA for all accounts targeted from this IP."
                        ),
                    )

        # ── Port scan
        for ip, entries in list(_port_accesses.items()):
            window  = [(t, p) for t, p in entries if now - t <= PORT_WINDOW]
            _port_accesses[ip] = window
            ports   = {p for _, p in window}
            if len(ports) > PORT_THRESHOLD:
                key = f"portscan_{ip}"
                if _can_fire(key):
                    _store_and_notify(
                        ip=ip, pattern="port_scan",
                        score=min(30 + len(ports) * 2, 95),
                        event_count=len(ports),
                        explanation=(
                            f"{len(ports)} distinct ports probed by {ip} "
                            f"within {PORT_WINDOW} seconds ({sorted(ports)}). "
                            "Sequential port access indicates network reconnaissance."
                        ),
                        mitigation=(
                            f"Block {ip} immediately. "
                            "Enable port-scan detection on your firewall/IDS. "
                            "Audit exposed services — close any unnecessary ports."
                        ),
                    )

        # ── Geo anomaly
        for uid, events in list(_geo_events.items()):
            window = [(t, c) for t, c in events if now - t <= GEO_WINDOW]
            _geo_events[uid] = window
            countries = {c for _, c in window}
            if len(countries) >= 2:
                key = f"geo_{uid}"
                if _can_fire(key):
                    country_list = ", ".join(sorted(countries))
                    _store_and_notify(
                        ip="multiple",
                        pattern="geo_anomaly",
                        score=70,
                        event_count=len(window),
                        explanation=(
                            f"Account '{uid}' authenticated from {country_list} "
                            f"within {GEO_WINDOW // 60} minutes — physically impossible. "
                            "The account is likely compromised."
                        ),
                        mitigation=(
                            f"Lock account '{uid}' immediately. "
                            "Force password reset and MFA enrollment. "
                            "Contact the account owner for verification."
                        ),
                    )


def _run_loop():
    global _running
    while _running:
        try:
            _scan()
        except Exception as exc:
            print(f"[Detector] error: {exc}")
        time.sleep(POLL_INTERVAL)


# ── Public API ─────────────────────────────────────────────────────────────
def register_callback(fn):
    """Register fn(alert_dict) to be called when a new alert fires."""
    _callbacks.append(fn)


def start():
    global _running, _thread
    if _running:
        return
    _running = True
    _thread  = threading.Thread(target=_run_loop, daemon=True, name="detector")
    _thread.start()
    print("[Detector] started")


def stop():
    global _running
    _running = False
    print("[Detector] stopped")


# ── On-demand scan (useful for /simulate endpoint) ─────────────────────────
def force_scan():
    _scan()
