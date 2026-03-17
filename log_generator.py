"""
log_generator.py  —  Continuously emits simulated cybersecurity logs into SQLite.

Patterns produced
-----------------
  normal        : healthy user logins scattered across known IPs / countries
  brute_force   : same IP fires many rapid login failures
  port_scan     : same IP touches sequential ports in quick succession
  geo_anomaly   : same user_id appears from two different countries within minutes
  odd_time      : logins between 00:00 – 05:00 local hour
"""

import random
import threading
import time
from datetime import datetime

from database import get_conn

# ── Static lookup tables ───────────────────────────────────────────────────
NORMAL_IPS = [
    "203.0.113.10", "198.51.100.22", "192.0.2.55",
    "10.0.0.5",     "172.16.0.8",    "192.168.1.42",
]
ATTACK_IPS = [
    "45.142.212.100", "91.108.4.33",    "185.220.101.7",
    "5.188.206.14",   "103.25.206.44",  "162.55.48.101",
    "194.165.16.73",  "193.32.127.154",
]
COUNTRIES = ["US", "DE", "GB", "CN", "RU", "BR", "IN", "NL", "FR", "SG"]
EVENT_TYPES = ["login_success", "login_fail", "port_access", "file_access"]
USER_IDS = [f"user_{i:03d}" for i in range(1, 21)]

# Tracks state for pattern generation
_brute_state: dict  = {}   # ip -> {count, start}
_port_state:  dict  = {}   # ip -> {ports, start}
_geo_state:   dict  = {}   # user_id -> {country, ts}
_running      = False
_thread       = None


# ── Helpers ────────────────────────────────────────────────────────────────
def _now_iso() -> str:
    return datetime.utcnow().isoformat(timespec="seconds")


def _insert_log(ip: str, event_type: str, location: str,
                user_id: str = None, port: int = None,
                status: str = "ok", extra: str = None):
    conn = get_conn()
    conn.execute(
        """INSERT INTO logs
           (ip, timestamp, event_type, location, user_id, port, status, extra)
           VALUES (?,?,?,?,?,?,?,?)""",
        (ip, _now_iso(), event_type, location,
         user_id, port, status, extra),
    )
    conn.commit()
    conn.close()


def _random_port() -> int:
    return random.choice([22, 80, 443, 3306, 5432, 8080, 8443,
                          21, 23, 25, 53, 110, 3389, 6379, 27017])


# ── Individual event generators ────────────────────────────────────────────
def _gen_normal():
    ip   = random.choice(NORMAL_IPS)
    uid  = random.choice(USER_IDS)
    ctry = random.choice(COUNTRIES[:6])          # "home" countries
    evt  = random.choice(EVENT_TYPES)
    port = _random_port() if evt == "port_access" else None
    _insert_log(ip, evt, ctry, user_id=uid, port=port)
    return {"ip": ip, "event_type": evt, "location": ctry, "user_id": uid}


def _gen_brute_force():
    """Fire a burst of login failures from the same attacker IP."""
    ip   = random.choice(ATTACK_IPS)
    ctry = "RU"
    for _ in range(random.randint(3, 6)):
        _insert_log(ip, "login_fail", ctry,
                    user_id=random.choice(USER_IDS),
                    status="fail",
                    extra="brute_force_burst")
    return {"ip": ip, "event_type": "login_fail", "location": ctry,
            "pattern": "brute_force"}


def _gen_port_scan():
    """Access many sequential ports from one IP."""
    ip   = random.choice(ATTACK_IPS)
    ctry = "CN"
    ports = random.sample(range(1, 1025), random.randint(8, 14))
    for p in ports:
        _insert_log(ip, "port_access", ctry, port=p,
                    status="probe", extra="port_scan")
    return {"ip": ip, "event_type": "port_access", "location": ctry,
            "ports": ports, "pattern": "port_scan"}


def _gen_geo_anomaly():
    """Same user logs in from two different countries within the window."""
    uid    = random.choice(USER_IDS)
    ctry_a = random.choice(COUNTRIES[:5])
    ctry_b = random.choice([c for c in COUNTRIES if c != ctry_a])
    ip_a   = random.choice(NORMAL_IPS)
    ip_b   = random.choice(ATTACK_IPS)
    _insert_log(ip_a, "login_success", ctry_a, user_id=uid)
    _insert_log(ip_b, "login_success", ctry_b, user_id=uid,
                extra="geo_anomaly")
    return {"user_id": uid, "country_a": ctry_a, "country_b": ctry_b,
            "pattern": "geo_anomaly"}


def _gen_odd_time():
    """Normal login but flagged with an odd-hour timestamp."""
    ip   = random.choice(NORMAL_IPS + ATTACK_IPS)
    uid  = random.choice(USER_IDS)
    ctry = random.choice(COUNTRIES)
    # Force timestamp into 01:00–04:00 range in the extra field
    _insert_log(ip, "login_success", ctry, user_id=uid,
                extra="odd_time_03:00")
    return {"ip": ip, "user_id": uid, "pattern": "odd_time"}


# ── Main loop ──────────────────────────────────────────────────────────────
_GENERATORS = [
    (_gen_normal,       0.60),   # 60 % of the time it's boring
    (_gen_brute_force,  0.15),
    (_gen_port_scan,    0.12),
    (_gen_geo_anomaly,  0.08),
    (_gen_odd_time,     0.05),
]


def _pick() -> callable:
    r = random.random()
    acc = 0.0
    for fn, w in _GENERATORS:
        acc += w
        if r < acc:
            return fn
    return _gen_normal


_on_new_log_callbacks: list = []


def register_callback(fn):
    """Register a function(log_dict) to be called after each insertion."""
    _on_new_log_callbacks.append(fn)


def _run_loop():
    global _running
    while _running:
        try:
            fn  = _pick()
            log = fn()
            for cb in _on_new_log_callbacks:
                try:
                    cb(log)
                except Exception:
                    pass
        except Exception as exc:
            print(f"[LogGen] error: {exc}")
        time.sleep(random.uniform(1.0, 2.0))


def start():
    global _running, _thread
    if _running:
        return
    _running = True
    _thread  = threading.Thread(target=_run_loop, daemon=True, name="log-gen")
    _thread.start()
    print("[LogGen] started")


def stop():
    global _running
    _running = False
    print("[LogGen] stopped")


# ── Trigger a specific attack type on-demand ───────────────────────────────
def trigger(attack_type: str) -> dict:
    mapping = {
        "brute_force": _gen_brute_force,
        "port_scan":   _gen_port_scan,
        "geo_anomaly": _gen_geo_anomaly,
        "odd_time":    _gen_odd_time,
        "ddos":        _gen_brute_force,   # repurpose for demo
        "apt":         _gen_port_scan,
    }
    fn = mapping.get(attack_type, _gen_normal)
    return fn()
