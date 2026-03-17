"""
app.py  —  AegisX Flask backend
========================================
Endpoints
---------
  GET  /                → health check
  POST /login           → alias for /auth/login
  POST /signup          → alias for /auth/signup
  GET  /logs            → recent logs (paginated)
  GET  /alerts          → recent alerts (paginated)
  POST /explain         → AI explanation for a threat / chat question
  POST /simulate        → trigger an attack simulation

WebSocket (Socket.IO)
---------------------
  Namespace: /
  Events emitted by server:
    "log"   → new log entry
    "alert" → new alert entry
  Events accepted from client:
    "connect"    → acknowledged
    "subscribe"  → acknowledged
"""

import os
from datetime import timedelta

import eventlet
eventlet.monkey_patch()          # must be before other imports

from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity, get_jwt
from flask_socketio import SocketIO, emit

from database import init_db, get_conn
from auth import auth_bp
import log_generator
import pattern_detection
import llm_engine


# ── App setup ──────────────────────────────────────────────────────────────
app = Flask(__name__)
app.config["JWT_SECRET_KEY"]        = os.environ.get("JWT_SECRET", "aegisx-dev-secret-change-me")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=7)

CORS(app, resources={r"/*": {"origins": "*"}})
jwt = JWTManager(app)

socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="eventlet",
    logger=False,
    engineio_logger=False,
)

app.register_blueprint(auth_bp)


# ── WebSocket event emitters ───────────────────────────────────────────────
def _broadcast_log(log_dict: dict):
    socketio.emit("log", log_dict, namespace="/")


def _broadcast_alert(alert_dict: dict):
    socketio.emit("alert", {"type": "alert", **alert_dict}, namespace="/")


# ── Initialise everything ──────────────────────────────────────────────────
@app.before_request
def _startup():
    pass   # startup is done once at module level below


def startup():
    init_db()
    log_generator.register_callback(_broadcast_log)
    log_generator.register_callback(pattern_detection.ingest)
    pattern_detection.register_callback(_broadcast_alert)
    log_generator.start()
    pattern_detection.start()
    print("[AegisX] backend ready on http://localhost:8000")


# ── REST Endpoints ─────────────────────────────────────────────────────────

@app.route("/", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "AegisX Backend"})


# ── /login & /signup aliases (frontend uses these directly) ───────────────
@app.route("/login", methods=["POST"])
def login_alias():
    from auth import login as _login
    return _login()


@app.route("/signup", methods=["POST"])
def signup_alias():
    from auth import signup as _signup
    return _signup()


# ── /logs ──────────────────────────────────────────────────────────────────
@app.route("/logs", methods=["GET"])
def get_logs():
    limit  = min(int(request.args.get("limit",  50)), 500)
    offset = int(request.args.get("offset", 0))
    conn   = get_conn()
    try:
        rows = conn.execute(
            "SELECT * FROM logs ORDER BY id DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
        return jsonify([dict(r) for r in rows])
    finally:
        conn.close()


# ── /alerts ────────────────────────────────────────────────────────────────
@app.route("/alerts", methods=["GET"])
def get_alerts():
    limit  = min(int(request.args.get("limit",  50)), 500)
    offset = int(request.args.get("offset", 0))
    conn   = get_conn()
    try:
        rows = conn.execute(
            "SELECT * FROM alerts ORDER BY id DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
        return jsonify([dict(r) for r in rows])
    finally:
        conn.close()


# ── /explain (chat + alert explanation) ───────────────────────────────────
@app.route("/explain", methods=["POST"])
def explain():
    data = request.get_json(silent=True) or {}

    # Free-form chat question
    if "question" in data:
        answer = llm_engine.chat(data["question"])
        return jsonify({"explanation": answer})

    # Structured alert explanation
    alert_data = {
        "pattern_type": data.get("pattern_type", "unknown"),
        "ip":           data.get("ip", "unknown"),
        "event_count":  data.get("event_count", 0),
        "severity":     data.get("severity", "medium"),
        "timestamp":    data.get("timestamp", ""),
    }
    result = llm_engine.explain_alert(alert_data)
    return jsonify(result)


# ── /simulate ─────────────────────────────────────────────────────────────
@app.route("/simulate", methods=["POST"])
def simulate():
    data        = request.get_json(silent=True) or {}
    attack_type = data.get("type", "brute_force")

    log = log_generator.trigger(attack_type)
    pattern_detection.ingest(log)
    pattern_detection.force_scan()

    return jsonify({
        "status":      "ok",
        "attack_type": attack_type,
        "log_sample":  log,
        "message":     f"Simulation '{attack_type}' triggered. Check /alerts for results.",
    })


# ── WebSocket events ───────────────────────────────────────────────────────
@socketio.on("connect")
def on_connect():
    emit("connected", {"message": "AegisX WebSocket connected"})


@socketio.on("subscribe")
def on_subscribe(data):
    emit("subscribed", {"channel": data.get("channel", "all")})


# ── Entrypoint ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    startup()
    socketio.run(app, host="0.0.0.0", port=8000, debug=False)
