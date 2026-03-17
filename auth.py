"""
auth.py  —  JWT-backed authentication helpers & Flask Blueprint.

Roles
-----
  individual  : personal account, can see own data
  org_admin   : can add/remove staff, see all org alerts
  org_staff   : read-only access to org alerts

Endpoints (all under /auth prefix):
  POST /auth/signup
  POST /auth/login
  GET  /auth/me
  POST /auth/org/add-staff       (org_admin only)
  POST /auth/org/remove-staff    (org_admin only)
  GET  /auth/org/staff           (org_admin only)
"""

import hashlib
import secrets
from datetime import timedelta
from functools import wraps

from flask import Blueprint, jsonify, request
from flask_jwt_extended import (
    JWTManager, create_access_token, get_jwt_identity,
    jwt_required, get_jwt,
)

from database import get_conn

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


# ── Password helpers (SHA-256 + salt, no external deps) ───────────────────
def _hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"{salt}:{digest}"


def _check_password(stored: str, provided: str) -> bool:
    try:
        salt, digest = stored.split(":", 1)
        return hashlib.sha256((salt + provided).encode()).hexdigest() == digest
    except Exception:
        return False


# ── Role decorator ─────────────────────────────────────────────────────────
def roles_required(*roles):
    def decorator(fn):
        @wraps(fn)
        @jwt_required()
        def wrapper(*args, **kwargs):
            claims = get_jwt()
            if claims.get("user_type") not in roles:
                return jsonify({"error": "Insufficient permissions"}), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator


# ── Signup ─────────────────────────────────────────────────────────────────
@auth_bp.route("/signup", methods=["POST"])
def signup():
    data      = request.get_json(silent=True) or {}
    email     = (data.get("email") or "").strip().lower()
    password  = data.get("password") or ""
    name      = (data.get("name") or email.split("@")[0]).strip()
    user_type = data.get("user_type", "individual")   # individual | org_admin
    org_name  = (data.get("org_name") or "").strip()

    if not email or not password:
        return jsonify({"error": "email and password are required"}), 400
    if len(password) < 6:
        return jsonify({"error": "password must be at least 6 characters"}), 400
    if user_type not in ("individual", "org_admin"):
        return jsonify({"error": "user_type must be individual or org_admin"}), 400

    conn = get_conn()
    try:
        # Check duplicate
        row = conn.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
        if row:
            return jsonify({"error": "Email already registered"}), 409

        org_id = None
        if user_type == "org_admin":
            if not org_name:
                return jsonify({"error": "org_name required for org_admin signup"}), 400
            cur = conn.execute(
                "INSERT INTO organisations (name) VALUES (?)", (org_name,)
            )
            org_id = cur.lastrowid

        conn.execute(
            "INSERT INTO users (email, name, password, user_type, org_id) VALUES (?,?,?,?,?)",
            (email, name, _hash_password(password), user_type, org_id),
        )
        conn.commit()

        uid = conn.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()["id"]
        token = create_access_token(
            identity=str(uid),
            additional_claims={"user_type": user_type, "org_id": org_id},
            expires_delta=timedelta(days=7),
        )
        return jsonify({
            "token":     token,
            "user":      {"id": uid, "name": name, "email": email,
                          "user_type": user_type, "org_id": org_id},
        }), 201
    finally:
        conn.close()


# ── Login ──────────────────────────────────────────────────────────────────
@auth_bp.route("/login", methods=["POST"])
def login():
    data     = request.get_json(silent=True) or {}
    email    = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    # Demo shortcut
    if email == "demo@aegisx.ai":
        token = create_access_token(
            identity="0",
            additional_claims={"user_type": "org_admin", "org_id": 0},
            expires_delta=timedelta(days=1),
        )
        return jsonify({
            "token": token,
            "user":  {"id": 0, "name": "Demo User", "email": email,
                      "user_type": "org_admin", "org_id": 0},
        })

    if not email or not password:
        return jsonify({"error": "email and password are required"}), 400

    conn = get_conn()
    try:
        row = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if not row or not _check_password(row["password"], password):
            return jsonify({"error": "Invalid credentials"}), 401

        token = create_access_token(
            identity=str(row["id"]),
            additional_claims={"user_type": row["user_type"], "org_id": row["org_id"]},
            expires_delta=timedelta(days=7),
        )
        return jsonify({
            "token": token,
            "user":  {
                "id":        row["id"],
                "name":      row["name"],
                "email":     row["email"],
                "user_type": row["user_type"],
                "org_id":    row["org_id"],
            },
        })
    finally:
        conn.close()


# ── /me ────────────────────────────────────────────────────────────────────
@auth_bp.route("/me", methods=["GET"])
@jwt_required()
def me():
    uid  = get_jwt_identity()
    conn = get_conn()
    try:
        row = conn.execute("SELECT id,name,email,user_type,org_id FROM users WHERE id=?",
                           (uid,)).fetchone()
        if not row:
            return jsonify({"error": "User not found"}), 404
        return jsonify(dict(row))
    finally:
        conn.close()


# ── Admin: list staff ──────────────────────────────────────────────────────
@auth_bp.route("/org/staff", methods=["GET"])
@roles_required("org_admin")
def list_staff():
    claims = get_jwt()
    org_id = claims.get("org_id")
    conn   = get_conn()
    try:
        rows = conn.execute(
            "SELECT id,name,email,user_type,created_at FROM users WHERE org_id=? AND user_type='org_staff'",
            (org_id,),
        ).fetchall()
        return jsonify([dict(r) for r in rows])
    finally:
        conn.close()


# ── Admin: add staff ───────────────────────────────────────────────────────
@auth_bp.route("/org/add-staff", methods=["POST"])
@roles_required("org_admin")
def add_staff():
    claims   = get_jwt()
    org_id   = claims.get("org_id")
    data     = request.get_json(silent=True) or {}
    email    = (data.get("email") or "").strip().lower()
    password = data.get("password") or secrets.token_urlsafe(12)
    name     = data.get("name") or email.split("@")[0]

    if not email:
        return jsonify({"error": "email required"}), 400

    conn = get_conn()
    try:
        if conn.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone():
            return jsonify({"error": "Email already exists"}), 409
        conn.execute(
            "INSERT INTO users (email, name, password, user_type, org_id) VALUES (?,?,?,?,?)",
            (email, name, _hash_password(password), "org_staff", org_id),
        )
        conn.commit()
        return jsonify({"message": f"Staff member {email} added", "temp_password": password}), 201
    finally:
        conn.close()


# ── Admin: remove staff ────────────────────────────────────────────────────
@auth_bp.route("/org/remove-staff", methods=["POST"])
@roles_required("org_admin")
def remove_staff():
    claims  = get_jwt()
    org_id  = claims.get("org_id")
    data    = request.get_json(silent=True) or {}
    user_id = data.get("user_id")

    if not user_id:
        return jsonify({"error": "user_id required"}), 400

    conn = get_conn()
    try:
        row = conn.execute(
            "SELECT id FROM users WHERE id=? AND org_id=? AND user_type='org_staff'",
            (user_id, org_id),
        ).fetchone()
        if not row:
            return jsonify({"error": "Staff member not found in your org"}), 404
        conn.execute("DELETE FROM users WHERE id=?", (user_id,))
        conn.commit()
        return jsonify({"message": "Staff member removed"})
    finally:
        conn.close()
