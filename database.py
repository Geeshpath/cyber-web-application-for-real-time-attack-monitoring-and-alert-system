"""
database.py  —  SQLite schema & helper functions for AegisX
"""

import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "aegisx.db")


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_conn()
    c = conn.cursor()

    # ── Users ────────────────────────────────────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            email       TEXT    UNIQUE NOT NULL,
            name        TEXT    NOT NULL,
            password    TEXT    NOT NULL,
            user_type   TEXT    NOT NULL DEFAULT 'individual',  -- individual | org_admin | org_staff
            org_id      INTEGER,
            created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
        )
    """)

    # ── Organisations ────────────────────────────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS organisations (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            name       TEXT    NOT NULL,
            created_at TEXT    NOT NULL DEFAULT (datetime('now'))
        )
    """)

    # ── Logs ─────────────────────────────────────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            ip         TEXT    NOT NULL,
            timestamp  TEXT    NOT NULL,
            event_type TEXT    NOT NULL,
            location   TEXT    NOT NULL,
            user_id    TEXT,
            port       INTEGER,
            status     TEXT,
            extra      TEXT,
            created_at TEXT    NOT NULL DEFAULT (datetime('now'))
        )
    """)

    # ── Alerts ───────────────────────────────────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            ip           TEXT    NOT NULL,
            pattern_type TEXT    NOT NULL,
            severity     TEXT    NOT NULL,
            score        INTEGER NOT NULL,
            event_count  INTEGER NOT NULL,
            explanation  TEXT,
            mitigation   TEXT,
            timestamp    TEXT    NOT NULL DEFAULT (datetime('now'))
        )
    """)

    conn.commit()
    conn.close()
    print("[DB] Schema initialised →", DB_PATH)
