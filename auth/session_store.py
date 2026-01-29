"""
session_store.py
----------------
Stores verified login sessions after OTP validation.
"""

import sqlite3
from datetime import datetime, timedelta

DB = "./data/qshield_mvp.db"

def _get_conn():
    return sqlite3.connect(DB)

def init_session_table():
    conn = _get_conn()
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            user_id TEXT,
            created_at TEXT,
            expires_at TEXT,
            active INTEGER DEFAULT 1
        )
    """)
    conn.commit()
    conn.close()

def create_session(user_id, session_id, ttl_minutes=60):
    conn = _get_conn()
    c = conn.cursor()
    now = datetime.utcnow()
    expires = now + timedelta(minutes=ttl_minutes)
    c.execute(
        "INSERT INTO sessions (session_id, user_id, created_at, expires_at, active) VALUES (?, ?, ?, ?, 1)",
        (session_id, user_id, now.isoformat(), expires.isoformat())
    )
    conn.commit()
    conn.close()

def is_session_valid(session_id):
    conn = _get_conn()
    c = conn.cursor()
    c.execute("SELECT expires_at, active FROM sessions WHERE session_id=?", (session_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return False
    expires_at, active = row
    if not active:
        return False
    from datetime import datetime
    return datetime.fromisoformat(expires_at) > datetime.utcnow()
