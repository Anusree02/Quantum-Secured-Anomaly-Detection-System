"""
response_engine.py
-------------------
Enhanced multi-level, role-aware security response for QSHIELD.
Integrates adaptive thresholds per role for granular control.
Now logs response_action and logout_time for all relevant events.
"""

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import sqlite3
from datetime import datetime, timezone
import os
from dotenv import load_dotenv

# ---------- Load Environment ----------
load_dotenv()
DB = "./qshield_live.db"

SENDER_EMAIL = os.getenv("SMTP_SENDER_EMAIL", "youremail@gmail.com")
SENDER_PASS = os.getenv("SMTP_APP_PASSWORD", "your_app_password")
ADMIN_EMAIL = os.getenv("SECURITY_ADMIN_EMAIL", "admin@example.com")
CISO_EMAIL = os.getenv("CISO_EMAIL", "ciso@example.com")


# ---------- DB Helpers ----------
def _get_conn():
    return sqlite3.connect(DB, timeout=10, check_same_thread=False)


def mark_logout_time(session_id: str):
    """Mark logout_time when session is forcibly ended."""
    with _get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            UPDATE ehr_access_logs
            SET logout_time = ?
            WHERE session_id = ? AND logout_time IS NULL
        """, (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), session_id))
        conn.commit()
    print(f"🕒 Logout time recorded for session {session_id}")


def mark_session_locked(session_id: str):
    """Lock a session when a critical anomaly occurs."""
    with _get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS locked_sessions (
                session_id TEXT PRIMARY KEY,
                locked_at TEXT
            )
        """)
        cur.execute(
            "INSERT OR REPLACE INTO locked_sessions (session_id, locked_at) VALUES (?, ?)",
            (session_id, datetime.now(timezone.utc).isoformat())
        )
        conn.commit()
    print(f"🔒 Session {session_id} locked.")


def block_user(user_email: str):
    """Add user to a blocked list until CISO/Admin unblocks."""
    with _get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS blocked_users (
                email TEXT PRIMARY KEY,
                blocked_at TEXT
            )
        """)
        cur.execute(
            "INSERT OR REPLACE INTO blocked_users (email, blocked_at) VALUES (?, ?)",
            (user_email, datetime.now(timezone.utc).isoformat())
        )
        conn.commit()
    print(f"🚫 User {user_email} blocked due to critical anomaly.")


def update_response_action(session_id: str, action: str):
    """Store the final response action (log_only / notify / re_otp / lock)."""
    with _get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            UPDATE ehr_access_logs
            SET response_action = ?
            WHERE session_id = ?
        """, (action, session_id))
        conn.commit()
    print(f"🗂️ Recorded response action '{action}' for session {session_id}")


# ---------- Email Utility ----------
def send_email_notification(to_email: str, subject: str, body: str):
    msg = MIMEMultipart()
    msg["From"] = SENDER_EMAIL
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(SENDER_EMAIL, SENDER_PASS)
            server.send_message(msg)
        print(f"📧 Notification sent to {to_email}")
    except Exception as e:
        print(f"⚠️ Failed to send email to {to_email}: {e}")


# ---------- Role-based Risk Policy ----------
ROLE_RESPONSE_POLICY = {
    # stricter roles
    "OPD Nurse": {"lock": 0.75, "re_otp": 0.6, "notify": 0.4},
    "Finance Officer": {"lock": 0.8, "re_otp": 0.6, "notify": 0.4},
    "Imaging Tech": {"lock": 0.75, "re_otp": 0.55, "notify": 0.4},
    # moderate-risk roles
    "Pathologist": {"lock": 0.85, "re_otp": 0.7, "notify": 0.4},
    "Radiologist": {"lock": 0.85, "re_otp": 0.7, "notify": 0.4},
    "OPD Doctor": {"lock": 0.8, "re_otp": 0.75, "notify": 0.4},
    "Hospital Admin": {"lock": 0.85, "re_otp": 0.7, "notify": 0.4},
    "Compliance Officer": {"lock": 0.85, "re_otp": 0.7, "notify": 0.4},
    # low-risk or 24x7 roles
    "Receptionist": {"lock": 0.95, "re_otp": 0.75, "notify": 0.5},
    "System Admin": {"lock": 0.95, "re_otp": 0.8, "notify": 0.5},
    "Duty Manager": {"lock": 0.95, "re_otp": 0.8, "notify": 0.5},
    "CISO": {"lock": 1.0, "re_otp": 0.9, "notify": 0.5},
    "Quantum AI Anomaly Agent": {"lock": 1.0, "re_otp": 0.9, "notify": 0.5},
    "DEFAULT": {"lock": 0.9, "re_otp": 0.7, "notify": 0.4}
}


# ---------- Response Engine ----------
def respond_to_anomaly(user_email: str, session_id: str, risk_score: float, role: str = None):
    """
    Handles 4-tier risk logic with role-based thresholds (correct order):
      - risk_score >= lock    : CRITICAL  -> block + alert CISO
      - risk_score >= re_otp   : HIGH      -> suspend session + re-OTP
      - risk_score >= notify   : MEDIUM    -> notify user + admin
      - else                   : LOW       -> log only

    Returns one of: "log_only", "notify", "re_otp", "lock"
    """
    policy = ROLE_RESPONSE_POLICY.get(role, ROLE_RESPONSE_POLICY["DEFAULT"])
    print(f"🧠 Role Policy Applied for {role}: {policy} | Risk Score: {risk_score:.4f}")

    # --- Critical / Block ---
    if risk_score >= policy["lock"]:
        # Critical risk — block user + lock session
        block_user(user_email)
        mark_session_locked(session_id)
        mark_logout_time(session_id)
        update_response_action(session_id, "lock")

        send_email_notification(
            user_email,
            "QSHIELD: Account Locked",
            f"Dear user,\n\nYour account has been locked due to a critical anomaly. "
            f"Please contact the security team for reactivation.\n\n- QSHIELD Security"
        )
        send_email_notification(
            CISO_EMAIL,
            f"[CRITICAL] User {user_email} Blocked by QSHIELD",
            f"User: {user_email}\nRole: {role}\nRisk Score: {risk_score}\nSession: {session_id}\nAction: BLOCKED"
        )
        print("🚨 Critical risk — user blocked, logout recorded, CISO alerted.")
        return "lock"

    # --- High / Re-OTP ---
    if risk_score >= policy["re_otp"]:
        subject = "QSHIELD: Re-verification Required"
        body = (
            f"Dear user,\n\n"
            f"Suspicious activity detected in your session ({session_id}). "
            f"Your session has been suspended temporarily. Please log in again using OTP verification.\n\n"
            f"- QSHIELD Security"
        )
        send_email_notification(user_email, subject, body)
        send_email_notification(
            ADMIN_EMAIL,
            f"[ALERT] High Risk Access - Reverification Triggered for {user_email}",
            f"User: {user_email}\nRole: {role}\nRisk Score: {risk_score}\nSession: {session_id}\nAction: Re-OTP Required"
        )
        mark_logout_time(session_id)
        update_response_action(session_id, "re_otp")
        print("🚪 High risk — session suspended, re-verification triggered.")
        return "re_otp"

    # --- Medium / Notify ---
    if risk_score >= policy["notify"]:
        subject = "QSHIELD: Unusual Access Pattern Detected"
        body = (
            f"Dear user,\n\n"
            f"We detected an unusual access pattern in your session ({session_id}). "
            f"If this was not you, please contact your administrator immediately.\n\n"
            f"- QSHIELD Security"
        )
        send_email_notification(user_email, subject, body)
        send_email_notification(
            ADMIN_EMAIL,
            f"[ALERT] Medium Risk Access Detected for {user_email}",
            f"User: {user_email}\nRole: {role}\nRisk Score: {risk_score}\nSession: {session_id}\nAction: Notify"
        )
        update_response_action(session_id, "notify")
        print("⚠️ Medium risk — user and admin notified.")
        return "notify"

    # --- Low / Log only ---
    update_response_action(session_id, "log_only")
    print("✅ Low risk event — logged silently.")
    return "log_only"

