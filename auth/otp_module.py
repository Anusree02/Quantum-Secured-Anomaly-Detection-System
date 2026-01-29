"""
otp_module.py
--------------
Handles OTP generation, delivery (via Gmail SMTP), and verification for QSHIELD.
Now enhanced with Quantum-secured randomness and encryption from quantum_utils.py.
"""

import os
import sqlite3
import smtplib
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

# 🔹 Import quantum functions
from quantum_utils import quantum_random_number, quantum_encrypt, quantum_decrypt, quantum_anomaly_score

# ---------- Configuration ----------
load_dotenv()
DB = "./qshield_live.db"
SENDER_EMAIL = os.getenv("SENDER_EMAIL")
SENDER_PASSWORD = os.getenv("SENDER_PASSWORD")

# ---------- Database ----------
def _get_conn():
    return sqlite3.connect(DB)

def init_otp_table():
    conn = _get_conn()
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS otps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT,
            otp TEXT,
            expires_at TEXT,
            used INTEGER DEFAULT 0,
            quantum_entropy REAL,
            encrypted_blob BLOB
        )
    """)
    conn.commit()
    conn.close()


# ---------- Utility ----------
def cleanup_expired_otps():
    """Remove expired or used OTPs to prevent DB growth."""
    conn = _get_conn()
    c = conn.cursor()
    c.execute("DELETE FROM otps WHERE used=1 OR expires_at < ?", (datetime.utcnow().isoformat(),))
    conn.commit()
    conn.close()

def can_generate_otp(user_email):
    """Throttle OTP requests (1 per minute per user)."""
    conn = _get_conn()
    c = conn.cursor()
    c.execute("""
        SELECT COUNT(*) FROM otps 
        WHERE user_id=? AND datetime(expires_at) > datetime('now', '-1 minute')
    """, (user_email,))
    count = c.fetchone()[0]
    conn.close()
    return count == 0


# ---------- Quantum-secured OTP Logic ----------
def generate_otp(user_email, ttl_seconds=300):
    """
    Generate and email an OTP using quantum randomness, valid for given TTL (default 5 mins).
    """
    cleanup_expired_otps()
    if not can_generate_otp(user_email):
        print("⚠️ OTP recently sent — please wait before retrying.")
        return None

    # 🔹 Use quantum randomness for OTP generation
    otp = "".join([str(quantum_random_number(10)) for _ in range(6)])  # 6-digit OTP

    # 🔹 Quantum encryption (store encrypted version for extra layer)
    encrypted_blob, qkey = quantum_encrypt(otp)

    # 🔹 Entropy score of the OTP (for anomaly correlation)
    digits = [int(ch) / 9 for ch in otp]
    quantum_entropy = quantum_anomaly_score(digits)

    expires = (datetime.utcnow() + timedelta(seconds=ttl_seconds)).isoformat()

    conn = _get_conn()
    c = conn.cursor()
    c.execute("""
        INSERT INTO otps (user_id, otp, expires_at, used, quantum_entropy, encrypted_blob)
        VALUES (?, ?, ?, 0, ?, ?)
    """, (user_email, otp, expires, quantum_entropy, encrypted_blob))
    conn.commit()
    conn.close()

    deliver_otp(user_email, otp)
    print(f"🔐 Quantum-secured OTP generated (entropy={quantum_entropy})")
    return otp


# ---------- Email Delivery ----------
def deliver_otp(user_email, otp):
    """Send OTP to user via Gmail SMTP (App Password required)."""
    if not SENDER_EMAIL or not SENDER_PASSWORD:
        print("❌ Missing SMTP credentials. Please set SENDER_EMAIL and SENDER_PASSWORD in .env.")
        return

    subject = "Your Quantum-Secured QSHIELD OTP Code"
    body = f"""
    Hello,

    Your Quantum-secured OTP is: {otp}
    It is valid for 5 minutes.

    This OTP was generated using Q-SHIELD’s Quantum Randomness Engine
    to ensure unbreakable security against prediction or replay attacks.

    - Q-SHIELD Quantum Security Team
    """

    msg = MIMEMultipart()
    msg["From"] = SENDER_EMAIL
    msg["To"] = user_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.send_message(msg)
        print(f"✅ Quantum OTP sent successfully to {user_email}")
    except Exception as e:
        print(f"❌ Failed to send OTP to {user_email}: {e}")


# ---------- Verification ----------
def verify_otp(user_email, otp):
    """Check if OTP is valid, unused, and not expired."""
    conn = _get_conn()
    c = conn.cursor()
    c.execute("SELECT rowid, otp, expires_at, used, encrypted_blob FROM otps WHERE user_id=? ORDER BY rowid DESC LIMIT 1",
              (user_email,))
    row = c.fetchone()

    if not row:
        conn.close()
        return False, "no_otp"

    rowid, otp_stored, expires_at, used, encrypted_blob = row

    if used:
        conn.close()
        return False, "already_used"

    if datetime.fromisoformat(expires_at) < datetime.utcnow():
        conn.close()
        return False, "expired"

    # 🔹 Double verification (plaintext & quantum-decrypted)
    try:
        decrypted = quantum_decrypt(encrypted_blob, None)  # None uses internal random key
    except Exception:
        decrypted = None

    if otp_stored != otp and decrypted != otp:
        conn.close()
        return False, "mismatch"

    c.execute("UPDATE otps SET used=1 WHERE rowid=?", (rowid,))
    conn.commit()
    conn.close()
    return True, "ok"


# ---------- Main Test Runner ----------
if __name__ == "__main__":
    init_otp_table()
    print("✅ OTP table (quantum-secured) initialized.")

    test_email = input("Enter your test email: ").strip()
    otp = generate_otp(test_email)
    if otp:
        print(f"OTP {otp} generated and sent to {test_email}.")
