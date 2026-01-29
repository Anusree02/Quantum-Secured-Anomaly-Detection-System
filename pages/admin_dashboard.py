import streamlit as st
import os
import pandas as pd
import sqlite3
from datetime import datetime
from dotenv import load_dotenv, find_dotenv
import smtplib, random
from email.mime.text import MIMEText
import base64
from io import StringIO


# Quantum imports (optional)
try:
    from auth.quantum_utils import quantum_encrypt, quantum_decrypt, generate_quantum_key
except Exception:
    quantum_encrypt = quantum_decrypt = generate_quantum_key = None

# Load environment
load_dotenv(find_dotenv())
ADMIN_EMAIL_ENV = os.getenv("SECURITY_ADMIN_EMAIL")
ADMIN_PWD_ENV = os.getenv("SECURITY_ADMIN_PASSWORD")
SENDER_EMAIL = os.getenv("SENDER_EMAIL")
SENDER_PASSWORD = os.getenv("SENDER_PASSWORD")
DB = os.getenv("DB_PATH", "qshield_live.db")

# ------------------ SMTP OTP ------------------
def send_otp(email, purpose="Admin Login"):
    otp = str(random.randint(100000, 999999))
    if not SENDER_EMAIL or not SENDER_PASSWORD:
        return None, "SMTP credentials missing"
    try:
        msg = MIMEText(f"Your QSHIELD OTP for {purpose} is: {otp}")
        msg["Subject"] = f"QSHIELD OTP - {purpose}"
        msg["From"] = SENDER_EMAIL
        msg["To"] = email
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.send_message(msg)
        server.quit()
        return otp, "sent"
    except Exception as e:
        return None, str(e)

# ------------------ DB Helpers ------------------
def get_conn():
    return sqlite3.connect(DB, timeout=10, check_same_thread=False)

def fetch_logs(limit=200):
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
        CREATE TABLE IF NOT EXISTS ehr_access_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT,
            role TEXT,
            department TEXT,
            access_timestamp TEXT,
            access_type TEXT,
            action_performed TEXT,
            ehr_record_id TEXT,
            login_shift_window TEXT,
            login_frequency_last_hour INTEGER,
            previous_access_time TEXT,
            session_id TEXT,
            login_time TEXT,
            logout_time TEXT,
            anomaly_level TEXT,             -- NEW COLUMN
            response_action TEXT,           -- NEW COLUMN
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)

        cur.execute("SELECT * FROM ehr_access_logs ORDER BY id DESC LIMIT ?", (limit,))
        rows = cur.fetchall()

    cols = [
    "id", "user_id", "role", "department", "access_timestamp",
    "access_type", "action_performed", "ehr_record_id",
    "login_shift_window", "login_frequency_last_hour",
    "previous_access_time", "session_id", "login_time", "logout_time",
    "anomaly_level", "response_action", "created_at" # ✅ New columns
]

    return pd.DataFrame(rows, columns=cols)



def block_user_db(email):
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""CREATE TABLE IF NOT EXISTS blocked_users(email TEXT PRIMARY KEY, blocked_at TEXT)""")
        cur.execute("INSERT OR REPLACE INTO blocked_users VALUES (?, ?)", (email, datetime.utcnow().isoformat()))
        conn.commit()

def unblock_user_db(email):
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM blocked_users WHERE email=?", (email,))
        conn.commit()

def is_blocked(email):
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM blocked_users WHERE email=?", (email,))
        return cur.fetchone() is not None

def fetch_blocked_users():
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""CREATE TABLE IF NOT EXISTS blocked_users(email TEXT PRIMARY KEY, blocked_at TEXT)""")
        cur.execute("SELECT email, blocked_at FROM blocked_users ORDER BY blocked_at DESC")
        rows = cur.fetchall()
    return [{"email": r[0], "blocked_at": r[1]} for r in rows]

# ------------------ Streamlit UI ------------------
st.set_page_config(page_title="QSHIELD - Admin Dashboard", layout="wide")
st.title("🛡️ QSHIELD — Admin / CISO Dashboard")

# Session setup
if "admin_verified" not in st.session_state:
    st.session_state["admin_verified"] = False

# ========== LOGIN WITH OTP ==========
if not st.session_state["admin_verified"]:
    st.subheader("🔐 Admin Login (Email + Password + OTP)")
    admin_email = st.text_input("Admin Email", value=ADMIN_EMAIL_ENV or "", key="admin_email")
    admin_password = st.text_input("Admin Password", type="password", key="admin_password")

    if st.button("Send OTP"):
        if admin_email == ADMIN_EMAIL_ENV and admin_password == ADMIN_PWD_ENV:
            otp, status = send_otp(admin_email, "Admin Login Verification")
            if otp:
                st.session_state["admin_otp"] = otp
                st.success("✅ OTP sent to your registered admin email.")
            else:
                st.error(f"Failed to send OTP: {status}")
        else:
            st.error("❌ Invalid email or password")

    if "admin_otp" in st.session_state:
        entered_otp = st.text_input("Enter OTP", key="entered_admin_otp")
        if st.button("Verify & Login"):
            if entered_otp == st.session_state["admin_otp"]:
                st.session_state["admin_verified"] = True
                st.session_state.pop("admin_otp", None)
                st.success("✅ OTP verified. Admin logged in.")
                st.rerun()
            else:
                st.error("❌ Invalid OTP entered")
    st.stop()

# ========== AFTER VERIFIED ==========
st.success(f"✅ Logged in as {ADMIN_EMAIL_ENV}")
st.subheader("📂 Encrypted EHR Logs")

# Encrypt logs automatically
if "encrypted_logs_blob" not in st.session_state or st.button("🔄 Refresh Logs"):
    df = fetch_logs()
    csv = df.to_csv(index=False)

    try:
        key = generate_quantum_key() if generate_quantum_key else base64.urlsafe_b64encode(os.urandom(32))
    except Exception:
        key = base64.urlsafe_b64encode(os.urandom(32))

    try:
        if quantum_encrypt:
            encrypted, qkey = quantum_encrypt(csv, key)
        else:
            from cryptography.fernet import Fernet
            f = Fernet(key)
            encrypted = f.encrypt(csv.encode())
            qkey = key
        st.session_state["encrypted_logs_blob"] = encrypted
        st.session_state["encrypted_logs_key"] = qkey
    except Exception as e:
        st.error(f"Encryption failed: {e}")
        st.stop()

st.code(str(st.session_state.get("encrypted_logs_blob"))[:500] + "...", language=None)

# ========== DECRYPT WITH OTP ==========
st.subheader("🔐 Decrypt Logs")

if "decrypt_stage" not in st.session_state:
    st.session_state["decrypt_stage"] = "idle"

if st.session_state["decrypt_stage"] == "idle":
    if st.button("Send OTP for Decryption"):
        otp, status = send_otp(ADMIN_EMAIL_ENV, "Decrypt Logs")
        if otp:
            st.session_state["decrypt_otp"] = otp
            st.session_state["decrypt_stage"] = "otp_sent"
            st.success("✅ OTP sent to admin email.")
            st.rerun()
        else:
            st.error(f"Failed to send OTP: {status}")

elif st.session_state["decrypt_stage"] == "otp_sent":
    entered_otp = st.text_input("Enter OTP to decrypt logs", key="entered_dec_otp")
    if st.button("Verify & Decrypt"):
        if entered_otp == st.session_state.get("decrypt_otp"):
            try:
                key = st.session_state.get("encrypted_logs_key")
                enc = st.session_state.get("encrypted_logs_blob")

                if quantum_decrypt:
                    plain = quantum_decrypt(enc, key)
                else:
                    from cryptography.fernet import Fernet
                    f = Fernet(key)
                    plain = f.decrypt(enc).decode()

                df = pd.read_csv(StringIO(plain))
                st.session_state["decrypted_logs_df"] = df
                st.success("✅ Logs decrypted successfully.")
                st.session_state["decrypt_stage"] = "done"
                st.session_state.pop("decrypt_otp", None)
                st.rerun()
            except Exception as e:
                st.error(f"Decryption failed: {e}")
        else:
            st.error("❌ Invalid OTP entered")

# ========== SHOW DECRYPTED LOGS ==========
if st.session_state.get("decrypt_stage") == "done" and "decrypted_logs_df" in st.session_state:
    df = st.session_state["decrypted_logs_df"]
    st.subheader("📜 Decrypted Logs")

    col1, col2, col3 = st.columns([3, 2, 2])
    search = col1.text_input("🔍 Search (user_id/action/role)")
    suspicious_only = col2.checkbox("Show only possible anomalies")
    sort_order = col3.radio("Sort by date", ["Newest", "Oldest"], horizontal=True)

    # Safe filtering (column existence check)
    if suspicious_only and "flag" in df.columns:
        df = df[df["flag"] == 1]
    elif suspicious_only and "access_result" in df.columns:
        df = df[df["access_result"].str.lower() != "normal"]

    if search:
        q = search.lower()
        df = df[df.apply(lambda x:
            q in str(x.get("user_id", "")).lower() or
            q in str(x.get("action_performed", "")).lower() or
            q in str(x.get("role", "")).lower(),
            axis=1
        )]

    if "access_timestamp" in df.columns:
        df = df.sort_values("access_timestamp", ascending=(sort_order == "Oldest"))
    elif "created_at" in df.columns:
        df = df.sort_values("created_at", ascending=(sort_order == "Oldest"))

    st.dataframe(df, use_container_width=True)

    # ------------------------------
    # ✅ Cleaned: Show only blocked users list with Unblock buttons
    # ------------------------------
    st.markdown("### 🔒 Currently Blocked Users")
    blocked = fetch_blocked_users()
    if not blocked:
        st.info("No users are currently blocked.")
    else:
        st.write("Below are the users currently blocked from system access:")
        for entry in blocked:
            email = entry["email"]
            blocked_at = entry.get("blocked_at", "")
            cols = st.columns([4, 3, 1])
            cols[0].markdown(f"**{email}**")
            cols[1].markdown(f"Blocked at: `{blocked_at}`")
            btn_key = f"unblock_{email}_{blocked_at}"
            if cols[2].button("Unblock", key=btn_key):
                try:
                    unblock_user_db(email)
                    st.success(f"✅ {email} unblocked successfully.")
                except Exception as e:
                    st.error(f"Failed to unblock {email}: {e}")
                st.rerun()
