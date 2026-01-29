import streamlit as st
import sqlite3
import smtplib
import random
import time
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from dotenv import load_dotenv
import os
import bcrypt
import pandas as pd

# project modules
from engine.anomaly_engine import process_event
from engine.response_engine import respond_to_anomaly

# Quantum import
try:
    from auth.quantum_utils import QuantumSecurity
    qs = QuantumSecurity()
except Exception:
    qs = None

# ---- Load .env ----
load_dotenv()
SENDER_EMAIL = os.getenv("SENDER_EMAIL")
SENDER_PASSWORD = os.getenv("SENDER_PASSWORD")

# ---- Role-based config ----
ROLE_CONFIG = {
    "Receptionist": {"allowed_actions": ["read_basic_info", "write_appointment"], "allowed_time": ["00:00-23:59"], "expected_login_frequency_role": 3},
    "OPD Doctor": {"allowed_actions": ["read_prescription", "write_prescription", "read_patient_summary"], "allowed_time": ["08:00-20:00"], "expected_login_frequency_role": 5},
    "OPD Nurse": {"allowed_actions": ["read_vitals", "write_nursing_notes"], "allowed_time": ["08:00-11:00"], "expected_login_frequency_role": 4},
    "Ward Doctor": {"allowed_actions": ["read_treatment_plan", "write_treatment_plan", "admit", "discharge"], "allowed_time": ["00:00-23:59"], "expected_login_frequency_role": 6},
    "Duty Manager": {"allowed_actions": ["monitor_logs", "assign_shift", "read_basic_records"], "allowed_time": ["00:00-23:59"], "expected_login_frequency_role": 4},
    "Lab Technician": {"allowed_actions": ["write_test_result", "read_test_request"], "allowed_time": ["08:00-18:00"], "expected_login_frequency_role": 2},
    "Pathologist": {"allowed_actions": ["read_lab_request", "write_lab_report"], "allowed_time": ["08:00-18:00"], "expected_login_frequency_role": 2},
    "Radiologist": {"allowed_actions": ["write_scan_report"], "allowed_time": ["08:00-20:00"], "expected_login_frequency_role": 3},
    "Imaging Tech": {"allowed_actions": ["capture_image", "tag_metadata"], "allowed_time": ["08:00-18:00"], "expected_login_frequency_role": 2},
    "Pharmacist": {"allowed_actions": ["read_prescription", "dispense_medicine"], "allowed_time": ["00:00-23:59"], "expected_login_frequency_role": 5},
    "Finance Officer": {"allowed_actions": ["view_cost", "create_invoice"], "allowed_time": ["08:00-20:00"], "expected_login_frequency_role": 2},
    "System Admin": {"allowed_actions": ["create_account", "manage_privileges"], "allowed_time": ["00:00-23:59"], "expected_login_frequency_role": 10},
    "Audit Log Monitor": {"allowed_actions": ["view_encrypted_log_metadata"], "allowed_time": ["00:00-23:59"], "expected_login_frequency_role": 1},
    "Hospital Admin": {"allowed_actions": ["view_flagged_anomalies", "approve_role_changes"], "allowed_time": ["08:00-22:00"], "expected_login_frequency_role": 2},
    "Compliance Officer": {"allowed_actions": ["read_encrypted_logs_with_ciso"], "allowed_time": ["09:00-19:00"], "expected_login_frequency_role": 2},
    "CISO": {"allowed_actions": ["decrypt_audit_logs", "manage_qkv"], "allowed_time": ["00:00-23:59"], "expected_login_frequency_role": 3},
    "Quantum AI Anomaly Agent": {"allowed_actions": ["auto_detect_abnormal_access", "alert_admins"], "allowed_time": ["00:00-23:59"], "expected_login_frequency_role": 20},
}

# ---- DB helpers ----
DB = "qshield_live.db"

def init_db():
    """Ensure all required tables exist."""
    with sqlite3.connect(DB, timeout=10, check_same_thread=False) as conn:
        cur = conn.cursor()
        cur.execute("""
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            email TEXT UNIQUE,
            password TEXT,
            role TEXT
        )
        """)
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
    anomaly_level TEXT,
    response_action TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
""")

        cur.execute("""
        CREATE TABLE IF NOT EXISTS blocked_users(
            email TEXT PRIMARY KEY,
            blocked_at TEXT
        )
        """)
        conn.commit()

def get_db_connection():
    return sqlite3.connect(DB, timeout=10, check_same_thread=False)

def safe_execute(query, params=(), fetch=False):
    """Safe execute with retries and ensured tables."""
    init_db()
    for attempt in range(4):
        try:
            with get_db_connection() as conn:
                cur = conn.cursor()
                cur.execute(query, params)
                if fetch:
                    return cur.fetchall()
                conn.commit()
                return
        except sqlite3.OperationalError as e:
            if "locked" in str(e).lower():
                time.sleep(0.5 + attempt * 0.5)
                continue
            raise

def is_blocked(email):
    init_db()
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM blocked_users WHERE email=?", (email,))
        return cur.fetchone() is not None

# 🔹 Compute login frequency dynamically
def compute_login_frequency(email):
    one_hour_ago = (datetime.now() - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
    rows = safe_execute("""
        SELECT COUNT(*) FROM ehr_access_logs 
        WHERE user_id=? AND access_timestamp > ?
    """, (email, one_hour_ago), fetch=True)
    return rows[0][0] if rows else 0

# ---- Utility functions ----
def send_otp(email):
    otp = str(random.randint(100000, 999999))
    if not SENDER_EMAIL or not SENDER_PASSWORD:
        return None, "SMTP credentials not set"
    try:
        msg = MIMEText(f"Your QSHIELD OTP is: {otp}")
        msg["Subject"] = "QSHIELD Login OTP"
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

def hash_password(pw):
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()

def check_password(pw, hashed):
    return bcrypt.checkpw(pw.encode(), hashed.encode())

def is_action_allowed(role, action):
    if role not in ROLE_CONFIG:
        return False
    now = datetime.now().strftime("%H:%M")
    role_data = ROLE_CONFIG[role]
    allowed_actions = role_data.get("allowed_actions", [])
    start, end = role_data.get("allowed_time", ["00:00-23:59"])[0].split("-")
    return action in allowed_actions and start <= now <= end

# ---- Pages ----
def register():
    st.subheader("🔐 Register")
    username = st.text_input("Username", key="reg_username")
    email = st.text_input("Email", key="reg_email")
    password = st.text_input("Password", type="password", key="reg_password")
    role = st.selectbox("Role", list(ROLE_CONFIG.keys()), key="reg_role")
    if st.button("Register"):
        if not username or not email or not password:
            st.error("Please fill all fields.")
            return
        try:
            hashed = hash_password(password)
            safe_execute(
                "INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
                (username, email, hashed, role)
            )
            st.success("✅ Registration successful. Please login.")
        except sqlite3.IntegrityError:
            st.error("Email already registered.")

def login():
    st.subheader("🔑 Login with OTP")

    if st.session_state.get("require_reverify"):
        st.warning("🔐 Please verify your identity again due to unusual activity.")

    email = st.text_input("Email", key="login_email")
    password = st.text_input("Password", type="password", key="login_password")

    if st.button("Send OTP"):
        if not email or not password:
            st.error("Enter email and password.")
            return
        rows = safe_execute("SELECT password, role FROM users WHERE email=?", (email,), fetch=True)
        if not rows:
            st.error("Invalid email or password")
            return

        stored_password, role = rows[0]
        if check_password(password, stored_password):
            if is_blocked(email):
                st.error("🚫 Your account has been blocked by the administrator.")
                return

            otp, status = send_otp(email)
            if otp:
                st.session_state["otp"] = otp
                st.session_state["email"] = email
                st.session_state["verified"] = False
                st.info("OTP sent to your email.")
            else:
                st.error(f"Failed to send OTP: {status}")
        else:
            st.error("Invalid email or password")

    if "otp" in st.session_state:
        user_otp = st.text_input("Enter OTP", key="login_otp")
        if st.button("Verify OTP"):
            if user_otp == st.session_state["otp"]:
                st.session_state["verified"] = True
                st.session_state["user_email"] = st.session_state.get("email")
                st.session_state["menu"] = "Dashboard"
                st.session_state["session_id"] = f"sess_{random.randint(1000,9999)}"
                st.success("✅ Login successful!")
                st.rerun()
            else:
                st.error("❌ Invalid OTP")

def dashboard():
    st.subheader("📊 QSHIELD Role-Based Access Dashboard")

    email = st.session_state.get("user_email") or st.session_state.get("email")
    if not email:
        st.warning("No logged-in user found. Please login.")
        return

    # 🧠 Fetch user role
    role_row = safe_execute("SELECT role FROM users WHERE email=?", (email,), fetch=True)
    role = role_row[0][0] if role_row else "Unknown"
    st.write(f"👤 Logged in as: **{email}** ({role})")

    # 🔹 EHR & Action selection
    ehr_record_id = st.selectbox("Select EHR Record", ["EHR001", "EHR002", "EHR003"], key="ehr_record")
    actions = ROLE_CONFIG.get(role, {}).get("allowed_actions", [])
    action = st.selectbox("Select Action", actions + ["other_action"], key="dashboard_action")

    if "session_start" not in st.session_state:
        st.session_state["session_start"] = datetime.now()

    if st.button("Perform Action"):
        now = datetime.now()
        login_freq = compute_login_frequency(email)
        expected_freq = ROLE_CONFIG.get(role, {}).get("expected_login_frequency_role", 1)

        # ✅ Role-based shift window check
        role_allowed_time = ROLE_CONFIG.get(role, {}).get("allowed_time", ["00:00-23:59"])[0]
        start, end = role_allowed_time.split("-")
        current_time_str = now.strftime("%H:%M")
        login_shift_window = "Yes" if start <= current_time_str <= end else "No"

        # ✅ Event object (includes new columns)
        event = {
            "user_id": email,
            "role": role,
            "department": "General",
            "access_date": now.strftime("%Y-%m-%d"),
            "access_time": now.strftime("%H:%M:%S"),
            "access_timestamp": now.strftime("%Y-%m-%d %H:%M:%S"),
            "access_type": "EHR_ACCESS",
            "action_performed": action,
            "ehr_record_id": ehr_record_id,
            "session_id": st.session_state.get("session_id"),
            "login_shift_window": login_shift_window,
            "login_frequency_last_hour": login_freq,
            "expected_login_frequency_role": expected_freq,
            "previous_access_time": now.strftime("%Y-%m-%d %H:%M:%S"),
            "login_time": now.strftime("%Y-%m-%d %H:%M:%S"),
            "logout_time": None,
            "anomaly_level": None,
            "response_action": None
        }

        # 🧮 Run anomaly detection
        score, flag, explanation, anomaly_level = process_event(event)

        # 🧠 Run adaptive response policy (role-aware)
        risk_action = respond_to_anomaly(email, event["session_id"], score, role)

        # 📝 Update event metadata
        event["anomaly_level"] = anomaly_level
        event["response_action"] = risk_action

        # 💾 Persist updates
        safe_execute(
            "UPDATE ehr_access_logs SET anomaly_level=?, response_action=? WHERE session_id=?",
            (event["anomaly_level"], event["response_action"], event["session_id"])
        )

        # 🎯 Display result
        if flag:
            st.error(f"🚨 Anomaly detected! ({anomaly_level} Risk, Score: {score:.2f})")
        else:
            st.success(f"✅ Action '{action}' normal ({anomaly_level} Risk, Score: {score:.2f})")
        st.caption(f"💡 Explanation: {explanation}")

        # 🧩 Response handling
        st.info(f"🔔 Response Engine Action: {risk_action}")

        if risk_action == "lock":
            st.error("🚨 Your account has been locked. Contact CISO/Admin.")
            st.session_state.clear()
            time.sleep(2)
            st.rerun()

        elif risk_action == "re_otp":
            st.warning("⚠️ Suspicious activity — please verify identity again.")
            user_email = st.session_state.get("user_email", email)
            st.session_state.clear()
            st.session_state["email"] = user_email
            st.session_state["require_reverify"] = True
            time.sleep(2)
            st.rerun()

        # 📜 Recent logs display
        st.divider()
        logs = safe_execute("""
            SELECT id, action_performed, access_timestamp, department,
                   anomaly_level, response_action
            FROM ehr_access_logs
            WHERE user_id=?
            ORDER BY id DESC LIMIT 10
        """, (email,), fetch=True)

        if logs:
            df = pd.DataFrame(logs, columns=[
                "ID", "Action", "Timestamp", "Department",
                "Anomaly Level", "Response Action"
            ])
            st.dataframe(df, use_container_width=True)
        else:
            st.info("No activity logs found.")


# ---- Main UI ----
st.set_page_config(page_title="QSHIELD", page_icon="🛡️", layout="centered")
st.markdown("""
    <h2 style='text-align:center;color:#2C3E50;'>🛡️ QSHIELD</h2>
    <hr style='border:1px solid #E0E0E0;margin-bottom:25px;'>
""", unsafe_allow_html=True)

with st.sidebar:
    st.markdown("### 🔍 Navigation")
    menu_list = ["Register", "Login", "Dashboard"]
    menu = st.radio("", menu_list, index=menu_list.index(st.session_state.get("menu", "Register")), label_visibility="collapsed")

    if st.session_state.get("verified"):
        if st.button("🚪 Logout"):
            try:
                safe_execute(
                    "UPDATE ehr_access_logs SET logout_time=? WHERE session_id=?",
                    (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), st.session_state.get("session_id"))
                )
            except Exception as e:
                st.warning(f"⚠️ Could not record logout time: {e}")

            st.session_state.clear()
            st.success("✅ Logged out successfully!")
            st.rerun()

if menu == "Register":
    register()
elif menu == "Login":
    login()
elif menu == "Dashboard":
    if st.session_state.get("verified"):
        dashboard()
    else:
        st.warning("Please login first.")

# Hide Streamlit UI
st.markdown("""
<style>
#MainMenu {visibility: hidden;}
footer {visibility: hidden;}
header {visibility: hidden;}
</style>
""", unsafe_allow_html=True)
