"""
anomaly_engine.py
-----------------
Role-aware hybrid anomaly detection for QSHIELD.
Adds role-specific shift violation policies, weighted risk scoring,
and integrates quantum uncertainty for adaptive risk calibration.
"""

import sqlite3
from datetime import datetime
from auth.quantum_utils import QuantumSecurity

DB = "./qshield_live.db"


# ---------- DB Connection ----------
def _get_conn():
    return sqlite3.connect(DB, timeout=10, check_same_thread=False)


# ---------- Role-based Behavioral Baselines ----------
ROLE_BEHAVIOR = {
    # Doctors & Nurses
    "OPD Doctor": {"expected_logins_hour": 3, "expected_duration": (300, 900)},     # 5–15 min
    "Ward Doctor": {"expected_logins_hour": 6, "expected_duration": (300, 900)},
    "OPD Nurse": {"expected_logins_hour": 4, "expected_duration": (30, 300)},        # 0.5–5 min
    "Duty Manager": {"expected_logins_hour": 4, "expected_duration": (60, 600)},

    # Diagnostics & Labs
    "Lab Technician": {"expected_logins_hour": 6, "expected_duration": (60, 480)},
    "Pathologist": {"expected_logins_hour": 5, "expected_duration": (60, 600)},
    "Radiologist": {"expected_logins_hour": 3, "expected_duration": (120, 900)},
    "Imaging Tech": {"expected_logins_hour": 4, "expected_duration": (60, 480)},

    # Admin & Operations
    "Receptionist": {"expected_logins_hour": 10, "expected_duration": (20, 180)},
    "Hospital Admin": {"expected_logins_hour": 5, "expected_duration": (120, 600)},
    "Finance Officer": {"expected_logins_hour": 4, "expected_duration": (120, 600)},
    "System Admin": {"expected_logins_hour": 2, "expected_duration": (300, 1800)},
    "Audit Log Monitor": {"expected_logins_hour": 3, "expected_duration": (120, 600)},
    "Compliance Officer": {"expected_logins_hour": 3, "expected_duration": (120, 600)},
    "CISO": {"expected_logins_hour": 2, "expected_duration": (300, 1800)},

    # Security & AI
    "Quantum AI Anomaly Agent": {"expected_logins_hour": 2, "expected_duration": (60, 300)},

    # Pharmacy
    "Pharmacist": {"expected_logins_hour": 5, "expected_duration": (60, 600)},
}


# ---------- Role–Action Matrix ----------
ROLE_ACTION_MATRIX = {
    # Medical roles
    "OPD Doctor": ["read_prescription", "write_prescription", "read_patient_summary"],
    "Ward Doctor": ["read_patient_summary", "update_progress_notes", "write_prescription"],
    "OPD Nurse": ["read_vitals", "write_nursing_notes"],
    "Duty Manager": ["approve_shift", "allocate_staff"],

    # Diagnostics & Labs
    "Lab Technician": ["record_lab_results", "update_lab_status"],
    "Pathologist": ["review_lab_results", "signoff_report"],
    "Radiologist": ["write_scan_report", "upload_scan"],
    "Imaging Tech": ["capture_scan", "upload_image"],

    # Administrative & Operations
    "Receptionist": ["read_basic_info", "write_appointment", "update_schedule"],
    "Hospital Admin": ["view_all_departments", "assign_roles", "approve_leave"],
    "Finance Officer": ["view_cost", "create_invoice", "approve_payment"],
    "System Admin": ["create_account", "manage_privileges", "reset_password"],
    "Audit Log Monitor": ["view_logs", "export_audit_report"],
    "Compliance Officer": ["review_access_logs", "approve_policy_exception"],
    "CISO": ["override_security_policies", "block_user", "unblock_user"],
    "Quantum AI Anomaly Agent": ["monitor_anomaly", "calibrate_thresholds"],

    # Pharmacy
    "Pharmacist": ["read_prescription", "dispense_medicine"],
}


# ---------- Shift Violation Policy ----------
# Defines how off-shift activity is treated per role
# ---------- Shift Violation Policy ----------
# Defines how off-shift activity contributes to risk per role
SHIFT_POLICY = {
    "Receptionist": 0.0,
    "OPD Doctor": 0.15,
    "OPD Nurse": 0.30,
    "Ward Doctor": 0.0,
    "Duty Manager": 0.0,
    "Lab Technician": 0.15,
    "Pathologist": 0.25,
    "Radiologist": 0.25,
    "Imaging Tech": 0.30,
    "Pharmacist": 0.0,
    "Finance Officer": 0.30,
    "System Admin": 0.0,
    "Audit Log Monitor": 0.0,
    "Hospital Admin": 0.25,
    "Compliance Officer": 0.25,
    "CISO": 0.0,
    "Quantum AI Anomaly Agent": 0.0,
}


# ---------- Classical Rule-Based Scoring ----------
def compute_classical_score(event):
    """Role-sensitive weighted scoring system."""
    score = 0.0
    reasons = []

    role = event.get("role", "")
    action = event.get("action_performed", "")
    department = event.get("department", "")
    login_shift = event.get("login_shift_window", "Yes")
    freq_hour = event.get("login_frequency_last_hour", 0)

    role_base = ROLE_BEHAVIOR.get(role, {"expected_logins_hour": 4})
    expected_freq = role_base["expected_logins_hour"]

    # 1️⃣ Role–Action mismatch (high risk)
    allowed_actions = ROLE_ACTION_MATRIX.get(role, [])
    if action not in allowed_actions and role in ROLE_ACTION_MATRIX:
        score += 0.35
        reasons.append(f"Unauthorized action '{action}' for role '{role}' (+0.35)")

    # 2️⃣ Department mismatch (medium risk)
    if (role == "OPD Doctor" and department != "OPD") or \
       (role == "Ward Doctor" and department != "IPD") or \
       (role == "Finance Officer" and department not in ["Finance", "Billing"]):
        score += 0.20
        reasons.append(f"Department mismatch for role {role} (+0.20)")

    # 3️⃣ Shift window anomaly (role-based risk)
    if login_shift == "No":
        shift_risk = SHIFT_POLICY.get(role, 0.20)
        score += shift_risk
        reasons.append(f"Access outside allowed shift window ({role}) (+{shift_risk:.2f})")


    # 4️⃣ Login frequency anomaly (low-medium risk)
    if freq_hour > 2 * expected_freq:
        deviation = (freq_hour - expected_freq) / expected_freq
        weight = min(0.10 + 0.05 * deviation, 0.20)
        score += weight
        reasons.append(f"Unusual login frequency ({freq_hour}/hr vs expected {expected_freq}) (+{round(weight,2)})")

    # 5️⃣ Cross-role / repetition anomalies (low-medium risk)
    if event.get("cross_role_access", False):
        score += 0.10
        reasons.append("Cross-role record access detected (+0.10)")
    if event.get("action_repetition_rate", 0) > 10:
        score += 0.10
        reasons.append("Repeated same action excessively (+0.10)")

    # Cap between [0, 1]
    score = max(min(score, 1.0), 0.0)
    explanation = "; ".join(reasons) if reasons else "Normal access pattern"
    return score, explanation


# ---------- Quantum-Enhanced Layer ----------
def compute_quantum_score(event):
    """
    Integrates QuantumSecurity for uncertainty weighting.
    The quantum layer adjusts classical score probabilistically.
    """
    classical_score, explanation = compute_classical_score(event)

    try:
        qs = QuantumSecurity()
        quantum_weight = qs.secure_anomaly_score(event)
    except Exception:
        quantum_weight = classical_score * 0.5  # fallback

    # Combine adaptively (stable hybridization)
    hybrid_score = (0.7 * classical_score) + (0.3 * quantum_weight)

    # Slightly boost if quantum entropy shows strong randomness (>0.7)
    if quantum_weight > 0.7:
        hybrid_score += 0.05

    hybrid_score = round(min(hybrid_score, 1.0), 4)
    explanation += f"; Quantum-adjusted uncertainty factor: {round(quantum_weight, 3)}"

    return hybrid_score, explanation


# ---------- Main Event Processor ----------
def process_event(event):
    score, explanation = compute_quantum_score(event)
    flag = 1 if score > 0.45 else 0
    event["flag"] = flag

    # 🧠 Determine anomaly level (for dashboard visualization)
    from engine.response_engine import ROLE_RESPONSE_POLICY
    role = event.get("role", "DEFAULT")
    policy = ROLE_RESPONSE_POLICY.get(role, ROLE_RESPONSE_POLICY["DEFAULT"])

    if score < policy["notify"]:
        anomaly_level = "LOW"
    elif score < policy["re_otp"]:
        anomaly_level = "MEDIUM"
    elif score < policy["lock"]:
        anomaly_level = "HIGH"
    else:
        anomaly_level = "CRITICAL"


    # ✅ Save to DB
    conn = _get_conn()
    c = conn.cursor()
    c.execute("""
        INSERT INTO ehr_access_logs (
            user_id, role, department, access_timestamp, access_type,
            action_performed, ehr_record_id, login_shift_window,
            login_frequency_last_hour, previous_access_time,
            session_id, login_time, logout_time, anomaly_level
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        event.get("user_id"),
        event.get("role"),
        event.get("department"),
        event.get("access_timestamp"),
        event.get("access_type"),
        event.get("action_performed"),
        event.get("ehr_record_id"),
        event.get("login_shift_window"),
        event.get("login_frequency_last_hour"),
        event.get("previous_access_time"),
        event.get("session_id"),
        event.get("login_time"),
        event.get("logout_time"),
        anomaly_level,
    ))
    conn.commit()
    conn.close()

    # ✅ Return all four values now
    return score, flag, explanation, anomaly_level




# ---------- Local Test ----------
if __name__ == "__main__":
    test_event = {
        "user_id": "finance_officer_01",
        "role": "Finance Officer",
        "department": "Billing",
        "access_timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "access_type": "login",
        "action_performed": "view_cost",
        "ehr_record_id": "EHR009",
        "session_id": "sess123",
        "login_shift_window": "No",
        "login_frequency_last_hour": 15,
        "access_duration_seconds": 900,
        "previous_access_time": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "action_repetition_rate": 12,
        "cross_role_access": False,
    }

    score, flag, explanation = process_event(test_event)
    print(f"🔮 Hybrid anomaly score: {score} | Flag: {flag}")
    print(f"💡 Explanation: {explanation}")
