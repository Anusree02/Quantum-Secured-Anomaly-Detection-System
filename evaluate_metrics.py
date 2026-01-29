"""
evaluate_qshield.py
-------------------
Performance and latency evaluation for QSHIELD.
Measures detection + response times for hybrid anomaly engine and policy engine.
No XAI components required.
"""

import time
from datetime import datetime
from engine.anomaly_engine import compute_quantum_score, process_event
from engine.response_engine import respond_to_anomaly

# ---------------------- Test Input Event ----------------------
test_event = {
    "user_id": "opdnurse_01",
    "role": "OPD Nurse",
    "department": "OPD",
    "access_timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
    "access_type": "login",
    "action_performed": "read_vitals",
    "ehr_record_id": "EHR_TEST_001",
    "session_id": "sess_eval_001",
    "login_shift_window": "No",  # Outside shift (for risk trigger)
    "login_frequency_last_hour": 14,
    "expected_login_frequency_role": 6,
    "access_duration_seconds": 360,
    "previous_access_time": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
    "login_time": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
    "logout_time": None,
}

# ---------------------- Evaluation Function ----------------------
def evaluate_qshield():
    print("\n🧩 QSHIELD PERFORMANCE EVALUATION\n" + "="*60)
    metrics = {}

    # 1️⃣ Anomaly Detection Latency
    start = time.perf_counter()
    score, explanation = compute_quantum_score(test_event)
    metrics["anomaly_detection_time_ms"] = round((time.perf_counter() - start) * 1000, 2)

    print(f"✅ Anomaly Detection: {metrics['anomaly_detection_time_ms']} ms | Score: {score}")
    print(f"💡 Explanation: {explanation}")

    # 2️⃣ Response Engine Latency
    start = time.perf_counter()
    action = respond_to_anomaly(
        user_email="testuser@example.com",
        session_id=test_event["session_id"],
        risk_score=score,
        role=test_event["role"]
    )
    metrics["response_time_ms"] = round((time.perf_counter() - start) * 1000, 2)
    print(f"✅ Response Decision: {action} | Time: {metrics['response_time_ms']} ms")

    # 3️⃣ Total Pipeline Latency
    total_time = (metrics["anomaly_detection_time_ms"] + metrics["response_time_ms"]) / 1000
    metrics["total_pipeline_sec"] = round(total_time, 2)
    print(f"⚙️ Total End-to-End Latency: {metrics['total_pipeline_sec']} s")

    # 4️⃣ Evaluate Performance
    print("\n📊 --- PERFORMANCE SUMMARY ---")
    print(f"🔹 Detection Latency: {metrics['anomaly_detection_time_ms']} ms")
    print(f"🔹 Response Latency:  {metrics['response_time_ms']} ms")
    print(f"🔹 Total Pipeline:    {metrics['total_pipeline_sec']} s")


# ---------------------- Run Evaluation ----------------------
if __name__ == "__main__":
    evaluate_qshield()
