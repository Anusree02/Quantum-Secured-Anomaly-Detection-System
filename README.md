# Quantum-Secured Anomaly Detection System (QSHIELD)

**Tech Stack:** Python · Qiskit · Streamlit

QSHIELD is a security framework that combines **quantum-inspired authentication** with **behavior-based anomaly detection** to protect sensitive systems such as Electronic Health Records (EHRs).

## 🚀 Key Features
- **Quantum OTP Authentication:** Uses a QRNG simulated in Qiskit to generate highly unpredictable one-time passwords.
- **Hybrid Anomaly Detection:** Combines rule-based behavioral checks with quantum entropy–driven scoring.
- **Role-Based Access Control (RBAC):** Detects misuse based on user roles and access patterns.
- **Adaptive Response System:**  
  - Low risk → logged  
  - Medium risk → alerts  
  - High risk → OTP re-verification  
  - Critical → forced logout & admin lock
- **Admin Dashboard:** Encrypted log storage and real-time monitoring using Streamlit.

## 🧠 How It Works
User behavior (access frequency, session duration, timing, role alignment) is evaluated using a **hybrid scoring model**.  
Quantum entropy generated via Hadamard and Rz-based circuits enhances unpredictability and reduces false negatives.

## 📊 Performance Highlights
- QRNG entropy correlation: **0.996**
- Anomaly scoring time: **~175 ms**
- Full response cycle: **~9.2 seconds**

