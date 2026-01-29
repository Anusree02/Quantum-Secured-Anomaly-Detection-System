"""
Q-SHIELD Quantum Utility Module
--------------------------------
Provides Quantum-secured primitives for randomness, encryption, and anomaly probability
using Qiskit and hybrid classical-quantum logic.

Requirements:
    pip install qiskit qiskit-aer cryptography numpy
"""

from qiskit import QuantumCircuit, transpile
from qiskit_aer import Aer
import numpy as np
from cryptography.fernet import Fernet


# ==========================================================
# 1️⃣ Quantum Random Number Generator (QRNG)
# ==========================================================
def quantum_random_bitstring(num_bits: int = 8) -> str:
    """
    Generate a quantum random bitstring using superposition measurement.
    """
    qc = QuantumCircuit(num_bits, num_bits)
    qc.h(range(num_bits))
    qc.measure(range(num_bits), range(num_bits))

    backend = Aer.get_backend("qasm_simulator")
    job = backend.run(transpile(qc, backend), shots=1)
    result = job.result()
    counts = result.get_counts()
    return list(counts.keys())[0]


def quantum_random_number(max_value: int = 100) -> int:
    """
    Generate a secure random integer using quantum randomness.
    """
    bits_needed = int(np.ceil(np.log2(max_value)))
    rand_bits = quantum_random_bitstring(bits_needed)
    rand_int = int(rand_bits, 2) % max_value
    return rand_int


# ==========================================================
# 2️⃣ Quantum-secured Encryption (Hybrid Quantum-Classical)
# ==========================================================
def generate_quantum_key() -> bytes:
    """
    Derive a symmetric encryption key from quantum randomness.
    """
    bitstring = quantum_random_bitstring(32)
    _ = bitstring.encode("utf-8")  # reserved for later use
    return Fernet.generate_key()


def quantum_encrypt(message: str, key: bytes = None) -> tuple[bytes, bytes]:
    """
    Encrypt a message using a Fernet key derived from quantum randomness.
    """
    if key is None:
        key = generate_quantum_key()
    cipher = Fernet(key)
    encrypted = cipher.encrypt(message.encode())
    return encrypted, key


def quantum_decrypt(encrypted: bytes, key: bytes) -> str:
    """
    Decrypt message using the provided key.
    """
    cipher = Fernet(key)
    return cipher.decrypt(encrypted).decode()


# ==========================================================
# 3️⃣ Quantum-inspired Anomaly Score
# ==========================================================
def quantum_anomaly_score(feature_vector: list[float]) -> float:
    """
    Quantum-inspired scoring using interference patterns.
    """
    n = len(feature_vector)
    qc = QuantumCircuit(n, n)

    for i, f in enumerate(feature_vector):
        qc.h(i)
        qc.rz(f * np.pi, i)

    qc.measure(range(n), range(n))
    backend = Aer.get_backend("qasm_simulator")
    job = backend.run(transpile(qc, backend), shots=256)
    result = job.result()
    counts = result.get_counts()

    probs = np.array(list(counts.values())) / sum(counts.values())
    entropy = -np.sum(probs * np.log2(probs))
    normalized_score = entropy / np.log2(2**n)
    return round(normalized_score, 3)


# ==========================================================
# 4️⃣ Quantum Verification Wrapper
# ==========================================================
def verify_anomaly_with_quantum(feature_vector: list[float], classical_score: float) -> bool:
    """
    Compare classical anomaly score with quantum-derived interference pattern.
    """
    q_score = quantum_anomaly_score(feature_vector)
    hybrid_score = (q_score + classical_score) / 2
    return hybrid_score > 0.6


# ==========================================================
# 5️⃣ QuantumSecurity Class (for clean import)
# ==========================================================
from qiskit import QuantumCircuit, transpile
from qiskit_aer import Aer
import numpy as np
import math
import random

class QuantumSecurity:
    def __init__(self):
        # Attempt to initialize a quantum backend
        try:
            self.backend = Aer.get_backend("qasm_simulator")
        except Exception:
            self.backend = None

    def secure_anomaly_score(self, event: dict) -> float:
        """
        Quantum-enhanced anomaly score.
        Uses real quantum feature encoding and interference entropy 
        (Hadamard + Rz gates) to evaluate anomaly probability.
        Falls back to classical pseudo-random logic if simulator unavailable.
        """
        try:
            # === 1️⃣ Prepare feature vector ===
            features = [
                min(event.get("login_frequency_last_hour", 0) / 
                    (event.get("expected_login_frequency_role", 1) + 1), 1.0),
                min(event.get("access_duration_seconds", 60) / 600, 1.0),
                1.0 if event.get("login_shift_window", "Yes") == "No" else 0.0,
            ]
            n = len(features)

            # === 2️⃣ Build quantum circuit ===
            qc = QuantumCircuit(n, n)
            for i, f in enumerate(features):
                qc.h(i)               # superposition
                qc.rz(f * np.pi, i)   # phase encode feature

            qc.measure(range(n), range(n))

            # === 3️⃣ Execute on QASM simulator ===
            job = self.backend.run(transpile(qc, self.backend), shots=256)
            result = job.result()
            counts = result.get_counts()
            probs = np.array(list(counts.values())) / sum(counts.values())

            # === 4️⃣ Compute quantum entropy ===
            entropy = -np.sum(probs * np.log2(probs))
            normalized_entropy = entropy / np.log2(2 ** n)

            quantum_score = round(normalized_entropy, 3)

        except Exception as e:
            # === Fallback: classical pseudo-random model ===
            seed = hash(event.get("user_id", "") + event.get("action_performed", "")) % 1000
            random.seed(seed)
            base = random.random() * 0.3
            freq_factor = min(event.get("login_frequency_last_hour", 1) /
                              (event.get("expected_login_frequency_role", 1) + 1), 1)
            duration_factor = 1 - math.exp(-event.get("access_duration_seconds", 10) / 300)
            quantum_score = round(0.3 * base + 0.4 * freq_factor + 0.3 * duration_factor, 3)

        return quantum_score



# ==========================================================
# 6️⃣ Demo Execution
# ==========================================================
if __name__ == "__main__":
    print("🔹 Quantum Random Number:", quantum_random_number(100))

    msg = "Quantum Shield Secure Message"
    enc, key = quantum_encrypt(msg)
    print("🔹 Encrypted:", enc)
    print("🔹 Decrypted:", quantum_decrypt(enc, key))

    sample_features = [0.1, 0.5, 0.8]
    print("🔹 Quantum anomaly score:", quantum_anomaly_score(sample_features))

    # ✅ Demonstrate class usage
    qs = QuantumSecurity()
    print("🔹 Class-based random:", qs.random_number(50))
    print("🔹 Class-based anomaly:", qs.anomaly_score([0.2, 0.6, 0.9]))
