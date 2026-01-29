# decrypt_blob.py
"""
Decrypt an encrypted blob (Fernet / quantum_encrypt output).

Usage:
  1) Paste the encrypted blob literal below (or set ENCRYPTED_BLOB_FILE to a filename).
  2) Provide the key (Fernet base64 key) in KEY variable or via input prompt.
  3) Run: python decrypt_blob.py
"""

import ast
import os
import sys

# Optional: try to import quantum decrypt if you have auth.quantum_utils implemented
try:
    from auth.quantum_utils import quantum_decrypt
except Exception:
    quantum_decrypt = None

# cryptography fallback
try:
    from cryptography.fernet import Fernet, InvalidToken
except Exception:
    Fernet = None
    InvalidToken = Exception
ENCRYPTED_BLOB_LITERAL = b'gAAAAABpEcrl5Y42f5IOuC4-DxYWeOoje5KqxWpCxZo-Q_hEDDxUehrb2aXwqeIPIQSIEB1zYki0uWJdZxi-jLlI59hnwz05IFumepLHTIEcG-mHAc0B5F8LGUv0cbG0EnyPE0mPQ0UfliDiqJbxIHWPmIk5J4iG4nBZnm46bs57MXUAFGtYDLw0LhXAlCqHSBboBExn41yZbG2Ysj_-b2JKs6gIESa-kQcEXeIvDRdfoW55_q_TYz6LLSUHdzttuH1l60jkoeH8MA9rJL0CeIgol9s-KC8Augt7G8KeQaVvhBuQEsFQNyMsdaz2zYjxEvFgO5c-lJqcnde5wJj9_1tfwCbAHSGsjie_-KjKLRbnzvpp_p6fbR2MH47OiZfcRPnWOfwVU--bdiSWkfa_BmOF86w_k7QJLDuMslQJeaIUU1JVVeTswQX6mVx2g2iwK402cLVAuJD4xPv-h1Zjps7IunZg2AuXSAsY43H_BkyhYfvp9w'


# --------- Provide your encrypted blob here OR set ENCRYPTED_BLOB_FILE ----------
# Option A: paste the Python bytes literal (the thing that starts with b'GAAAAA...') :
# Example (do NOT include triple quotes around the b'...'): 
# ENCRYPTED_BLOB_LITERAL = b'GAAAAA...'

# Option B: store the blob in a file (binary) and give its path here:
ENCRYPTED_BLOB_FILE = None
# e.g. ENCRYPTED_BLOB_FILE = "encrypted_logs.bin"

# --------- Key (Fernet or quantum key) ----------
# Provide the key here (bytes literal or base64 string). If you used Fernet.generate_key()
# it will look like b'nk3...==' or a base64 string.
KEY_LITERAL = None
# e.g. KEY_LITERAL = b'0Lw0x9...=='   OR KEY_LITERAL = '0Lw0x9...=='

# -------------------------------------------------------------------------------
def load_blob():
    if ENCRYPTED_BLOB_LITERAL:
        if isinstance(ENCRYPTED_BLOB_LITERAL, (bytes, bytearray)):
            return bytes(ENCRYPTED_BLOB_LITERAL)
        # try parse if user pasted a python bytes literal string
        try:
            return ast.literal_eval(ENCRYPTED_BLOB_LITERAL)
        except Exception:
            return ENCRYPTED_BLOB_LITERAL.encode()
    if ENCRYPTED_BLOB_FILE:
        with open(ENCRYPTED_BLOB_FILE, "rb") as f:
            return f.read()
    # # interactive: paste blob
    # print("Paste the encrypted blob (a Python-style bytes literal starting with b'GAAA...') then ENTER, followed by Ctrl-D (or Ctrl-Z then Enter on Windows):")
    # blob_text = sys.stdin.read().strip()
    # if not blob_text:
    #     print("No blob provided. Exiting.")
    #     sys.exit(1)
    # try:
    #     return ast.literal_eval(blob_text)
    # except Exception:
    #     # fallback: try raw bytes
    #     return blob_text.encode()

def get_key():
    if KEY_LITERAL:
        if isinstance(KEY_LITERAL, (bytes, bytearray)):
            return bytes(KEY_LITERAL)
        return KEY_LITERAL.encode()
    # environment variable
    env_key = os.getenv("DECRYPTION_KEY") or os.getenv("FERNET_KEY")
    if env_key:
        return env_key.encode()
    # prompt
    k = input("Enter decryption key (Fernet/base64) or press Enter to try quantum_decrypt only: ").strip()
    if not k:
        return None
    # try to interpret as Python literal (b'...') first
    try:
        return ast.literal_eval(k) if (k.startswith("b'") or k.startswith('b"')) else k.encode()
    except Exception:
        return k.encode()

def try_quantum_decrypt(blob, key):
    if not quantum_decrypt:
        print("quantum_decrypt not available in auth.quantum_utils (skipped).")
        return None
    try:
        print("Trying quantum_decrypt(...) from auth.quantum_utils...")
        # some quantum_decrypt implementations might expect bytes or str for key
        return quantum_decrypt(blob, key)
    except Exception as e:
        print(f"quantum_decrypt failed: {e}")
        return None

def try_fernet(blob, key):
    if not Fernet:
        print("cryptography.Fernet not installed. Install cryptography (`pip install cryptography`) and retry.")
        return None
    try:
        # Key must be base64 urlsafe 32-bytes; accept bytes or string
        if isinstance(key, bytes):
            k = key
        else:
            k = key.encode()
        f = Fernet(k)
        plaintext = f.decrypt(blob)
        return plaintext.decode("utf-8", errors="replace")
    except InvalidToken:
        print("Fernet decryption failed: InvalidToken (wrong key or corrupted blob).")
        return None
    except Exception as e:
        print(f"Fernet decryption error: {e}")
        return None

def main():
    blob = load_blob()
    print(f"Loaded encrypted blob: {type(blob)} length={len(blob)} bytes")

    key = get_key()
    if key:
        print("Key provided (length:", len(key), "). Will try both quantum_decrypt (if available) and Fernet.")
    else:
        print("No key provided. Will try quantum_decrypt (if available) only.")

    # Try quantum_decrypt first if available
    if quantum_decrypt:
        qres = try_quantum_decrypt(blob, key)
        if qres:
            print("\n=== Decrypted (quantum_decrypt) ===\n")
            print(qres)
            return
    else:
        print("quantum_decrypt not available in environment.")

    # If key present, try Fernet
    if key:
        fres = try_fernet(blob, key)
        if fres:
            print("\n=== Decrypted (Fernet) ===\n")
            print(fres)
            return
        else:
            print("Fernet decryption failed or produced no output.")

    print("\nERROR: Could not decrypt the blob. Check that you provided the exact key used when encrypting (Fernet-style base64 32-byte key).")
    print("If you used quantum_encrypt (custom), provide the same key object returned by that function, or run this inside your project's environment where auth.quantum_utils exists.")

if __name__ == "__main__":
    main()
