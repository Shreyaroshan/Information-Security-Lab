from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.number import getPrime, inverse
from datetime import datetime
from hashlib import sha256
from math import gcd
from random import randint
import base64
import sys

# ============================================================
# RSA (for confidentiality)
# ============================================================
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def rsa_encrypt(message, public_key):
    key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(key)
    return base64.b64encode(cipher.encrypt(message.encode())).decode()

def rsa_decrypt(ciphertext, private_key):
    key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(key)
    return cipher.decrypt(base64.b64decode(ciphertext)).decode()

# ============================================================
# ElGamal (for digital signatures) - simple demo implementation
# ============================================================
def generate_elgamal_keys(bits=256):
    p = getPrime(bits)
    # choose generator g in [2, p-2]
    g = randint(2, p - 2)
    x = randint(1, p - 2)       # private key
    y = pow(g, x, p)            # public key component
    public = (p, g, y)
    private = (p, g, x)
    return public, private

def sign_elgamal(private_key, document):
    p, g, x = private_key
    # choose k with gcd(k, p-1) == 1
    while True:
        k = randint(1, p - 2)
        if gcd(k, p - 1) == 1:
            break
    h = int(sha256(document.encode()).hexdigest(), 16) % p
    r = pow(g, k, p)
    k_inv = inverse(k, p - 1)               # modular inverse of k mod (p-1)
    s = (k_inv * (h - x * r)) % (p - 1)
    return (int(r), int(s))

def verify_elgamal(public_key, document, signature):
    p, g, y = public_key
    r, s = signature
    if not (0 < r < p):
        return False
    h = int(sha256(document.encode()).hexdigest(), 16) % p
    # verify: y^r * r^s (mod p) == g^h (mod p)
    left = (pow(y, r, p) * pow(r, s, p)) % p
    right = pow(g, h, p)
    return left == right

# ============================================================
# Workflow Global Variables
# ============================================================

rsa_private, rsa_public = generate_rsa_keys()   # RSA pair (professor holds private)
elg_public, elg_private = generate_elgamal_keys()  # ElGamal pub/priv for signing

records = []   # Store dicts: {name, encrypted_score, signature}
logs = []      # Timestamped log entries

# ============================================================
# Logging helper
# ============================================================
def log_event(action):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    logs.append(f"[{timestamp}] {action}")

# ============================================================
# Student Role
# ============================================================
def student_menu():
    name = input("\nEnter student name: ").strip()
    if not name:
        print("⚠️ Name required.")
        return

    score = input("Enter exam score: ").strip()
    if not score:
        print("⚠️ Score required.")
        return

    # Encrypt score with RSA public key (professor's public key)
    encrypted_score = rsa_encrypt(score, rsa_public)

    # Sign the plaintext score with ElGamal private key
    signature = sign_elgamal(elg_private, score)

    records.append({
        "name": name,
        "encrypted_score": encrypted_score,
        "signature": signature
    })

    log_event(f"Student '{name}' encrypted and signed their score.")
    print("\n✅ Score encrypted and signed successfully.")
    print("🔐 Encrypted Score (RSA, truncated):", encrypted_score[:80], "...")
    print("✍️  Signature (ElGamal):", signature)

# ============================================================
# Professor Role
# ============================================================
def professor_menu():
    if not records:
        print("\n⚠️ No student records available.")
        return

    print("\n📚 Available Students:")
    for i, rec in enumerate(records, start=1):
        print(f"{i}. {rec['name']}")

    try:
        idx = int(input("\nSelect student number to decrypt: ")) - 1
        rec = records[idx]
    except (IndexError, ValueError):
        print("⚠️ Invalid selection.")
        return

    # Decrypt score using professor's RSA private key
    try:
        decrypted_score = rsa_decrypt(rec["encrypted_score"], rsa_private)
    except Exception as e:
        print("❌ Error decrypting score:", e)
        return

    # Verify ElGamal signature using ElGamal public key
    is_valid = verify_elgamal(elg_public, decrypted_score, rec["signature"])

    log_event(f"Professor decrypted and verified score of '{rec['name']}'.")
    print("\n👨‍🏫 Student Name:", rec["name"])
    print("📖 Decrypted Score:", decrypted_score)
    print("✅ Signature Verified" if is_valid else "❌ Signature Verification Failed")

# ============================================================
# Administrator Role
# ============================================================
def admin_menu():
    while True:
        print("\n🧾 Administrator Access:")
        print("1. View Encrypted Messages")
        print("2. View Operation Log")
        print("3. Back to Main Menu")
        choice = input("Enter choice: ").strip()

        if choice == '1':
            if not records:
                print("\n⚠️ No encrypted messages available.")
            else:
                for rec in records:
                    print(f"\n👤 {rec['name']}: {rec['encrypted_score'][:120]} ...")
            log_event("Administrator viewed encrypted messages.")
        elif choice == '2':
            print("\n📜 Operation Logs:")
            if not logs:
                print("No logs yet.")
            else:
                for entry in logs:
                    print(entry)
        elif choice == '3':
            return
        else:
            print("⚠️ Invalid option. Try again.")

# ============================================================
# Main Menu
# ============================================================
def main_menu():
    print("RSA public key (professor) and ElGamal public key (verifier) were generated at startup.")
    while True:
        print("\n================= 🏛️ SECURE UNIVERSITY SYSTEM =================")
        print("1️⃣ Student       - Encrypt & Sign Exam Score")
        print("2️⃣ Professor     - Decrypt & Verify Student Scores")
        print("3️⃣ Administrator - View Logs & Encrypted Data")
        print("4️⃣ Exit")
        choice = input("\nSelect your role (1-4): ").strip()

        if choice == '1':
            student_menu()
        elif choice == '2':
            professor_menu()
        elif choice == '3':
            admin_menu()
        elif choice == '4':
            print("\n🔒 Exiting Secure System. Goodbye!")
            sys.exit()
        else:
            print("⚠️ Invalid choice. Try again.")

# ============================================================
# Run the Program
# ============================================================
if __name__ == "__main__":
    main_menu()
