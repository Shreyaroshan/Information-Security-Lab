from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
import hashlib
import sys
from datetime import datetime

# ============================================================
# RSA Key Generation
# ============================================================
def generate_rsa_key_pair():
    key = RSA.generate(2048)
    private_key = (key.d, key.n)  # (private exponent, modulus)
    public_key = (key.e, key.n)   # (public exponent, modulus)
    return private_key, public_key

# ============================================================
# AES Encryption and Decryption
# ============================================================
def manifest_encryption(public_key, msg):
    key = get_random_bytes(16)  # AES-128 key
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(msg.encode('utf-8'), AES.block_size))

    # Encrypt AES key with RSA
    e, n = public_key
    encrypted_aes_key = pow(bytes_to_long(key), e, n)
    return base64.b64encode(long_to_bytes(encrypted_aes_key)).decode('utf-8'), ciphertext, iv

def manifest_decryption(private_key, ciphertext, encrypted_key_b64, iv):
    d, n = private_key
    encrypted_key_bytes = base64.b64decode(encrypted_key_b64)
    encrypted_key_int = bytes_to_long(encrypted_key_bytes)
    decrypted_key_int = pow(encrypted_key_int, d, n)
    decrypted_key = long_to_bytes(decrypted_key_int)
    cipher = AES.new(decrypted_key, AES.MODE_CBC, iv)
    decrypted_message = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted_message.decode('utf-8')

# ============================================================
# Hashing and Signature
# ============================================================
def hashing(msg):
    return hashlib.sha256(msg).digest()

def sign_hash(private_key, hash_bytes):
    d, n = private_key
    hash_int = bytes_to_long(hash_bytes)
    signature = pow(hash_int, d, n)
    return signature

def verify_signature(public_key, signature, hash_bytes):
    e, n = public_key
    hash_from_signature = pow(signature, e, n)
    return hash_from_signature == bytes_to_long(hash_bytes)

# ============================================================
# Timestamp Logger
# ============================================================
def log_event(action):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    logs.append(f"[{timestamp}] {action}")

# ============================================================
# Global Variables
# ============================================================
private_key, public_key = generate_rsa_key_pair()
records = []  # Stores all encrypted votes
logs = []     # Stores timestamps

# ============================================================
# Voter Role
# ============================================================
def voter_menu():
    manifest = input("\n🗳️ Enter your Vote Manifest (e.g., VoteManifest2025:CandidateX): ")
    print("\nEncrypting and signing your vote...")

    encrypted_key_b64, ciphertext, iv = manifest_encryption(public_key, manifest)
    hash_val = hashing(manifest.encode('utf-8'))
    signature = sign_hash(private_key, hash_val)

    records.append({
        "manifest": manifest,
        "encrypted_key": encrypted_key_b64,
        "ciphertext": ciphertext,
        "iv": iv,
        "signature": signature
    })

    log_event("Voter cast and signed their vote.")
    print("\n✅ Vote successfully encrypted and signed.")
    print("🔐 Encrypted AES Key:", encrypted_key_b64[:60], "...")
    print("📦 Ciphertext (Base64):", base64.b64encode(ciphertext).decode('utf-8')[:60], "...")
    print("✍️  Digital Signature:", hex(signature)[:60], "...")
    print("\nVote securely recorded in the system.")

# ============================================================
# Commissioner Role
# ============================================================
def commissioner_menu():
    if not records:
        print("\n⚠️ No votes recorded yet.")
        return

    print("\n📋 Available Votes:")
    for i, rec in enumerate(records, 1):
        print(f"{i}. {rec['manifest'].split(':')[0]} (Encrypted Entry)")

    try:
        choice = int(input("\nSelect a vote number to verify: ")) - 1
        rec = records[choice]
    except (ValueError, IndexError):
        print("⚠️ Invalid selection.")
        return

    print("\n🔍 Decrypting and verifying vote...")

    decrypted = manifest_decryption(private_key, rec['ciphertext'], rec['encrypted_key'], rec['iv'])
    hash_val = hashing(decrypted.encode('utf-8'))
    verified = verify_signature(public_key, rec['signature'], hash_val)

    log_event("Commissioner verified a vote manifest.")
    print("\n📖 Decrypted Manifest:", decrypted)
    print("✅ Signature Verification: Passed" if verified else "❌ Failed")

    # Simulate tampering check
    tampered = decrypted.replace("CandidateX", "CandidateY")
    tampered_hash = hashing(tampered.encode('utf-8'))
    if verify_signature(public_key, rec['signature'], tampered_hash):
        print("⚠️ Tampering Check: FAILED (Signature still valid — unexpected!)")
    else:
        print("🔒 Tampering Check: PASSED (Integrity protected)")

# ============================================================
# Admin Log Viewer
# ============================================================
def admin_menu():
    print("\n🧾 Commissioner Logbook")
    print("1️⃣ View Operation Logs")
    print("2️⃣ View Encrypted Votes")
    print("3️⃣ Back")
    choice = input("\nEnter choice: ")

    if choice == '1':
        print("\n📜 Operation Logs:")
        for entry in logs:
            print(entry)
    elif choice == '2':
        for i, rec in enumerate(records, 1):
            print(f"\n[{i}] Encrypted AES Key: {rec['encrypted_key'][:60]} ...")
            print(f"Ciphertext: {base64.b64encode(rec['ciphertext']).decode('utf-8')[:80]} ...")
    elif choice == '3':
        return
    else:
        print("⚠️ Invalid option.")

# ============================================================
# Main Menu
# ============================================================
def main_menu():
    while True:
        print("\n================= 🗳️ SECURE VOTING SYSTEM =================")
        print("1️⃣ Voter         - Encrypt & Sign Vote Manifest")
        print("2️⃣ Commissioner  - Decrypt & Verify Vote")
        print("3️⃣ Administrator - View Logs & Encrypted Data")
        print("4️⃣ Exit System")
        choice = input("\nSelect role (1-4): ")

        if choice == '1':
            voter_menu()
        elif choice == '2':
            commissioner_menu()
        elif choice == '3':
            admin_menu()
        elif choice == '4':
            print("\n🔒 Exiting Secure Voting System. Goodbye!")
            sys.exit()
        else:
            print("⚠️ Invalid input, try again.")

# ============================================================
# Run Program
# ============================================================
if __name__ == "__main__":
    main_menu()
