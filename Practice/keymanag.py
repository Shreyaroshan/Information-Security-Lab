from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import numpy as np
import base64
import random

# ============================================================
# 1️⃣ Hill Cipher (Classical Layer)
# ============================================================

def hill_encrypt(message, key_matrix):
    message = message.lower().replace(" ", "")
    while len(message) % 2 != 0:
        message += 'x'  # padding
    encrypted_text = ""
    for i in range(0, len(message), 2):
        block = np.array([[ord(message[i]) - 97], [ord(message[i+1]) - 97]])
        result = np.dot(key_matrix, block) % 26
        encrypted_text += chr(result[0][0] + 97) + chr(result[1][0] + 97)
    return encrypted_text


def hill_decrypt(ciphertext, key_matrix):
    det = int(np.round(np.linalg.det(key_matrix)))
    det_inv = pow(det, -1, 26)
    adj = np.round(det * np.linalg.inv(key_matrix)).astype(int) % 26
    inverse_matrix = (det_inv * adj) % 26

    decrypted_text = ""
    for i in range(0, len(ciphertext), 2):
        block = np.array([[ord(ciphertext[i]) - 97], [ord(ciphertext[i+1]) - 97]])
        result = np.dot(inverse_matrix, block) % 26
        decrypted_text += chr(result[0][0] + 97) + chr(result[1][0] + 97)
    return decrypted_text

# ============================================================
# 2️⃣ AES-256 Encryption/Decryption (Modern Layer)
# ============================================================

def aes_encrypt(plaintext, key):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return base64.b64encode(iv + ciphertext).decode()

def aes_decrypt(encoded_ciphertext, key):
    raw = base64.b64decode(encoded_ciphertext)
    iv, ciphertext = raw[:16], raw[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()

# ============================================================
# 3️⃣ Diffie-Hellman Key Exchange (Patient ↔ Nurse)
# ============================================================

def diffie_hellman_key_exchange():
    p = 467  # prime
    g = 2    # base
    a = random.randint(1, p-2)
    b = random.randint(1, p-2)
    A = pow(g, a, p)
    B = pow(g, b, p)
    shared_key_patient = pow(B, a, p)
    shared_key_nurse = pow(A, b, p)
    assert shared_key_patient == shared_key_nurse
    shared_key = SHA256.new(str(shared_key_patient).encode()).digest()
    return shared_key[:32]  # 256-bit AES key

# ============================================================
# 4️⃣ RSA + SHA-256 (Doctor ↔ Pharmacist)
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

def sha256_hash(data):
    return SHA256.new(data.encode()).hexdigest()

# ============================================================
# 5️⃣ Secure Workflow Simulation (User Input for Patient Data)
# ============================================================

# Step 1: Patient enters details
patient_data = input("🧾 Enter patient details (e.g., ID101,Name=Alice,Disease=Flu): ")
print("👩‍⚕️ Patient Original Data:", patient_data)

# Hill Cipher key
hill_key = np.array([[3, 3], [2, 5]])
hill_encrypted = hill_encrypt(patient_data.lower(), hill_key)
print("\n🔒 Hill Encrypted Text:", hill_encrypted)

# Generate shared AES key using Diffie-Hellman (Patient ↔ Nurse)
aes_key = diffie_hellman_key_exchange()

# AES-256 encryption on top of Hill Cipher
aes_encrypted = aes_encrypt(hill_encrypted, aes_key)
print("🔐 AES-256 Encrypted Text Sent to Nurse:", aes_encrypted)

# Step 2: Nurse receives and decrypts
aes_decrypted = aes_decrypt(aes_encrypted, aes_key)
hill_decrypted = hill_decrypt(aes_decrypted, hill_key)
print("\n💉 Nurse Decrypted Data:", hill_decrypted)

# Step 3: Doctor creates prescription
doctor_private, doctor_public = generate_rsa_keys()
prescription = input("\n🧾 Enter doctor's prescription: ")
print("\n👨‍⚕️ Doctor Prescription:", prescription)

rsa_encrypted_prescription = rsa_encrypt(prescription, doctor_public)
prescription_hash = sha256_hash(prescription)
print("🔏 Encrypted Prescription Sent with SHA256 Hash")

# Step 4: Pharmacist verifies and decrypts
pharma_decrypted = rsa_decrypt(rsa_encrypted_prescription, doctor_private)
pharma_hash = sha256_hash(pharma_decrypted)

print("\n💊 Pharmacist Received Prescription:", pharma_decrypted)
if pharma_hash == prescription_hash:
    print("✅ Prescription Verified (Hash Match, Integrity OK)")
else:
    print("❌ Prescription Verification Failed (Tampering Detected)")

# ============================================================
# 6️⃣ Key Management Simulation
# ============================================================
print("\n🧩 Key Management Status:")
print("AES-256 Key (DH shared):", aes_key.hex()[:32], "...")
print("Doctor RSA Private Key Stored Securely ✅")
print("If system compromised ➜ Rotate keys + enable secure vault 🔐")
