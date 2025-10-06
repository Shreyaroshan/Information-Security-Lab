from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import numpy as np
import base64
import random

# ============================================================
# 1️⃣ Playfair Cipher (Classical Layer)
# ============================================================

def generate_playfair_matrix(key):
    key = key.lower().replace("j", "i")
    matrix = []
    used = set()
    for c in key:
        if c not in used and c.isalpha():
            matrix.append(c)
            used.add(c)
    for c in "abcdefghijklmnopqrstuvwxyz":
        if c not in used and c != "j":
            matrix.append(c)
            used.add(c)
    matrix = [matrix[i:i+5] for i in range(0, 25, 5)]
    return matrix

def find_position(matrix, char):
    for i in range(5):
        for j in range(5):
            if matrix[i][j] == char:
                return i, j
    return None, None

def playfair_prepare_text(text):
    text = text.lower().replace("j", "i")
    text = "".join([c for c in text if c.isalpha()])
    prepared = ""
    i = 0
    while i < len(text):
        a = text[i]
        b = text[i+1] if i+1 < len(text) else "x"
        if a == b:
            prepared += a + "x"
            i += 1
        else:
            prepared += a + b
            i += 2
    if len(prepared) % 2 != 0:
        prepared += "x"
    return prepared

def playfair_encrypt(plaintext, key):
    matrix = generate_playfair_matrix(key)
    text = playfair_prepare_text(plaintext)
    ciphertext = ""
    for i in range(0, len(text), 2):
        a, b = text[i], text[i+1]
        row1, col1 = find_position(matrix, a)
        row2, col2 = find_position(matrix, b)
        if row1 == row2:
            ciphertext += matrix[row1][(col1+1)%5] + matrix[row2][(col2+1)%5]
        elif col1 == col2:
            ciphertext += matrix[(row1+1)%5][col1] + matrix[(row2+1)%5][col2]
        else:
            ciphertext += matrix[row1][col2] + matrix[row2][col1]
    return ciphertext

def playfair_decrypt(ciphertext, key):
    matrix = generate_playfair_matrix(key)
    plaintext = ""
    for i in range(0, len(ciphertext), 2):
        a, b = ciphertext[i], ciphertext[i+1]
        row1, col1 = find_position(matrix, a)
        row2, col2 = find_position(matrix, b)
        if row1 == row2:
            plaintext += matrix[row1][(col1-1)%5] + matrix[row2][(col2-1)%5]
        elif col1 == col2:
            plaintext += matrix[(row1-1)%5][col1] + matrix[(row2-1)%5][col2]
        else:
            plaintext += matrix[row1][col2] + matrix[row2][col1]
    return plaintext

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

patient_data = input("🧾 Enter patient details (e.g., ID101,Name=Alice,Disease=Flu): ")
print("👩‍⚕️ Patient Original Data:", patient_data)

# Playfair key
playfair_key = "HOSPITAL"
playfair_encrypted = playfair_encrypt(patient_data.lower(), playfair_key)
print("\n🔒 Playfair Encrypted Text:", playfair_encrypted)

# Generate shared AES key using Diffie-Hellman (Patient ↔ Nurse)
aes_key = diffie_hellman_key_exchange()

# AES-256 encryption on top of Playfair Cipher
aes_encrypted = aes_encrypt(playfair_encrypted, aes_key)
print("🔐 AES-256 Encrypted Text Sent to Nurse:", aes_encrypted)

# Step 2: Nurse receives and decrypts
aes_decrypted = aes_decrypt(aes_encrypted, aes_key)
playfair_decrypted = playfair_decrypt(aes_decrypted, playfair_key)
print("\n💉 Nurse Decrypted Data:", playfair_decrypted)

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
