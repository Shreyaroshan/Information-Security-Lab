from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import numpy as np
import base64
import random
import sys

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
# 5️⃣ Workflow Global Variables
# ============================================================

aes_key = diffie_hellman_key_exchange()
hill_key = np.array([[3, 3], [2, 5]])

encrypted_patient_data = None
decrypted_patient_data = None
rsa_encrypted_prescription = None
prescription_hash = None
doctor_private = None
doctor_public = None

# ============================================================
# 6️⃣ Menu-Driven Simulation
# ============================================================

def patient_menu():
    global encrypted_patient_data
    patient_data = input("\n🧾 Enter patient details (e.g., ID101,Name=Alice,Disease=Flu): ")
    hill_encrypted = hill_encrypt(patient_data.lower(), hill_key)
    encrypted_patient_data = aes_encrypt(hill_encrypted, aes_key)
    print("\n✅ Patient data encrypted and sent to Nurse.")
    print("🔐 AES-256 Ciphertext:", encrypted_patient_data[:80], "...")


def nurse_menu():
    global decrypted_patient_data
    if not encrypted_patient_data:
        print("\n⚠️ No encrypted data received from patient yet.")
        return
    aes_decrypted = aes_decrypt(encrypted_patient_data, aes_key)
    decrypted_patient_data = hill_decrypt(aes_decrypted, hill_key)
    print("\n💉 Nurse decrypted the patient data:")
    print(decrypted_patient_data)


def doctor_menu():
    global rsa_encrypted_prescription, prescription_hash, doctor_private, doctor_public
    if not decrypted_patient_data:
        print("\n⚠️ No patient data received by nurse yet.")
        return
    doctor_private, doctor_public = generate_rsa_keys()
    prescription = input("\n🧾 Enter doctor's prescription: ")
    rsa_encrypted_prescription = rsa_encrypt(prescription, doctor_public)
    prescription_hash = sha256_hash(prescription)
    print("\n✅ Prescription encrypted and sent to Pharmacist.")
    print("🔏 RSA Encrypted Prescription:", rsa_encrypted_prescription[:80], "...")


def pharmacist_menu():
    if not rsa_encrypted_prescription:
        print("\n⚠️ No encrypted prescription received from doctor yet.")
        return
    pharma_decrypted = rsa_decrypt(rsa_encrypted_prescription, doctor_private)
    pharma_hash = sha256_hash(pharma_decrypted)
    print("\n💊 Pharmacist decrypted prescription:")
    print(pharma_decrypted)
    if pharma_hash == prescription_hash:
        print("✅ Verification successful (SHA256 hash matches).")
    else:
        print("❌ Verification failed (Data tampered).")


def main_menu():
    while True:
        print("\n================= 🏥 SECURE HEALTHCARE SYSTEM =================")
        print("1️⃣ Patient - Enter and Encrypt Data")
        print("2️⃣ Nurse   - Decrypt and View Data")
        print("3️⃣ Doctor  - Create and Encrypt Prescription")
        print("4️⃣ Pharmacist - Decrypt & Verify Prescription")
        print("5️⃣ Exit")
        choice = input("\nSelect your role (1-5): ")

        if choice == '1':
            patient_menu()
        elif choice == '2':
            nurse_menu()
        elif choice == '3':
            doctor_menu()
        elif choice == '4':
            pharmacist_menu()
        elif choice == '5':
            print("\n🔒 Exiting Secure System. Goodbye!")
            sys.exit()
        else:
            print("⚠️ Invalid choice. Please try again.")

# ============================================================
# Run the Program
# ============================================================

if __name__ == "__main__":
    main_menu()
