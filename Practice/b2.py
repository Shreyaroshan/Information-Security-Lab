from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
import hashlib

# ---------------------- RSA Key Generation ----------------------
def generate_rsa_key_pair():
    key = RSA.generate(2048)
    private_key = (key.d, key.n)  # (private exponent, modulus)
    public_key = (key.e, key.n)   # (public exponent, modulus)
    return private_key, public_key

# ---------------------- AES Encryption ----------------------
def manifest_encryption(public_key, msg):
    key = get_random_bytes(16)   # AES-128 key (16 bytes)
    iv = get_random_bytes(16)    # Random IV for CBC mode

    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(msg.encode('utf-8'), AES.block_size))

    # Encrypt AES key using RSA public key
    e, n = public_key
    encrypted_aes_key = pow(bytes_to_long(key), e, n)

    # Convert to base64 for readability
    return base64.b64encode(long_to_bytes(encrypted_aes_key)).decode('utf-8'), ciphertext, iv

# ---------------------- AES Decryption ----------------------
def manifest_decryption(private_key, ciphertext, encrypted_key_b64, iv):
    d, n = private_key
    encrypted_key_bytes = base64.b64decode(encrypted_key_b64)
    encrypted_key_int = bytes_to_long(encrypted_key_bytes)

    # Decrypt AES key using private key
    decrypted_key_int = pow(encrypted_key_int, d, n)
    decrypted_key = long_to_bytes(decrypted_key_int)

    cipher = AES.new(decrypted_key, AES.MODE_CBC, iv)
    decrypted_message = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted_message.decode('utf-8')

# ---------------------- Hashing for Integrity ----------------------
def hashing(msg):
    # Return SHA-256 hash as bytes
    return hashlib.sha256(msg).digest()

# ---------------------- Digital Signature ----------------------
def sign_hash(private_key, hash_bytes):
    d, n = private_key
    hash_int = bytes_to_long(hash_bytes)
    signature = pow(hash_int, d, n)
    return signature

def verify_signature(public_key, signature, hash_bytes):
    e, n = public_key
    hash_from_signature = pow(signature, e, n)
    return hash_from_signature == bytes_to_long(hash_bytes)

# ---------------------- MAIN FLOW ----------------------
if __name__ == "__main__":
    manifest = "VoteManifest2025:CandidateX"
    print("🗳️ Original Manifest:", manifest)

    # Step 1: Generate RSA keys
    private_key, public_key = generate_rsa_key_pair()
    print("\n🔐 RSA keys generated.")

    # Step 2: Encrypt manifest using AES, AES key encrypted with RSA public key
    encrypted_key_b64, ciphertext, iv = manifest_encryption(public_key, manifest)
    print("\n🧩 AES Key (Encrypted, Base64):", encrypted_key_b64)
    print("📦 Ciphertext:", base64.b64encode(ciphertext).decode('utf-8'))

    # Step 3: Hash the plaintext manifest
    hash_val = hashing(manifest.encode('utf-8'))
    print("\n🔏 Manifest SHA-256 Hash:", hash_val.hex())

    # Step 4: Sign the hash using candidate's private key
    signature = sign_hash(private_key, hash_val)
    print("\n✍️ Digital Signature:", hex(signature)[:60] + "...")

    # Step 5: Decrypt the manifest (using AES key decrypted with RSA private key)
    decrypted_message = manifest_decryption(private_key, ciphertext, encrypted_key_b64, iv)
    print("\n📖 Decrypted Manifest:", decrypted_message)

    # Step 6: Verify integrity & authenticity
    new_hash = hashing(decrypted_message.encode('utf-8'))
    verified = verify_signature(public_key, signature, new_hash)

    if verified:
        print("\n✅ Verification successful — hash matches and signature valid.")
    else:
        print("\n❌ Verification failed — possible tampering detected.")
 # ---------------------------
    # Step 6: Tampering Simulation
    # ---------------------------
    tampered_manifest = "VoteManifest2025:CandidateY"
    print("\n⚠️ Tampered Manifest Introduced:", tampered_manifest)

    # Compute new hash (different)
    tampered_hash = hashing(tampered_manifest.encode('utf-8'))

    # Attempt to verify with original signature
    if verify_signature(public_key, signature,tampered_hash ):
        print("✅ Signature Verification: PASSED (Unexpected!)")
    else:
        print("❌ Signature Verification: FAILED (Tampering Detected)")

    # Compare hash values
    if hash_val == tampered_hash:
        print("✅ Hash Match (No Tampering)")
    else:
        print("❌ Hash Mismatch Detected! (Integrity Compromised)")