from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import time

# RSA Key Generation
rsa_start_time = time.time()
rsa_key = RSA.generate(2048)
rsa_end_time = time.time()
rsa_key_gen_time = rsa_end_time - rsa_start_time
print(f"RSA Key Generation Time: {rsa_key_gen_time:.10f} seconds")

# ECC Key Generation
ecc_start_time = time.time()
ecc_key = ECC.generate(curve='P-256')
ecc_end_time = time.time()
ecc_key_gen_time = ecc_end_time - ecc_start_time
print(f"ECC Key Generation Time: {ecc_key_gen_time:.10f} seconds")

# RSA Hybrid Encryption/Decryption
def rsa_hybrid_encrypt(file_data, rsa_key):
    aes_key = get_random_bytes(32)
    aes_cipher = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = aes_cipher.encrypt_and_digest(file_data)
    rsa_cipher = PKCS1_OAEP.new(rsa_key.publickey())
    encrypted_aes_key = rsa_cipher.encrypt(aes_key)
    return encrypted_aes_key, aes_cipher.nonce, ciphertext, tag

def rsa_hybrid_decrypt(encrypted_aes_key, nonce, ciphertext, tag, rsa_key):
    rsa_cipher = PKCS1_OAEP.new(rsa_key)
    aes_key = rsa_cipher.decrypt(encrypted_aes_key)
    aes_cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    decrypted_data = aes_cipher.decrypt_and_verify(ciphertext, tag)
    return decrypted_data

# ECC Hybrid Encryption/Decryption (Simulated with signing + verification)
def ecc_hybrid_encrypt(file_data, ecc_key):
    aes_key = get_random_bytes(32)
    aes_cipher = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = aes_cipher.encrypt_and_digest(file_data)
    h = SHA256.new(aes_key)
    signer = DSS.new(ecc_key, 'fips-186-3')
    signature = signer.sign(h)
    return signature, aes_cipher.nonce, ciphertext, tag, aes_key

def ecc_hybrid_decrypt(signature, nonce, ciphertext, tag, ecc_key, aes_key):
    # Verify signature (simulating ECC decryption/validation)
    h = SHA256.new(aes_key)
    verifier = DSS.new(ecc_key.public_key(), 'fips-186-3')
    try:
        verifier.verify(h, signature)
        aes_cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
        decrypted_data = aes_cipher.decrypt_and_verify(ciphertext, tag)
        return decrypted_data
    except ValueError:
        print("ECC Verification Failed!")
        return None

# Generate test data
file_data_1mb = get_random_bytes(1024 * 1024)
file_data_10mb = get_random_bytes(1024 * 1024 * 10)

# RSA Encryption/Decryption
rsa_enc_start = time.time()
enc_aes_key, nonce, ciphertext, tag = rsa_hybrid_encrypt(file_data_1mb, rsa_key)
rsa_enc_time_1mb = time.time() - rsa_enc_start

rsa_dec_start = time.time()
rsa_decrypted_data = rsa_hybrid_decrypt(enc_aes_key, nonce, ciphertext, tag, rsa_key)
rsa_dec_time_1mb = time.time() - rsa_dec_start

rsa_enc_start = time.time()
enc_aes_key, nonce, ciphertext, tag = rsa_hybrid_encrypt(file_data_10mb, rsa_key)
rsa_enc_time_10mb = time.time() - rsa_enc_start

rsa_dec_start = time.time()
rsa_decrypted_data = rsa_hybrid_decrypt(enc_aes_key, nonce, ciphertext, tag, rsa_key)
rsa_dec_time_10mb = time.time() - rsa_dec_start

# ECC Encryption/Decryption
ecc_enc_start = time.time()
signature, nonce, ciphertext, tag, aes_key = ecc_hybrid_encrypt(file_data_1mb, ecc_key)
ecc_enc_time_1mb = time.time() - ecc_enc_start

ecc_dec_start = time.time()
ecc_decrypted_data = ecc_hybrid_decrypt(signature, nonce, ciphertext, tag, ecc_key, aes_key)
ecc_dec_time_1mb = time.time() - ecc_dec_start

ecc_enc_start = time.time()
signature, nonce, ciphertext, tag, aes_key = ecc_hybrid_encrypt(file_data_10mb, ecc_key)
ecc_enc_time_10mb = time.time() - ecc_enc_start

ecc_dec_start = time.time()
ecc_decrypted_data = ecc_hybrid_decrypt(signature, nonce, ciphertext, tag, ecc_key, aes_key)
ecc_dec_time_10mb = time.time() - ecc_dec_start

# Print results
print(f"RSA Encryption Time (1MB): {rsa_enc_time_1mb:.10f} seconds")
print(f"RSA Decryption Time (1MB): {rsa_dec_time_1mb:.10f} seconds")
print(f"RSA Encryption Time (10MB): {rsa_enc_time_10mb:.10f} seconds")
print(f"RSA Decryption Time (10MB): {rsa_dec_time_10mb:.10f} seconds")

print(f"ECC Encryption Time (1MB): {ecc_enc_time_1mb:.10f} seconds")
print(f"ECC Decryption Time (1MB): {ecc_dec_time_1mb:.10f} seconds")
print(f"ECC Encryption Time (10MB): {ecc_enc_time_10mb:.10f} seconds")
print(f"ECC Decryption Time (10MB): {ecc_dec_time_10mb:.10f} seconds")
