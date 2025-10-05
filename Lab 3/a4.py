# ec_elgamal_hybrid.py
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import time
import os

# ---------------------------
# Key generation (recipient)
# ---------------------------
def generate_ec_keypair():
    """Generate secp256r1 (P-256) key pair for recipient"""
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

# ---------------------------
# Utilities: serialize/deserialize public keys
# ---------------------------
def pubkey_to_bytes(pubkey):
    """Serialize an EC public key to uncompressed X9.62 point bytes"""
    return pubkey.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )

def pubkey_from_bytes(data):
    """Load EC public key from X9.62 uncompressed point bytes"""
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), data)

# ---------------------------
# Derive symmetric key from ECDH shared secret
# ---------------------------
def derive_aes_key(shared_secret, info=b"ec-elgamal-hkdf", length=32):
    """
    Derive a symmetric key (AES-256) from ECDH shared secret using HKDF-SHA256.
    - shared_secret: raw bytes from private_key.exchange()
    - info: application-specific context
    - length: desired key length in bytes (32 => AES-256)
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info,
        backend=default_backend(),
    )
    return hkdf.derive(shared_secret)

# ---------------------------
# Encryption (EC-ElGamal hybrid)
# ---------------------------
def ec_elgamal_encrypt(plaintext_bytes, recipient_pubkey):
    """
    Encrypt plaintext_bytes for recipient_pubkey.
    Returns a dict containing:
      - ephemeral_pub (bytes)
      - nonce (bytes)
      - ciphertext (bytes)
    """
    # 1) Generate ephemeral EC key
    ephemeral_priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
    ephemeral_pub = ephemeral_priv.public_key()
    ephemeral_pub_bytes = pubkey_to_bytes(ephemeral_pub)

    # 2) ECDH: ephemeral_priv * recipient_pub -> shared secret
    shared_secret = ephemeral_priv.exchange(ec.ECDH(), recipient_pubkey)

    # 3) Derive AES key from shared secret
    aes_key = derive_aes_key(shared_secret, info=b"ec-elgamal-aesgcm")

    # 4) Encrypt with AES-GCM
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)  # 96-bit nonce for GCM
    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, associated_data=None)

    return {
        "ephemeral_pub": ephemeral_pub_bytes,
        "nonce": nonce,
        "ciphertext": ciphertext
    }

# ---------------------------
# Decryption
# ---------------------------
def ec_elgamal_decrypt(enc_struct, recipient_privkey):
    """
    Decrypt the enc_struct produced by ec_elgamal_encrypt using recipient_privkey.
    Returns plaintext bytes (or raises exception on auth failure).
    """
    ephemeral_pub_bytes = enc_struct["ephemeral_pub"]
    nonce = enc_struct["nonce"]
    ciphertext = enc_struct["ciphertext"]

    # Reconstruct ephemeral public key
    ephemeral_pub = pubkey_from_bytes(ephemeral_pub_bytes)

    # ECDH: recipient_priv * ephemeral_pub -> same shared secret
    shared_secret = recipient_privkey.exchange(ec.ECDH(), ephemeral_pub)

    # Derive AES key the same way
    aes_key = derive_aes_key(shared_secret, info=b"ec-elgamal-aesgcm")

    # Decrypt with AES-GCM
    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    return plaintext

# ---------------------------
# Performance measurement
# ---------------------------
def measure_performance(sizes_bytes):
    """
    sizes_bytes: list of integers (sizes in bytes) to test encryption/decryption time on.
    Prints and verifies correctness.
    """
    # Generate recipient keypair
    recipient_priv, recipient_pub = generate_ec_keypair()
    recipient_pub_bytes = pubkey_to_bytes(recipient_pub)

    print("Recipient public key (hex, uncompressed point):", recipient_pub_bytes.hex())
    print("Curve: secp256r1 (P-256)\n")

    results = []
    for size in sizes_bytes:
        print(f"--- Testing size: {size} bytes ---")
        # prepare plaintext
        plaintext = os.urandom(size)  # simulate binary patient data
        # encryption
        enc_start = time.perf_counter()
        enc_struct = ec_elgamal_encrypt(plaintext, recipient_pub)
        enc_end = time.perf_counter()
        enc_time = enc_end - enc_start

        # decryption
        dec_start = time.perf_counter()
        decrypted = ec_elgamal_decrypt(enc_struct, recipient_priv)
        dec_end = time.perf_counter()
        dec_time = dec_end - dec_start

        # verify
        ok = decrypted == plaintext
        print(f"Encryption time: {enc_time:.6f} s")
        print(f"Decryption time: {dec_time:.6f} s")
        print(f"Success (decrypted == original): {ok}\n")

        results.append({
            "size": size,
            "enc_time": enc_time,
            "dec_time": dec_time,
            "success": ok,
            "ciphertext_len": len(enc_struct["ciphertext"]),
            "ephemeral_pub_len": len(enc_struct["ephemeral_pub"])
        })

    print("=== Summary ===")
    for r in results:
        print(f"size={r['size']:>8}B  enc={r['enc_time']:.6f}s  dec={r['dec_time']:.6f}s  "
              f"ct_len={r['ciphertext_len']}  eph_len={r['ephemeral_pub_len']}  ok={r['success']}")

    return results

# ---------------------------
# Example run
# ---------------------------
if __name__ == "__main__":
    # sizes to measure (bytes): small to large (suitable for lab)
    sizes = [1024, 10*1024, 100*1024, 1024*1024]  # 1KB, 10KB, 100KB, 1MB
    measure_performance(sizes)
