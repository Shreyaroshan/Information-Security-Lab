"""
Benchmark RSA (2048-bit, RSA-OAEP) hybrid vs EC-ElGamal-like hybrid (secp256r1 ECDH -> AES-GCM)
Measures keygen, encryption, decryption times for 1KB and 10KB messages.

Requires: pip install cryptography
"""

import os
import time
from collections import defaultdict

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec

# ---------------------------
# Helpers
# ---------------------------
def now():
    return time.perf_counter()

def derive_aes_key_from_shared(shared_secret, info=b"ec-elgamal-hkdf", length=32):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info,
        backend=default_backend()
    )
    return hkdf.derive(shared_secret)

# ---------------------------
# RSA (2048) hybrid functions
# ---------------------------
def rsa_generate_key(key_size=2048):
    t0 = now()
    priv = rsa.generate_private_key(public_exponent=65537, key_size=key_size, backend=default_backend())
    t1 = now()
    return priv, t1 - t0

def rsa_hybrid_encrypt(plaintext: bytes, rsa_pub):
    # produce AES key, encrypt plaintext with AES-GCM, then wrap AES key with RSA-OAEP
    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext, associated_data=None)

    # wrap AES key with RSA-OAEP
    wrapped_key = rsa_pub.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return {
        "wrapped_key": wrapped_key,
        "nonce": nonce,
        "ciphertext": ct
    }

def rsa_hybrid_decrypt(enc_struct, rsa_priv):
    wrapped_key = enc_struct["wrapped_key"]
    nonce = enc_struct["nonce"]
    ct = enc_struct["ciphertext"]

    aes_key = rsa_priv.decrypt(
        wrapped_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    aesgcm = AESGCM(aes_key)
    pt = aesgcm.decrypt(nonce, ct, associated_data=None)
    return pt

# ---------------------------
# EC-ElGamal-like hybrid functions (secp256r1)
# ---------------------------
def ecc_generate_keypair():
    t0 = now()
    priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
    pub = priv.public_key()
    t1 = now()
    return priv, pub, t1 - t0

def ecc_elgamal_encrypt(plaintext: bytes, recipient_pub):
    # ephemeral ECDH to derive AES key, then AES-GCM for message
    ephemeral_priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
    ephemeral_pub = ephemeral_priv.public_key()
    shared_secret = ephemeral_priv.exchange(ec.ECDH(), recipient_pub)
    aes_key = derive_aes_key_from_shared(shared_secret, info=b"ec-elgamal-aesgcm")

    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext, associated_data=None)

    # serialize ephemeral public for receiver to reconstruct shared secret
    ephemeral_pub_bytes = ephemeral_pub.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    return {
        "ephemeral_pub": ephemeral_pub_bytes,
        "nonce": nonce,
        "ciphertext": ct
    }

def ecc_elgamal_decrypt(enc_struct, recipient_priv):
    ephemeral_pub_bytes = enc_struct["ephemeral_pub"]
    nonce = enc_struct["nonce"]
    ct = enc_struct["ciphertext"]

    ephemeral_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), ephemeral_pub_bytes)
    shared_secret = recipient_priv.exchange(ec.ECDH(), ephemeral_pub)
    aes_key = derive_aes_key_from_shared(shared_secret, info=b"ec-elgamal-aesgcm")
    aesgcm = AESGCM(aes_key)
    pt = aesgcm.decrypt(nonce, ct, associated_data=None)
    return pt

# ---------------------------
# Benchmark runner
# ---------------------------
def run_bench(sizes_bytes):
    results = defaultdict(dict)

    print("=== Benchmark: RSA (2048) hybrid vs EC-ElGamal-like (secp256r1) hybrid ===\n")

    # Key generation
    print("Generating keys...")
    rsa_priv, rsa_keygen_time = rsa_generate_key(2048)
    rsa_pub = rsa_priv.public_key()
    print(f"RSA-2048 key generation time: {rsa_keygen_time:.6f} s")

    ecc_priv, ecc_pub, ecc_keygen_time = ecc_generate_keypair()
    print(f"ECC P-256 key generation time: {ecc_keygen_time:.6f} s\n")

    results["rsa"]["keygen_time"] = rsa_keygen_time
    results["ecc"]["keygen_time"] = ecc_keygen_time

    # For each size, measure encryption/decryption times
    for size in sizes_bytes:
        print(f"--- Size: {size} bytes ---")
        plaintext = os.urandom(size)

        # RSA hybrid encrypt
        t0 = now()
        rsa_enc_struct = rsa_hybrid_encrypt(plaintext, rsa_pub)
        t1 = now()
        rsa_enc_time = t1 - t0

        t0 = now()
        rsa_decrypted = rsa_hybrid_decrypt(rsa_enc_struct, rsa_priv)
        t1 = now()
        rsa_dec_time = t1 - t0

        assert rsa_decrypted == plaintext, "RSA hybrid decryption failed!"

        print(f"RSA hybrid: enc={rsa_enc_time:.6f}s dec={rsa_dec_time:.6f}s")

        # ECC hybrid encrypt
        t0 = now()
        ecc_enc_struct = ecc_elgamal_encrypt(plaintext, ecc_pub)
        t1 = now()
        ecc_enc_time = t1 - t0

        t0 = now()
        ecc_decrypted = ecc_elgamal_decrypt(ecc_enc_struct, ecc_priv)
        t1 = now()
        ecc_dec_time = t1 - t0

        assert ecc_decrypted == plaintext, "ECC hybrid decryption failed!"

        print(f"ECC-ElGamal-like: enc={ecc_enc_time:.6f}s dec={ecc_dec_time:.6f}s\n")

        # Record
        results["rsa"][f"enc_{size}"] = rsa_enc_time
        results["rsa"][f"dec_{size}"] = rsa_dec_time
        results["rsa"][f"ct_len_{size}"] = len(rsa_enc_struct["ciphertext"]) + len(rsa_enc_struct["wrapped_key"])

        results["ecc"][f"enc_{size}"] = ecc_enc_time
        results["ecc"][f"dec_{size}"] = ecc_dec_time
        results["ecc"][f"ct_len_{size}"] = len(ecc_enc_struct["ciphertext"]) + len(ecc_enc_struct["ephemeral_pub"])

    # Summary
    print("=== Summary ===")
    print(f"RSA-2048 keygen: {results['rsa']['keygen_time']:.6f}s, ECC P-256 keygen: {results['ecc']['keygen_time']:.6f}s")
    for size in sizes_bytes:
        print(f"Size {size}B:")
        print(f"  RSA  : enc={results['rsa'][f'enc_{size}']:.6f}s dec={results['rsa'][f'dec_{size}']:.6f}s ct_len={results['rsa'][f'ct_len_{size}']}")
        print(f"  EC   : enc={results['ecc'][f'enc_{size}']:.6f}s dec={results['ecc'][f'dec_{size}']:.6f}s ct_len={results['ecc'][f'ct_len_{size}']}")
    return results

# ---------------------------
# Run
# ---------------------------
if __name__ == "__main__":
    sizes = [1024, 10*1024]  # 1 KB, 10 KB
    run_bench(sizes)
