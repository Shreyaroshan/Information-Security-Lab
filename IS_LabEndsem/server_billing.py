# server_paillier_homomorphic.py
import socket, json
from math import gcd
from Crypto.Util.number import getPrime
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

def lcm(x, y): return x * y // gcd(x, y)

def generate_paillier_keys(bits=512):
    # generate two distinct primes of size bits//2 each
    p = getPrime(bits // 2)
    q = getPrime(bits // 2)
    while q == p:
        q = getPrime(bits // 2)
    n = p * q
    n2 = n * n
    lam = lcm(p - 1, q - 1)
    g = n + 1
    def L(x): return (x - 1) // n
    mu = pow(L(pow(g, lam, n2)), -1, n)
    return (n, g), (lam, mu)

def decrypt(c, priv, pub):
    n, g = pub
    lam, mu = priv
    n2 = n * n
    def L(x): return (x - 1) // n
    return (L(pow(c, lam, n2)) * mu) % n

def add_encrypted(c1, c2, n2): return (c1 * c2) % n2

HOST, PORT = "127.0.0.1", 50007
server = socket.socket()
server.bind((HOST, PORT))
server.listen(5)
print(f"[SERVER] Payment Gateway running on {HOST}:{PORT}")

# Generate realistic Paillier keypair (bigger n avoids wraparound)
public_key, private_key = generate_paillier_keys(bits=512)   # 512-bit demo
n, g = public_key
n2 = n * n
print(f"[SERVER] Paillier Public Key (n size bits): {n.bit_length()} bits\n")

# Server loop: respond to "get_pubkey" or accept transaction payloads
while True:
    conn, addr = server.accept()
    try:
        raw = conn.recv(131072)
        if not raw:
            conn.close(); continue
        msg = json.loads(raw.decode())

        # If requested, return the public key (n,g)
        if isinstance(msg, dict) and msg.get("action") == "get_pubkey":
            conn.send(json.dumps({"n": str(n), "g": str(g)}).encode())
            conn.close()
            continue

        # Transaction payload
        seller = msg.get("seller")
        enc_txns = msg.get("encrypted", [])
        rsa_pub_components = msg.get("rsa_pub", [])
        signature = int(msg.get("signature", 0))

        # Reconstruct RSA public key and verify signature
        try:
            pub_rsa = RSA.construct((int(rsa_pub_components[0]), int(rsa_pub_components[1])))
            hash_val = SHA256.new(json.dumps(msg["transactions"]).encode())
            sig_bytes = signature.to_bytes((signature.bit_length() + 7)//8, "big")
            pkcs1_15.new(pub_rsa).verify(hash_val, sig_bytes)
            sig_ok = True
        except Exception:
            sig_ok = False

        # Homomorphic addition: multiply ciphertexts mod n^2
        total_encrypted = 1
        for c in enc_txns:
            ci = int(c)
            total_encrypted = add_encrypted(total_encrypted, ci, n2)

        total_decrypted = decrypt(total_encrypted, private_key, public_key)

        # (Optional) decrypt individuals for verification only
        decrypted_individual = [decrypt(int(c), private_key, public_key) for c in enc_txns]

        print(f"\n=== Department: {seller} ===")
        print(f"Original bill (for signature): {msg.get('transactions')}")
        print(f"Decrypted Individual (check): {decrypted_individual}")
        print(f"Total (Encrypted): {total_encrypted}")
        print(f"Total (Decrypted via Homomorphic): {total_decrypted}")
        print(f"Signature Verified: {sig_ok}")

        resp = {"seller": seller, "verified": sig_ok, "total": int(total_decrypted)}
        conn.send(json.dumps(resp).encode())

    except Exception as e:
        print("[SERVER] Error:", e)
    finally:
        conn.close()
