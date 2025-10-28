# server_paillier_elgamal.py
import socket, json, random
from math import gcd
from Crypto.Util.number import getPrime

# ---------------- Paillier ---------------- #
def lcm(x, y): return x * y // gcd(x, y)

def generate_paillier_keys(bits=512):
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

# ---------------- ElGamal Verify ---------------- #
def verify_elgamal(m_hash, r, s, p, g, y):
    if not (1 < r < p):
        return False
    v1 = (pow(y, r, p) * pow(r, s, p)) % p
    v2 = pow(g, m_hash, p)
    return v1 == v2

# ---------------- Server Setup ---------------- #
HOST, PORT = "127.0.0.1", 50007
server = socket.socket()
server.bind((HOST, PORT))
server.listen(5)
print(f"[SERVER] Payment Gateway running on {HOST}:{PORT}")

public_key, private_key = generate_paillier_keys(bits=512)
n, g = public_key
n2 = n * n
print(f"[SERVER] Paillier Public Key generated ({n.bit_length()} bits)\n")

while True:
    conn, addr = server.accept()
    data = conn.recv(131072)
    if not data:
        conn.close()
        continue

    msg = json.loads(data.decode())

    # If requesting public key
    if msg.get("action") == "get_pubkey":
        conn.send(json.dumps({"n": str(n), "g": str(g)}).encode())
        conn.close()
        continue

    # Process seller transaction
    seller = msg["seller"]
    enc_txns = [int(c) for c in msg["encrypted"]]
    p, g_elg, y = msg["elgamal_pub"]
    r, s = msg["signature"]
    m_hash = int.from_bytes(json.dumps(msg["transactions"]).encode(), "big")

    # Verify ElGamal signature
    verified = verify_elgamal(m_hash, r, s, p, g_elg, y)

    # Homomorphic addition
    total_enc = 1
    for c in enc_txns:
        total_enc = add_encrypted(total_enc, c, n2)
    total_dec = decrypt(total_enc, private_key, public_key)

    print(f"\n=== Department: {seller} ===")
    print(f"Transactions: {msg['transactions']}")
    print(f"Signature Verified: {verified}")
    print(f"Total Bill (Decrypted): {total_dec}")

    conn.send(json.dumps({
        "seller": seller,
        "verified": verified,
        "total": int(total_dec)
    }).encode())

    conn.close()
