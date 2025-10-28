# server_paillier_homomorphic.py
import socket, json
from math import gcd
from Crypto.Util.number import getPrime
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# === Paillier Key Generation ===
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

# === Server Setup ===
HOST, PORT = "127.0.0.1", 50007
server = socket.socket()
server.bind((HOST, PORT))
server.listen(5)
print(f"[SERVER] Payment Gateway running on {HOST}:{PORT}")

# Generate Paillier keypair
public_key, private_key = generate_paillier_keys(bits=512)
n, g = public_key
n2 = n * n
print(f"[SERVER] Paillier Public Key generated ({n.bit_length()} bits)\n")

# Handle multiple sellers
seller_totals = {}

while True:
    conn, addr = server.accept()
    raw = conn.recv(131072)
    if not raw:
        conn.close()
        continue

    msg = json.loads(raw.decode())

    # Return public key if requested
    if msg.get("action") == "get_pubkey":
        conn.send(json.dumps({"n": str(n), "g": str(g)}).encode())
        conn.close()
        continue

    # Extract data
    seller = msg["seller"]
    enc_txns = msg["encrypted"]
    rsa_pub_components = msg["rsa_pub"]
    signature = int(msg["signature"])
    transactions = msg["transactions"]

    # Reconstruct RSA public key and verify signature
    pub_rsa = RSA.construct((int(rsa_pub_components[0]), int(rsa_pub_components[1])))
    hash_val = SHA256.new(json.dumps(transactions).encode())
    sig_bytes = signature.to_bytes((signature.bit_length() + 7)//8, "big")
    try:
        pkcs1_15.new(pub_rsa).verify(hash_val, sig_bytes)
        sig_ok = True
    except (ValueError, TypeError):
        sig_ok = False

    # Homomorphic addition of encrypted values
    total_encrypted = 1
    for c in enc_txns:
        total_encrypted = add_encrypted(total_encrypted, int(c), n2)

    total_decrypted = decrypt(total_encrypted, private_key, public_key)

    # Store seller total
    seller_totals[seller] = int(total_decrypted)

    print(f"\n=== Seller: {seller} ===")
    print(f"Transactions: {transactions}")
    print(f"Decrypted Total: {total_decrypted}")
    print(f"Signature Verified: {sig_ok}")

    # Send response
    conn.send(json.dumps({
        "seller": seller,
        "verified": sig_ok,
        "total": int(total_decrypted)
    }).encode())
    conn.close()

    # If both sellers have reported, aggregate them
    if len(seller_totals) == 2:
        print("\n=== Final Aggregation ===")
        combined = sum(seller_totals.values())
        print(f"Seller Totals: {seller_totals}")
        print(f"Combined Total (All Sellers): {combined}\n")
