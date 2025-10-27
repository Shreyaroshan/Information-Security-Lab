import socket, json
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.Util.number import getPrime
from math import gcd

# === Paillier Key Generation ===
def lcm(x, y):
    return x * y // gcd(x, y)

def generate_paillier_keys(bits=1024):
    p = getPrime(bits)
    q = getPrime(bits)
    n = p * q
    n2 = n * n
    lam = lcm(p - 1, q - 1)
    g = n + 1
    def L(x): return (x - 1) // n
    mu = pow(L(pow(g, lam, n2)), -1, n)
    return (n, g), (lam, mu)

def decrypt(c, priv, pub):
    """Decrypt a Paillier ciphertext."""
    lam, mu = priv
    n, g = pub
    n2 = n * n
    def L(x): return (x - 1) // n
    return (L(pow(c, lam, n2)) * mu) % n

def add_encrypted(c1, c2, n2):
    """Homomorphic addition in Paillier = ciphertext multiplication mod n^2"""
    return (c1 * c2) % n2

# === ECC Signature Verification ===
def verify_signature(data, signature_hex, ecc_pub):
    """Verify ECC signature using received public key."""
    try:
        h = SHA256.new(json.dumps(data, sort_keys=True).encode())
        verifier = DSS.new(ecc_pub, 'fips-186-3')
        verifier.verify(h, bytes.fromhex(signature_hex))
        return True
    except Exception:
        return False

# === Generate Paillier Keys (Server) ===
public_key, private_key = generate_paillier_keys()
n, g = public_key
n2 = n * n

# === Start Server ===
server = socket.socket()
server.bind(("127.0.0.1", 50007))
server.listen(5)
print("🚀 ECC–Paillier Secure Payment Gateway running on port 50007...")

while True:
    conn, addr = server.accept()
    data_raw = conn.recv(8192)
    if not data_raw:
        conn.close()
        continue

    try:
        data = json.loads(data_raw.decode())

        # ✅ Handle public key request
        if data.get("action") == "get_pubkey":
            conn.send(json.dumps({"n": n, "g": g}).encode())
            conn.close()
            continue

        # === Process Transaction Payload ===
        seller = data["seller"]
        enc_txns = data["encrypted"]
        signature = data["signature"]
        transactions = data["transactions"]
        ecc_pub_data = data["ecc_pub"]

        # Reconstruct ECC Public Key
        ecc_pub = ECC.construct(curve='P-256',
                                point_x=int(ecc_pub_data[0]),
                                point_y=int(ecc_pub_data[1]))

        # Verify Signature
        verified = verify_signature(transactions, signature, ecc_pub)

        # Homomorphic addition of encrypted transactions
        total_encrypted = 1
        for c in enc_txns:
            total_encrypted = add_encrypted(total_encrypted, int(c), n2)

        # Decrypt results
        decrypted_individual = [decrypt(int(c), private_key, public_key) for c in enc_txns]
        total_decrypted = decrypt(total_encrypted, private_key, public_key)

        print(f"\n=== Seller: {seller} ===")
        print(f"🧾 Transactions: {transactions}")
        print(f"🔓 Decrypted Individual Amounts: {decrypted_individual}")
        print(f"💰 Total (Decrypted): {total_decrypted}")
        print(f"✅ Signature Verified: {verified}")

        # === Send Response ===
        response = {
            "seller": seller,
            "verified": verified,
            "total": int(total_decrypted)
        }
        conn.send(json.dumps(response).encode())
        conn.close()

    except Exception as e:
        print(f"❌ Error: {e}")
        conn.close()
