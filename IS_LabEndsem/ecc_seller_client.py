import socket, json, random
from math import gcd
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.Util.number import getPrime

# === Utility ===
def lcm(x, y): return x * y // gcd(x, y)

# === Paillier Key Generation (client can use same public key as server) ===
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

def encrypt(m, pub):
    """Paillier encryption: c = g^m * r^n mod n^2"""
    n, g = pub
    n2 = n * n
    r = random.randint(1, n - 1)
    while gcd(r, n) != 1:
        r = random.randint(1, n - 1)
    return (pow(g, m, n2) * pow(r, n, n2)) % n2

def sign_data(data, priv_key):
    """ECC digital signature on transaction data."""
    h = SHA256.new(json.dumps(data, sort_keys=True).encode())
    signer = DSS.new(priv_key, 'fips-186-3')
    return signer.sign(h).hex()

# === Sellers’ Transaction Data ===
sellers = {
    "Alice_Shop": [120, 200, 330],
    "Bob_Store": [150, 270, 180]
}

# === Step 1: Get Paillier Public Key from Server ===
client = socket.socket()
client.connect(("127.0.0.1", 50007))
client.send(json.dumps({"action": "get_pubkey"}).encode())
resp = json.loads(client.recv(8192).decode())
client.close()

# Convert n, g to int
n, g = int(resp["n"]), int(resp["g"])
public_key = (n, g)
print(f"🔑 Received Paillier Public Key from Server: n={n.bit_length()} bits")

# === Step 2: Send Encrypted & Signed Transactions ===
for name, txs in sellers.items():
    # Generate ECC key pair (per seller)
    ecc_key = ECC.generate(curve='P-256')
    ecc_pub = ecc_key.public_key()

    # Encrypt all transactions with Paillier
    encrypted = [encrypt(t, public_key) for t in txs]

    # Sign the plaintext transactions
    signature = sign_data(txs, ecc_key)

    payload = {
        "seller": name,
        "transactions": txs,
        "encrypted": encrypted,
        "ecc_pub": [int(ecc_pub.pointQ.x), int(ecc_pub.pointQ.y)],
        "signature": signature
    }

    # Send to server
    client = socket.socket()
    client.connect(("127.0.0.1", 50007))
    client.send(json.dumps(payload).encode())

    # Receive response
    response = json.loads(client.recv(8192).decode())
    client.close()

    print(f"\n=== 🏪 Seller: {name} ===")
    if "error" in response:
        print(f"⚠️ Error from server: {response['error']}")
    else:
        print(f"✅ Signature Verified: {response['verified']}")
        print(f"💰 Total (Decrypted by Server): {response['total']}")
