# paillier_elgamal_client.py
import socket, json, random, hashlib
from math import gcd
from Crypto.Util.number import getPrime

# ---------------- ElGamal Signature Functions ---------------- #
def generate_elgamal_keys(bits=256):
    p = getPrime(bits)
    g = random.randint(2, p - 2)
    x = random.randint(2, p - 2)  # private key
    y = pow(g, x, p)              # public key
    return (p, g, y), x

def sign_elgamal(m_hash, p, g, x):
    while True:
        k = random.randint(2, p - 2)
        if gcd(k, p - 1) == 1:
            break
    r = pow(g, k, p)
    s = ((m_hash - x * r) * pow(k, -1, p - 1)) % (p - 1)
    return r, s

# ---------------- Paillier Encryption ---------------- #
def encrypt_paillier(m, n, g):
    n2 = n * n
    r = random.randint(1, n - 1)
    return (pow(g, m, n2) * pow(r, n, n2)) % n2

# ---------------- Network ---------------- #
def get_public_key():
    sock = socket.socket()
    sock.connect(("127.0.0.1", 50007))
    sock.send(json.dumps({"action": "get_pubkey"}).encode())
    resp = json.loads(sock.recv(8192).decode())
    sock.close()
    return int(resp["n"]), int(resp["g"])

def send_seller_data(seller_name, transactions, pub_elgamal, priv_elgamal, n, g):
    p, g_elg, y = pub_elgamal
    x = priv_elgamal
    enc_txns = [encrypt_paillier(val, n, g) for val in transactions]

    # Hash message for signing
    m_hash = int(hashlib.sha256(json.dumps(transactions).encode()).hexdigest(), 16)
    r, s = sign_elgamal(m_hash, p, g_elg, x)

    msg = {
        "seller": seller_name,
        "transactions": transactions,
        "encrypted": enc_txns,
        "elgamal_pub": [p, g_elg, y],
        "signature": [r, s],
    }

    sock = socket.socket()
    sock.connect(("127.0.0.1", 50007))
    sock.send(json.dumps(msg).encode())
    response = json.loads(sock.recv(8192).decode())
    sock.close()

    print(f"\n--- Response from Server for {seller_name} ---")
    print(response)

# ---------------- MAIN ---------------- #
if __name__ == "__main__":
    n, g = get_public_key()

    # Seller 1
    pub1, priv1 = generate_elgamal_keys()
    seller1 = ("Electronics Dept", [1200, 800, 450], pub1, priv1)

    # Seller 2
    pub2, priv2 = generate_elgamal_keys()
    seller2 = ("Grocery Dept", [300, 500, 200], pub2, priv2)

    # Send both sellers’ data
    send_seller_data(*seller1, n, g)
    send_seller_data(*seller2, n, g)
