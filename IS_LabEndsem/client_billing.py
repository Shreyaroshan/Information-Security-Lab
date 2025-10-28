# client_paillier_homomorphic_two_sellers.py
import socket, json, random, time
from Crypto.Util.number import getPrime
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# ---------- Paillier Encryption ----------
def encrypt(m, pub):
    n, g = pub
    n2 = n * n
    r = random.randint(1, n - 1)
    return (pow(g, m, n2) * pow(r, n, n2)) % n2

# ---------- Connection Helper ----------
def send_recv(data, host="127.0.0.1", port=50007):
    s = socket.socket()
    s.connect((host, port))
    s.send(json.dumps(data).encode())
    response = json.loads(s.recv(131072).decode())
    s.close()
    return response

# ---------- Request Paillier Public Key ----------
print("[CLIENT] Requesting Paillier public key from Payment Gateway...")
pubkey_resp = send_recv({"action": "get_pubkey"})

n = int(pubkey_resp["n"])
g = int(pubkey_resp["g"])
public_key = (n, g)
print("[CLIENT] Received Paillier Public Key\n")

# ---------- Function to simulate a seller ----------
def send_seller_data(seller_name, transactions):
    rsa_key = RSA.generate(1024)
    rsa_pub = (rsa_key.n, rsa_key.e)

    # Encrypt transactions
    encrypted_txns = [encrypt(m, public_key) for m in transactions]

    # Sign the original transaction list
    msg_hash = SHA256.new(json.dumps(transactions).encode())
    signature_bytes = pkcs1_15.new(rsa_key).sign(msg_hash)
    signature_int = int.from_bytes(signature_bytes, "big")

    payload = {
        "seller": seller_name,
        "transactions": transactions,
        "encrypted": [str(c) for c in encrypted_txns],
        "rsa_pub": [str(rsa_pub[0]), str(rsa_pub[1])],
        "signature": str(signature_int)
    }

    print(f"[CLIENT] Sending data for {seller_name}...")
    resp = send_recv(payload)
    print(f"Response for {seller_name}: {resp}\n")

# ---------- Two Sellers ----------
seller1 = ("Electronics_Department", [1200, 800, 500, 700])
seller2 = ("Clothing_Department", [900, 650, 450, 400])

send_seller_data(*seller1)
time.sleep(1)
send_seller_data(*seller2)
