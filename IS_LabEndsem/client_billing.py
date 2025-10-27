import socket, json, random
from math import gcd
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

def lcm(x, y): return x * y // gcd(x, y)

def encrypt_paillier(m, pub):
    n = int(pub[0]); g = int(pub[1])
    n2 = n * n
    # Choose random r with gcd(r,n)=1
    r = random.randint(1, n - 1)
    while gcd(r, n) != 1:
        r = random.randint(1, n - 1)
    return (pow(g, m, n2) * pow(r, n, n2)) % n2

def sign_data(data_list, priv_key):
    h = SHA256.new(json.dumps(data_list).encode())
    sig = pkcs1_15.new(priv_key).sign(h)
    return int.from_bytes(sig, "big")

HOST, PORT = "127.0.0.1", 50007

sellers = {
    "Cardiology": [1000, 2000, 1500],
    "Neurology": [500, 1200, 800]
}

def get_paillier_pubkey():
    s = socket.socket()
    s.connect((HOST, PORT))
    s.send(json.dumps({"action":"get_pubkey"}).encode())
    resp_raw = s.recv(131072)
    s.close()
    if not resp_raw:
        raise RuntimeError("Failed to get public key")
    resp = json.loads(resp_raw.decode())
    return (int(resp["n"]), int(resp["g"]))

paillier_pub = get_paillier_pubkey()
print("[CLIENT] Received Paillier public key (n bit length):", paillier_pub[0].bit_length())

for name, txns in sellers.items():
    rsa_key = RSA.generate(2048)   # stronger RSA for lab demo
    rsa_pub = rsa_key.publickey()

    # Encrypt with server's public key
    encrypted = [encrypt_paillier(int(m), paillier_pub) for m in txns]

    # Sign plaintext transactions
    signature = sign_data(txns, rsa_key)

    payload = {
        "seller": name,
        "transactions": txns,
        "encrypted": [str(e) for e in encrypted],   # send as strings to be safe with JSON
        "rsa_pub": [str(rsa_pub.n), str(rsa_pub.e)],
        "signature": signature
    }

    try:
        client = socket.socket()
        client.connect((HOST, PORT))
        client.send(json.dumps(payload).encode())

        resp_raw = client.recv(131072)
        if not resp_raw:
            print(f"[CLIENT] Empty server response for {name}")
            client.close(); continue
        resp = json.loads(resp_raw.decode())
        print(f"\n=== Response for {name} ===")
        print(f"Signature Verified: {resp.get('verified')}")
        print(f"Total Amount (Decrypted by Server): {resp.get('total')}")
    except ConnectionRefusedError:
        print("[CLIENT] Server not running?")
        break
    finally:
        client.close()