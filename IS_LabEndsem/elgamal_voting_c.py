import socket, json, random
from math import gcd

# === ElGamal Setup ===
p = 104729  # large prime
g = 2
d = 12345
e1 = pow(g, d, p)

def encrypt(m, pub_key):
    p, g, e1 = pub_key
    r = random.randint(1, p - 2)
    c1 = pow(g, r, p)
    c2 = (m * pow(e1, r, p)) % p
    return (c1, c2)

def sign_message(msg_hash, priv_key):
    p, g, d = priv_key
    while True:
        k = random.randint(1, p - 2)
        if gcd(k, p - 1) == 1:
            break
    r = pow(g, k, p)
    s = ((msg_hash - d * r) * pow(k, -1, p - 1)) % (p - 1)
    return (r, s)

# Two booths with 3 votes each
booths = {
    "Booth_1": [4, 3, 5],   # votes encoded numerically
    "Booth_2": [2, 3, 4]
}

pub_key = (p, g, e1)
priv_key = (p, g, d)

for booth, votes in booths.items():
    encrypted_votes = [encrypt(v, pub_key) for v in votes]
    msg_hash = sum(votes) % p
    signature = sign_message(msg_hash, priv_key)

    data = {
        "booth": booth,
        "encrypted_votes": encrypted_votes,
        "msg_hash": msg_hash,
        "signature": signature
    }

    client = socket.socket()
    client.connect(("127.0.0.1", 50005))
    client.send(json.dumps(data).encode())

    response = json.loads(client.recv(4096).decode())
    print(f"\n=== Response for {booth} ===")
    print(f"Signature Verified: {response['verified']}")
    print(f"Booth Total (Decrypted by Server): {response['booth_total']}")
    client.close()
