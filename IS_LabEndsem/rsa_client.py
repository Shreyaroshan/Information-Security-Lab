import socket, json, random
from math import gcd

# === RSA Homomorphic Encryption ===
def generate_rsa_keys():
    p, q = 11, 13
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 7
    d = pow(e, -1, phi)
    return (e, n), (d, n)

def encrypt(m, pub):
    e, n = pub
    return pow(m, e, n)

# === ElGamal Digital Signature ===
def generate_elgamal_keys():
    p, g = 467, 2
    x = random.randint(2, p - 2)
    y = pow(g, x, p)
    return (p, g, y), x

def sign_elgamal(msg, priv, p, g):
    x = priv
    k = random.randint(2, p - 2)
    while gcd(k, p - 1) != 1:
        k = random.randint(2, p - 2)
    r = pow(g, k, p)
    s = ((msg - x * r) * pow(k, -1, p - 1)) % (p - 1)
    return r, s

# === Data per seller ===
sellers = {
    "Alice_Shop": [3, 4, 5],
    "Bob_Store": [2, 5, 6]
}

rsa_pub, _ = generate_rsa_keys()

for name, txns in sellers.items():
    enc_txns = [encrypt(t, rsa_pub) for t in txns]
    elg_pub, elg_priv = generate_elgamal_keys()
    m_val = sum(txns) % (elg_pub[0] - 1)
    sig = sign_elgamal(m_val, elg_priv, elg_pub[0], elg_pub[1])

    data = {
        "seller": name,
        "transactions": txns,
        "encrypted": enc_txns,
        "elgamal_pub": elg_pub,
        "signature": sig
    }

    client = socket.socket()
    client.connect(("127.0.0.1", 50008))
    client.send(json.dumps(data).encode())

    resp = json.loads(client.recv(4096).decode())
    print(f"\n=== Response for {name} ===")
    print(f"Signature OK: {resp['verified']}")
    print(f"Total (Decrypted by Server): {resp['total']}")
    client.close()
