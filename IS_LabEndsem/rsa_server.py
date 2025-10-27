import socket, json, math

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

def decrypt(c, priv):
    d, n = priv
    return pow(c, d, n)

# === ElGamal Signature Verification ===
def verify_elgamal_signature(msg, r, s, pub, p, g):
    y = pub
    lhs = (pow(y, r, p) * pow(r, s, p)) % p
    rhs = pow(g, msg, p)
    return lhs == rhs

# === SERVER SETUP ===
HOST, PORT = "127.0.0.1", 50008
server = socket.socket()
server.bind((HOST, PORT))
server.listen(5)
print(f"[SERVER] RSA Homomorphic Server running on {HOST}:{PORT}")

rsa_pub, rsa_priv = generate_rsa_keys()
print(f"[SERVER] RSA Public Key: {rsa_pub}\n")

while True:
    conn, addr = server.accept()
    print(f"\n[SERVER] Connected with {addr}")
    data = conn.recv(4096).decode()
    if not data:
        conn.close()
        continue

    msg = json.loads(data)
    seller = msg["seller"]
    enc_txns = msg["encrypted"]
    p, g, y = msg["elgamal_pub"]
    r, s = msg["signature"]
    txns = msg["transactions"]

    # Verify ElGamal signature (hash can be simplified to sum(txns))
    m_val = sum(txns) % (p - 1)
    sig_ok = verify_elgamal_signature(m_val, r, s, y, p, g)

    # Homomorphic combination (multiplicative)
    total_enc = 1
    for c in enc_txns:
        total_enc = (total_enc * c) % rsa_pub[1]
    total_dec = decrypt(total_enc, rsa_priv)

    print(f"\n=== Seller: {seller} ===")
    print(f"Transactions: {txns}")
    print(f"Encrypted: {enc_txns}")
    print(f"Decrypted Individually: {[decrypt(c, rsa_priv) for c in enc_txns]}")
    print(f"Total (Encrypted Product): {total_enc}")
    print(f"Total (Decrypted): {total_dec}")
    print(f"Signature Verified: {sig_ok}")

    conn.send(json.dumps({"seller": seller, "verified": sig_ok, "total": total_dec}).encode())
    conn.close()
