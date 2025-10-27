import socket, json

# === ElGamal Key Setup ===
p = 104729  # large prime
g = 2
d = 12345
e1 = pow(g, d, p)

# === ElGamal Decryption ===
def decrypt(cipher, priv_key):
    c1, c2 = cipher
    p, g, d = priv_key
    s = pow(c1, d, p)
    s_inv = pow(s, -1, p)
    return (c2 * s_inv) % p

# === ElGamal Signature Verification ===
def verify_signature(msg_hash, sig, pub_key):
    p, g, e1 = pub_key
    r, s = sig
    if not (0 < r < p):
        return False
    v1 = (pow(e1, r, p) * pow(r, s, p)) % p
    v2 = pow(g, msg_hash, p)
    return v1 == v2

# === Server Setup ===
server = socket.socket()
server.bind(("127.0.0.1", 50005))
server.listen(5)
print("🗳️ Election Server Running...\n")

pub_key = (p, g, e1)
priv_key = (p, g, d)

# Store all encrypted votes from multiple booths
aggregated_cipher = None

while True:
    conn, _ = server.accept()
    data = json.loads(conn.recv(4096).decode())

    booth = data["booth"]
    ciphertexts = data["encrypted_votes"]
    signature = tuple(data["signature"])
    msg_hash = data["msg_hash"]

    verified = verify_signature(msg_hash, signature, pub_key)

    # Multiply ciphertexts homomorphically to get encrypted total for this booth
    total_cipher = (1, 1)
    for c1, c2 in ciphertexts:
        total_cipher = ((total_cipher[0] * c1) % p, (total_cipher[1] * c2) % p)

    # Decrypt booth total (for display)
    booth_total = decrypt(total_cipher, priv_key)

    print(f"=== Booth: {booth} ===")
    print(f"Encrypted Votes: {ciphertexts}")
    print(f"Decrypted Individual (for check): {[decrypt(tuple(c), priv_key) for c in ciphertexts]}")
    print(f"Booth Total (Decrypted via Homomorphic): {booth_total}")
    print(f"Signature Verified: {verified}\n")

    # Aggregate homomorphically across booths
    if aggregated_cipher is None:
        aggregated_cipher = total_cipher
    else:
        aggregated_cipher = (
            (aggregated_cipher[0] * total_cipher[0]) % p,
            (aggregated_cipher[1] * total_cipher[1]) % p
        )

    conn.send(json.dumps({
        "verified": verified,
        "booth_total": booth_total
    }).encode())
    conn.close()

    # After both booths have sent, show total
    if booth == "Booth_2":
        final_total = decrypt(aggregated_cipher, priv_key)
        print("=== 🧾 Final Aggregated Total ===")
        print(f"Encrypted Total (All Booths): {aggregated_cipher}")
        print(f"Decrypted Final Total: {final_total}\n")
        break
