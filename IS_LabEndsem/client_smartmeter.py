# client_smartmeter.py
import socket
import json
import random
from math import gcd
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

# ---------- Paillier encrypt (client only needs pubkey) ----------
def encrypt_paillier(m: int, pubkey):
    n, g = pubkey
    n2 = n * n
    r = random.randint(1, n - 1)
    while gcd(r, n) != 1:
        r = random.randint(1, n - 1)
    c = (pow(g, m, n2) * pow(r, n, n2)) % n2
    return c

# ---------- ECC signature helpers ----------
def generate_ecc_keypair():
    key = ECC.generate(curve='P-256')
    return key, key.public_key()

def sign_with_ecc(priv_key, message_bytes):
    h = SHA256.new(message_bytes)
    signer = DSS.new(priv_key, 'fips-186-3')
    return signer.sign(h)

# ---------- Server contact helpers ----------
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 52000

def get_paillier_pubkey():
    s = socket.socket()
    s.connect((SERVER_HOST, SERVER_PORT))
    s.send(json.dumps({"action":"get_pubkey"}).encode())
    raw = s.recv(262144)
    s.close()
    if not raw:
        raise RuntimeError("No response for pubkey")
    resp = json.loads(raw.decode())
    return (int(resp['n']), int(resp['g']))

# ---------- Main client flow ----------
if __name__ == "__main__":
    device_id = input("Device id (sensor_1): ").strip() or "sensor_1"
    # simulate 3 readings
    readings = [random.randint(2, 10) for _ in range(3)]
    print(f"[CLIENT] Readings: {readings}")

    # obtain Paillier pubkey
    pub = get_paillier_pubkey()
    print(f"[CLIENT] Received Paillier public key (n bits = {pub[0].bit_length()})")

    # encrypt readings
    enc = [str(encrypt_paillier(int(m), pub)) for m in readings]

    # generate ECC keypair and sign plaintext summary
    ecc_priv, ecc_pub = generate_ecc_keypair()
    plain_summary = {"count": len(readings), "sum": sum(readings)}
    msg_bytes = json.dumps(plain_summary, sort_keys=True).encode()
    sig_bytes = sign_with_ecc(ecc_priv, msg_bytes)
    signature_hex = sig_bytes.hex()
    ecc_pub_pem = ecc_pub.export_key(format='PEM')

    payload = {
        "action": "submit",
        "device_id": device_id,
        "encrypted_readings": enc,
        "plain_summary": plain_summary,
        "ecc_pub": ecc_pub_pem,
        "signature": signature_hex
    }

    s = socket.socket()
    s.connect((SERVER_HOST, SERVER_PORT))
    s.send(json.dumps(payload).encode())
    resp_raw = s.recv(262144)
    s.close()
    resp = json.loads(resp_raw.decode())
    print(f"[CLIENT] Server response: {resp}")
    print("[CLIENT] Done. Run this client multiple times (or with different device ids).")
    print("When finished, request final aggregation using the 'finish' action (see README).")
