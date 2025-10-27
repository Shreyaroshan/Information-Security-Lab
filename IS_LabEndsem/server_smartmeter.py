# server_smartmeter.py
import socket
import json
from math import gcd
from Crypto.Util.number import getPrime
from Crypto.Hash import SHA256
from Crypto.Signature import DSS
from Crypto.PublicKey import ECC

# ---------- Paillier helpers ----------
def lcm(a, b):
    from math import gcd
    return a // gcd(a, b) * b

def generate_paillier_keys(bits=512):
    p = getPrime(bits // 2)
    q = getPrime(bits // 2)
    while q == p:
        q = getPrime(bits // 2)
    n = p * q
    n2 = n * n
    lam = lcm(p - 1, q - 1)
    g = n + 1
    def L(u): return (u - 1) // n
    mu = pow(L(pow(g, lam, n2)), -1, n)
    return (n, g), (lam, mu)

def paillier_decrypt(cipher_int, privkey, pubkey):
    n, g = pubkey
    lam, mu = privkey
    n2 = n * n
    def L(u): return (u - 1) // n
    x = pow(cipher_int, lam, n2)
    return (L(x) * mu) % n

def paillier_homomorphic_add(c1, c2, n2):
    return (c1 * c2) % n2

# ---------- ECC signature verification ----------
def verify_ecc_signature(ecc_pub_pem: str, message_bytes: bytes, signature_bytes: bytes) -> bool:
    try:
        pub = ECC.import_key(ecc_pub_pem)
        h = SHA256.new(message_bytes)
        verifier = DSS.new(pub, 'fips-186-3')
        verifier.verify(h, signature_bytes)
        return True
    except (ValueError, TypeError):
        return False

# ---------- Server state ----------
HOST = '127.0.0.1'
PORT = 52000

PAILLIER_BITS = 512
paillier_pub, paillier_priv = generate_paillier_keys(bits=PAILLIER_BITS)
n, g = paillier_pub
n2 = n * n
print(f"[SERVER] Paillier public key generated. n bits = {n.bit_length()}")

# Running encrypted aggregate and total count
aggregated_encrypted_sum = None
total_readings_count = 0

# ---------- Server protocol:
# action = "get_pubkey" -> returns {"n":"...", "g":"..."}
# action = "submit" -> expect device payload (encrypted_readings list of strings,
#    plain_summary={"count":..., "sum":...}, ecc_pub PEM, signature hex)
# action = "finish" -> decrypt aggregated sum and return totals
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind((HOST, PORT))
sock.listen(10)
print(f"[SERVER] Listening on {HOST}:{PORT} ...")

try:
    while True:
        conn, addr = sock.accept()
        raw = conn.recv(262144)
        if not raw:
            conn.close(); continue
        try:
            msg = json.loads(raw.decode())
        except Exception as e:
            conn.send(json.dumps({"error":"invalid json"}).encode()); conn.close(); continue

        action = msg.get("action")
        if action == "get_pubkey":
            # return public key as strings
            conn.send(json.dumps({"n": str(n), "g": str(g)}).encode())
            conn.close()
            continue

        if action == "finish":
            if aggregated_encrypted_sum is None:
                resp = {"total_sum": 0, "average": None, "count": total_readings_count}
            else:
                total_sum = paillier_decrypt(int(aggregated_encrypted_sum), paillier_priv, paillier_pub)
                avg = total_sum / total_readings_count if total_readings_count > 0 else None
                resp = {"total_sum": int(total_sum), "average": avg, "count": total_readings_count}
            conn.send(json.dumps(resp).encode())
            conn.close()
            continue

        if action == "submit":
            device_id = msg.get("device_id")
            enc_readings = msg.get("encrypted_readings", [])  # list of strings
            ecc_pub_pem = msg.get("ecc_pub")
            signature_hex = msg.get("signature")
            plain_summary = msg.get("plain_summary", {})  # signed data

            # verify signature: device signs JSON of plain_summary deterministically
            message_bytes = json.dumps(plain_summary, sort_keys=True).encode()
            sig_bytes = bytes.fromhex(signature_hex)
            sig_ok = verify_ecc_signature(ecc_pub_pem, message_bytes, sig_bytes)

            # compute device total encrypted by multiplying its ciphertexts
            device_total_enc = 1
            for cstr in enc_readings:
                ci = int(cstr)
                device_total_enc = paillier_homomorphic_add(device_total_enc, ci, n2)

            # update global aggregated encrypted sum
            if aggregated_encrypted_sum is None:
                aggregated_encrypted_sum = device_total_enc
            else:
                aggregated_encrypted_sum = paillier_homomorphic_add(aggregated_encrypted_sum, device_total_enc, n2)

            # update counts (trust signed plain_summary count)
            device_count = int(plain_summary.get("count", len(enc_readings)))
            total_readings_count += device_count

            # Log (optional) - do not reveal decrypted totals in real privacy-preserving design
            print(f"[SERVER] Received from {device_id}: sig_ok={sig_ok}, device_count={device_count}")

            conn.send(json.dumps({"status":"ok", "sig_ok": bool(sig_ok)}).encode())
            conn.close()
            continue

        # unknown action
        conn.send(json.dumps({"error":"unknown action"}).encode())
        conn.close()
finally:
    sock.close()
