# pkse_rsa_simulation.py
import hashlib
from collections import defaultdict
from Crypto.PublicKey import RSA

# -------------------------
# Utility: Textbook RSA (deterministic) helpers
# -------------------------
def int_to_bytes(x: int, size: int) -> bytes:
    return x.to_bytes(size, byteorder='big')

def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, byteorder='big')

def rsa_textbook_encrypt_bytes(pubkey: RSA.RsaKey, data: bytes) -> str:
    """
    Textbook (raw) RSA encryption: c = m^e mod n
    Returns hex string of ciphertext.
    WARNING: Not secure in practice; used here to produce deterministic tokens.
    """
    m = bytes_to_int(data)
    c = pow(m, pubkey.e, pubkey.n)
    # output as hex string
    return format(c, 'x')

def rsa_textbook_decrypt_hex(privkey: RSA.RsaKey, hex_str: str) -> bytes:
    c = int(hex_str, 16)
    m = pow(c, privkey.d, privkey.n)
    # convert back to bytes (pad to modulus size)
    k = (privkey.n.bit_length() + 7) // 8
    return int_to_bytes(m, k).lstrip(b'\x00')

# -------------------------
# Step 0: dataset
# -------------------------
documents = [
    "the quick brown fox jumps over the lazy dog",
    "a fox is quick and agile",
    "dogs are loyal and brave",
    "a lazy dog is not always a bad dog",
    "foxes are found in many regions",
    "bravery and loyalty are traits of dogs",
    "quick thinking and agility are traits of a fox",
    "foxes and dogs can sometimes be friends",
    "loyal dogs protect their family",
    "foxes often hunt alone"
]

# -------------------------
# Step 1: RSA key generation (client)
# -------------------------
# 2048-bit RSA key for reasonable size. Client holds private key.
client_key = RSA.generate(2048)
client_pub = client_key.publickey()

# -------------------------
# Step 2: Build plaintext inverted index (server-side)
# -------------------------
def normalize_token(tok: str) -> str:
    return tok.strip().lower().strip('.,!?;:"()[]')

plaintext_index = defaultdict(list)
for doc_id, doc in enumerate(documents):
    for tok in doc.split():
        w = normalize_token(tok)
        if doc_id not in plaintext_index[w]:
            plaintext_index[w].append(doc_id)

# -------------------------
# Step 3: Server builds PKSE index:
#    - For each term t: compute deterministic token = RSA_pub( SHA256(t) )
#    - Store mapping token -> [ RSA_pub_encrypt(doc_id) , ... ]
# Server only stores ciphertext hex strings, cannot decrypt doc_ids
# -------------------------
def term_token(term: str) -> str:
    """Deterministic token for a term (client & server can compute)"""
    h = hashlib.sha256(term.encode('utf-8')).digest()
    # use deterministic textbook RSA encryption of hash to produce token
    return rsa_textbook_encrypt_bytes(client_pub, h)

def rsa_encrypt_docid(pubkey: RSA.RsaKey, doc_id: int) -> str:
    """Deterministic RSA encryption of doc id integer (as bytes)"""
    # represent doc_id as bytes
    m = str(doc_id).encode('utf-8')
    return rsa_textbook_encrypt_bytes(pubkey, m)

def rsa_decrypt_docid(privkey: RSA.RsaKey, hex_str: str) -> int:
    b = rsa_textbook_decrypt_hex(privkey, hex_str)
    return int(b.decode('utf-8'))

# Build encrypted index on server
encrypted_index = {}
for term, doc_list in plaintext_index.items():
    tok = term_token(term)  # deterministic token (hex)
    encrypted_docs = [rsa_encrypt_docid(client_pub, doc_id) for doc_id in doc_list]
    encrypted_index[tok] = encrypted_docs

# -------------------------
# Step 4: Search workflow
#   - Client computes token for query term and sends it to server
#   - Server looks up token and returns list of RSA-encrypted docIDs
#   - Client decrypts docIDs and displays documents
# -------------------------
def server_lookup(token_hex: str):
    return encrypted_index.get(token_hex, [])

def client_search_and_display(query: str):
    tok = term_token(query.lower())
    enc_doclist = server_lookup(tok)
    if not enc_doclist:
        print(f"No documents found for '{query}'")
        return
    # client decrypts doc ids
    doc_ids = [rsa_decrypt_docid(client_key, enc) for enc in enc_doclist]
    print(f"Documents matching '{query}' (doc ids): {doc_ids}")
    for i in doc_ids:
        print(f"Doc {i}: {documents[i]}")

# -------------------------
# Example usage
# -------------------------
if __name__ == "__main__":
    print("=== PKSE (textbook RSA) simulation ===")
    client_search_and_display("fox")
    print()
    client_search_and_display("dog")
    print()
    client_search_and_display("loyal")
