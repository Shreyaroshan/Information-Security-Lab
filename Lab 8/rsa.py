# rsa_sse_fixed.py
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from base64 import b64encode, b64decode
from collections import defaultdict
import hashlib

# ----------------
# Dataset
# ----------------
documents = [
    "The quick brown fox jumps over the lazy dog",
    "A fox is quick and cunning",
    "Dogs are loyal and brave",
    "A lazy dog is not always a bad dog",
    "Foxes are found in many regions",
    "Bravery and loyalty are valued traits in dogs",
    "Quick thinking and agility are traits of a fox",
    "Foxes and dogs can sometimes be friends",
    "Loyal dogs protect their family",
    "Foxes often hunt alone"
]

# ----------------
# RSA keypair (client)
# ----------------
key = RSA.generate(2048)
pub = key.publickey()
encryptor = PKCS1_OAEP.new(pub)
decryptor = PKCS1_OAEP.new(key)

def rsa_encrypt_bytes(b: bytes) -> str:
    return b64encode(encryptor.encrypt(b)).decode()

def rsa_decrypt_str(s: str) -> bytes:
    return decryptor.decrypt(b64decode(s))

# ----------------
# deterministic term trapdoor (server-visible)
# ----------------
def trapdoor(term: str) -> str:
    return hashlib.sha256(term.strip().lower().encode()).hexdigest()

# ----------------
# build inverted index (plaintext), normalize words, dedupe
# ----------------
plaintext_index = defaultdict(set)
for doc_id, doc in enumerate(documents):
    for w in doc.lower().replace('.', '').replace(',', '').split():
        plaintext_index[w].add(doc_id)

# ----------------
# server: store hashed-term -> [RSA_encrypt(doc_id)]
# ----------------
encrypted_index = {}
for term, docid_set in plaintext_index.items():
    h = trapdoor(term)
    encrypted_index[h] = [rsa_encrypt_bytes(str(doc_id).encode()) for doc_id in sorted(docid_set)]

# ----------------
# client search
# ----------------
def search(query: str):
    h = trapdoor(query)
    enc_posting = encrypted_index.get(h, [])
    if not enc_posting:
        return []
    doc_ids = [int(rsa_decrypt_str(enc).decode()) for enc in enc_posting]
    return doc_ids

if __name__ == "__main__":
    q = "fox"
    ids = search(q)
    print("Query:", q)
    for i in ids:
        print(f"Doc {i}: {documents[i]}")
