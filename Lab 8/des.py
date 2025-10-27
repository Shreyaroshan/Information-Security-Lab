# des_sse_fixed.py
import os
from collections import defaultdict
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
import hashlib

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

# Symmetric key for DES (client & server share)
DES_KEY = os.urandom(8)  # 8 bytes (64-bit), small but for lab only

def des_encrypt_str(plain: str) -> str:
    iv = os.urandom(8)
    cipher = DES.new(DES_KEY, DES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plain.encode(), DES.block_size))
    return b64encode(iv + ct).decode()

def des_decrypt_str(enc_b64: str) -> str:
    data = b64decode(enc_b64)
    iv = data[:8]
    ct = data[8:]
    cipher = DES.new(DES_KEY, DES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), DES.block_size).decode()

def trapdoor(term: str) -> str:
    return hashlib.sha256(term.strip().lower().encode()).hexdigest()

# Build index
plaintext_index = defaultdict(set)
for doc_id, doc in enumerate(documents):
    for w in doc.lower().replace('.', '').replace(',', '').split():
        plaintext_index[w].add(doc_id)

# Server: store hashed term -> [DES_encrypt(doc_id as string)]
encrypted_index = {}
for term, ids in plaintext_index.items():
    h = trapdoor(term)
    encrypted_index[h] = [des_encrypt_str(str(i)) for i in sorted(ids)]

# Client search: compute trapdoor, server returns enc posting, client decrypts
def search(query: str):
    h = trapdoor(query)
    enc_posting = encrypted_index.get(h, [])
    return [int(des_decrypt_str(e)) for e in enc_posting]

if __name__ == "__main__":
    q = "dog"
    ids = search(q)
    print("Query:", q)
    for i in ids:
        print(f"Doc {i}: {documents[i]}")
