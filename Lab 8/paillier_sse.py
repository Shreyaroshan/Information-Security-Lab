# paillier_sse_example.py
import hashlib
from collections import defaultdict
from phe import paillier

# -----------------------
# Step 0: Dataset
# -----------------------
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

# -----------------------
# Step 1: Key generation (client side)
# -----------------------
public_key, private_key = paillier.generate_paillier_keypair(n_length=1024)
# public_key -> can be shared with server; private_key stays with client.

# -----------------------
# Utility: deterministic term hashing
# -----------------------
def term_hash(term: str) -> str:
    """Deterministic index key for a term (server-visible but irreversible to preimage is not guaranteed)."""
    return hashlib.sha256(term.encode('utf-8')).hexdigest()

# -----------------------
# Step 2: Build plaintext inverted index (server would normally build this)
# -----------------------
plaintext_index = defaultdict(list)
for doc_id, doc in enumerate(documents):
    words = [w.strip('.,!?').lower() for w in doc.split()]
    for w in words:
        plaintext_index[w].append(doc_id)

# -----------------------
# Step 3: Server: transform to hashed-key index and encrypt posting entries using client's public key
# (server stores: hashed_term -> [E(doc_id), E(doc_id), ...])
# -----------------------
encrypted_index = {}
for term, posting in plaintext_index.items():
    h = term_hash(term)                # deterministic key used to look up
    # encrypt each document id with client's public key (server can't decrypt)
    encrypted_posting = [public_key.encrypt(int(doc_id)) for doc_id in posting]
    encrypted_index[h] = encrypted_posting

# For demonstration: server can also compute encrypted counts homomorphically:
# store encrypted sum-of-ones for the posting list (useful to compute frequency without decrypting list)
encrypted_count_index = {}
for h, enc_posting in encrypted_index.items():
    # sum encrypted 1's for each item => E(count)
    # public_key.encrypt(1) returns an encryption of 1; multiplying encryptions adds plaintexts
    enc_count = None
    for _ in enc_posting:
        if enc_count is None:
            enc_count = public_key.encrypt(1)
        else:
            enc_count = enc_count + public_key.encrypt(1)  # addition in phe is homomorphic addition
    encrypted_count_index[h] = enc_count  # E(count) stored

# -----------------------
# Step 4: Client: search workflow
#  - Client hashes query term -> sends hash (trapdoor) to server
#  - Server returns encrypted posting list for that hash
#  - Client decrypts posting list to obtain doc IDs and display docs
# -----------------------
def server_search_return_encrypted_posting(hash_term):
    """Server-side function: given hashed term, return stored encrypted posting (if any)"""
    return encrypted_index.get(hash_term, [])

def server_return_encrypted_count(hash_term):
    """Server-side: return encrypted count E(count)"""
    return encrypted_count_index.get(hash_term, public_key.encrypt(0))

def client_search_and_display(query_term: str):
    # Client computes trapdoor
    h = term_hash(query_term.lower())
    # Client sends h to server; server returns encrypted posting
    enc_posting = server_search_return_encrypted_posting(h)

    if not enc_posting:
        print(f"No documents found for '{query_term}'")
        return

    # Client decrypts each posting entry
    decrypted_doc_ids = [private_key.decrypt(e) for e in enc_posting]
    print(f"Documents matching '{query_term}':")
    for doc_id in decrypted_doc_ids:
        print(f"- Doc {doc_id}: {documents[doc_id]}")

    # Demonstrate decrypting encrypted count returned by server (client receives E(count))
    enc_count = server_return_encrypted_count(h)
    count = private_key.decrypt(enc_count)
    print(f"(Decrypted count from homomorphic E(count)): {count}")

# -----------------------
# Example queries
# -----------------------
if __name__ == "__main__":
    client_search_and_display("fox")
    print()
    client_search_and_display("dog")
    print()
    client_search_and_display("loyal")
