from phe import paillier  # Use the PyPaillier library for Paillier encryption
from collections import defaultdict

# Step 1: Create a dataset with 10 documents (each document is a string)
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

# Step 2: Generate public and private keys for Paillier encryption
public_key, private_key = paillier.generate_paillier_keypair()

# Step 3: Create an inverted index for the documents
inverted_index = defaultdict(list)

# Populate the inverted index by mapping words to document IDs
for doc_id, document in enumerate(documents):
    words = document.lower().split()
    for word in words:
        inverted_index[word].append(doc_id)

# Step 4: Encrypt the document IDs in the inverted index using Paillier encryption
encrypted_index = {}
for word, doc_ids in inverted_index.items():
    encrypted_doc_ids = [public_key.encrypt(doc_id) for doc_id in doc_ids]
    encrypted_index[word] = encrypted_doc_ids  # Keep word as plaintext for simplicity

# Step 5: Implement the search function using encrypted document IDs
def search(query, encrypted_index):
    """Search for a plaintext query in the encrypted index."""
    if query in encrypted_index:
        # Decrypt the document IDs from the encrypted index
        encrypted_doc_ids = encrypted_index[query]
        return [private_key.decrypt(doc_id) for doc_id in encrypted_doc_ids]
    else:
        return []  # Return empty list if no match is found

# Step 6: Display the documents that match a search query
def display_documents(doc_ids, documents):
    """Display the documents based on their IDs."""
    if not doc_ids:
        print("No matching documents found.")
    else:
        for doc_id in doc_ids:
            print(f"Document {doc_id}: {documents[doc_id]}")

# Example Usage
print("----- Encrypted Search Example -----")
search_query = "fox"  # Search for the word "fox"
print(f"Search Query: '{search_query}'")

# Search for the query in the encrypted index
matching_doc_ids = search(search_query, encrypted_index)

# Display the matching documents
print(f"\nDocuments matching the query '{search_query}':")
display_documents(matching_doc_ids, documents)