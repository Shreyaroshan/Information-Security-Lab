
import os
from collections import defaultdict
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode

# Step 1: Create a dataset with at least 10 documents (each document is a simple string)
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

# Step 2: AES Encryption and Decryption Functions
AES_KEY = os.urandom(16)  # 128-bit random key
AES_IV = os.urandom(16)   # 128-bit initialization vector (IV)

def encrypt(text, key=AES_KEY, iv=AES_IV):
    """Encrypt a string using AES"""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_text = cipher.encrypt(pad(text.encode(), AES.block_size))
    return b64encode(iv + encrypted_text).decode('utf-8')  # Return IV + encrypted text encoded in base64

def decrypt(encrypted_text, key=AES_KEY):
    """Decrypt an AES encrypted string"""
    encrypted_data = b64decode(encrypted_text.encode('utf-8'))
    iv = encrypted_data[:16]
    encrypted_text = encrypted_data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(encrypted_text), AES.block_size).decode('utf-8')

# Step 3: Create an Inverted Index
inverted_index = defaultdict(list)

# Populate the inverted index
for doc_id, document in enumerate(documents):
    for word in document.lower().split():
        inverted_index[word].append(doc_id)

# Encrypt each word and the corresponding document IDs in the inverted index
encrypted_index = {}
for word, doc_ids in inverted_index.items():
    encrypted_word = encrypt(word)
    encrypted_doc_ids = [encrypt(str(doc_id)) for doc_id in doc_ids]
    encrypted_index[encrypted_word] = encrypted_doc_ids

# Step 4: Implement Search Function
def search(query, encrypted_index, key=AES_KEY):
    """Encrypt the query and search in the encrypted index"""
    encrypted_query = encrypt(query.lower(), key)  # Encrypt the search query
    if encrypted_query in encrypted_index:
        # Decrypt the document IDs from the encrypted index
        encrypted_doc_ids = encrypted_index[encrypted_query]
        return [int(decrypt(doc_id, key)) for doc_id in encrypted_doc_ids]
    else:
        return []

# Display the documents that match a search query
def display_documents(doc_ids, documents):
    """Display the documents based on their IDs"""
    for doc_id in doc_ids:
        print(f"Document {doc_id}: {documents[doc_id]}")

# Step 5: Run a Search Query
print("----- Encrypted Search Example -----")
search_query = "fox"
print(f"Search Query: {search_query}")
matching_doc_ids = search(search_query, encrypted_index)

if matching_doc_ids:
    print(f"\nDocuments matching the query '{search_query}':")
    display_documents(matching_doc_ids, documents)
else:
    print(f"No documents found for query '{search_query}'")
