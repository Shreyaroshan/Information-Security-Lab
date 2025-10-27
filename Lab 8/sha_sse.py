# sha_sse_fixed.py
import hashlib
from collections import defaultdict

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

def trapdoor(term: str) -> str:
    return hashlib.sha256(term.strip().lower().encode()).hexdigest()

# Build hashed index
hashed_index = {}
from collections import defaultdict
temp = defaultdict(set)
for doc_id, doc in enumerate(documents):
    for w in doc.lower().replace('.', '').replace(',', '').split():
        temp[trapdoor(w)].add(doc_id)

# convert sets to sorted lists
hashed_index = {h: sorted(list(ids)) for h, ids in temp.items()}

# Search
def search(query: str):
    h = trapdoor(query)
    return hashed_index.get(h, [])

if __name__ == "__main__":
    q = "fox"
    ids = search(q)
    print("Query:", q)
    for i in ids:
        print(f"Doc {i}: {documents[i]}")
