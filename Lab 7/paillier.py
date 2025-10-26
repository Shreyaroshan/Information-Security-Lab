import random
from math import gcd

# Step 1: Key Generation
def lcm(x, y):
    """Compute the Least Common Multiple of x and y"""
    return x * y // gcd(x, y)

def generate_keypair():
    """Generate public and private keys for Paillier encryption"""
    # Use two small prime numbers for demonstration
    # Replace with large primes for real-world applications
    p = 11
    q = 13

    # Calculate n, n^2, and lambda
    n = p * q
    n_square = n * n
    lambda_value = lcm(p - 1, q - 1)

    # Choose g (typically g = n + 1)
    g = n + 1

    # Calculate mu: mu = (L(g^λ mod n^2))^-1 mod n
    # L function: L(x) = (x - 1) // n
    def L(x):
        return (x - 1) // n

    # Calculate mu as (L(g^λ mod n^2))^-1 mod n
    mu = pow(L(pow(g, lambda_value, n_square)), -1, n)

    # Public key: (n, g)
    # Private key: (lambda, mu)
    return (n, g), (lambda_value, mu)

# Step 2: Encryption
def encrypt(plaintext, public_key):
    """Encrypt the plaintext using the public key"""
    n, g = public_key
    n_square = n * n

    # Select a random r such that gcd(r, n) = 1
    r = random.randint(1, n - 1)
    while gcd(r, n) != 1:
        r = random.randint(1, n - 1)

    # Compute ciphertext c = (g^m * r^n) mod n^2
    ciphertext = (pow(g, plaintext, n_square) * pow(r, n, n_square)) % n_square
    return ciphertext

# Step 3: Homomorphic Addition
def add_encrypted(c1, c2, n_square):
    """Add two encrypted values"""
    return (c1 * c2) % n_square

# Step 4: Decryption
def decrypt(ciphertext, private_key, public_key):
    """Decrypt the ciphertext using the private key"""
    n, g = public_key
    n_square = n * n
    lambda_value, mu = private_key

    # L function: L(x) = (x - 1) // n
    def L(x):
        return (x - 1) // n

    # Compute m = L(c^λ mod n^2) * mu mod n
    x = pow(ciphertext, lambda_value, n_square)
    L_x = L(x)
    plaintext = (L_x * mu) % n
    return plaintext

# Step 5: Implement the main flow
if __name__ == "__main__":
    # Generate key pair
    public_key, private_key = generate_keypair()

    # Print public and private keys
    print(f"Public Key (n, g): {public_key}")
    print(f"Private Key (lambda, mu): {private_key}\n")

    # Define two integers to be encrypted
    m1 = 15
    m2 = 25

    print(f"Original Integers: {m1}, {m2}")

    # Encrypt the integers
    c1 = encrypt(m1, public_key)
    c2 = encrypt(m2, public_key)
    print(f"Ciphertext for {m1}: {c1}")
    print(f"Ciphertext for {m2}: {c2}")

    # Perform homomorphic addition of the ciphertexts
    n_square = public_key[0] * public_key[0]
    encrypted_sum = add_encrypted(c1, c2, n_square)
    print(f"Encrypted sum of {m1} and {m2}: {encrypted_sum}")

    # Decrypt the result of the addition
    decrypted_sum = decrypt(encrypted_sum, private_key, public_key)
    print(f"Decrypted sum: {decrypted_sum}")

    # Verify that decrypted sum matches m1 + m2
    assert decrypted_sum == m1 + m2, f"Error: Decrypted sum {decrypted_sum} does not match {m1 + m2}!"
    print(f"Decryption verified: {m1} + {m2} = {decrypted_sum}")