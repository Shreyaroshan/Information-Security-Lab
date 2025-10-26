import random
from math import gcd

# Step 1: Key Generation
def generate_keypair():
    """Generate RSA public and private keys"""
    # Choose two prime numbers p and q (for demonstration, use small primes)
    p = 61
    q = 53

    # Calculate n and Euler's Totient (phi)
    n = p * q
    phi = (p - 1) * (q - 1)

    # Choose an integer e such that 1 < e < phi and gcd(e, phi) = 1
    e = random.randrange(1, phi)
    while gcd(e, phi) != 1:
        e = random.randrange(1, phi)

    # Compute the private key d such that (d * e) % phi = 1
    d = pow(e, -1, phi)

    # Public key: (e, n)
    # Private key: (d, n)
    return (e, n), (d, n)

# Step 2: Encryption
def encrypt(plaintext, public_key):
    """Encrypt the plaintext using the public key"""
    e, n = public_key
    # Compute ciphertext c = (m^e) % n
    ciphertext = pow(plaintext, e, n)
    return ciphertext

# Step 3: Homomorphic Multiplication
def multiply_encrypted(c1, c2, n):
    """Multiply two encrypted values"""
    return (c1 * c2) % n

# Step 4: Decryption
def decrypt(ciphertext, private_key):
    """Decrypt the ciphertext using the private key"""
    d, n = private_key
    # Compute plaintext m = (c^d) % n
    plaintext = pow(ciphertext, d, n)
    return plaintext

# Main function to demonstrate RSA multiplicative homomorphism
if __name__ == "__main__":
    # Generate RSA key pair
    public_key, private_key = generate_keypair()

    # Print public and private keys
    print(f"Public Key (e, n): {public_key}")
    print(f"Private Key (d, n): {private_key}\n")

    # Define two integers to be encrypted
    m1 = 7
    m2 = 3

    print(f"Original Integers: {m1}, {m2}")

    # Encrypt the integers
    c1 = encrypt(m1, public_key)
    c2 = encrypt(m2, public_key)
    print(f"Ciphertext for {m1}: {c1}")
    print(f"Ciphertext for {m2}: {c2}")

    # Perform homomorphic multiplication of the ciphertexts
    encrypted_product = multiply_encrypted(c1, c2, public_key[1])
    print(f"Encrypted product of {m1} and {m2}: {encrypted_product}")

    # Decrypt the result of the multiplication
    decrypted_product = decrypt(encrypted_product, private_key)
    print(f"Decrypted product: {decrypted_product}")

    # Verify that decrypted product matches m1 * m2
    assert decrypted_product == m1 * m2, f"Error: Decrypted product {decrypted_product} does not match {m1 * m2}!"
    print(f"Decryption verified: {m1} * {m2} = {decrypted_product}")