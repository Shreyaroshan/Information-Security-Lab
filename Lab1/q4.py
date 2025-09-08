import numpy as np


# Function to convert a letter to its numerical equivalent (A=0, B=1, ..., Z=25)
def letter_to_number(letter):
    return ord(letter) - ord('A')


# Function to convert a number back to a letter (0=A, 1=B, ..., 25=Z)
def number_to_letter(number):
    return chr(int(number) + ord('A'))


# Function to preprocess the text: Remove spaces, convert to uppercase, and handle odd length
def preprocess_text(text):
    text = text.upper().replace(" ", "")  # Remove spaces and convert to uppercase
    if len(text) % 2 != 0:  # If length is odd, add an 'X'
        text += 'X'
    return text


# Function to perform matrix multiplication and compute modulo 26
def matrix_multiply_mod(matrix, vector):
    result = np.dot(matrix, vector) % 26
    return result


# Function to find modular inverse of a matrix under modulo 26
def modular_inverse(matrix, modulus=26):
    determinant = int(np.round(np.linalg.det(matrix)))  # Compute determinant
    determinant_inv = pow(determinant, -1, modulus)  # Modular multiplicative inverse of determinant
    matrix_adj = np.round(determinant * np.linalg.inv(matrix)).astype(int) % modulus  # Adjugate matrix
    return (determinant_inv * matrix_adj) % modulus  # Multiply by determinant inverse and take mod


# Encryption function using Hill Cipher
def hill_cipher_encrypt(plaintext, key_matrix):
    plaintext = preprocess_text(plaintext)  # Preprocess the plaintext
    encrypted_text = ""

    # Encrypt each pair of characters
    for i in range(0, len(plaintext), 2):
        pair = plaintext[i:i + 2]
        vector = np.array([[letter_to_number(pair[0])], [letter_to_number(pair[1])]])  # Create column vector
        encrypted_vector = matrix_multiply_mod(key_matrix, vector)  # Matrix multiplication
        encrypted_text += number_to_letter(encrypted_vector[0][0]) + number_to_letter(
            encrypted_vector[1][0])  # Convert to letters

    return encrypted_text


# Decryption function using Hill Cipher
def hill_cipher_decrypt(ciphertext, key_matrix):
    decrypted_text = ""

    # Compute the modular inverse of the key matrix
    inverse_matrix = modular_inverse(key_matrix)

    # Decrypt each pair of characters
    for i in range(0, len(ciphertext), 2):
        pair = ciphertext[i:i + 2]
        vector = np.array([[letter_to_number(pair[0])], [letter_to_number(pair[1])]])  # Create column vector
        decrypted_vector = matrix_multiply_mod(inverse_matrix, vector)  # Matrix multiplication with inverse matrix
        decrypted_text += number_to_letter(decrypted_vector[0][0]) + number_to_letter(
            decrypted_vector[1][0])  # Convert to letters

    return decrypted_text


# Example usage
plaintext = "We live in an insecure world"
key_matrix = np.array([[3, 3], [2, 7]])  # Given key matrix (3,3),(2,7)

print(f"Original Plaintext: {plaintext}")

# Encrypt the plaintext using Hill Cipher
encrypted_text = hill_cipher_encrypt(plaintext, key_matrix)
print(f"Encrypted Text: {encrypted_text}")

# Decrypt the ciphertext using Hill Cipher
decrypted_text = hill_cipher_decrypt(encrypted_text, key_matrix)
print(f"Decrypted Text: {decrypted_text}")
