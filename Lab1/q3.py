import string


def generate_playfair_matrix(key):
    # Remove duplicates while preserving order
    key = key.upper().replace("J", "I")
    seen = set()
    filtered_key = []
    for c in key:
        if c not in seen and c.isalpha():
            seen.add(c)
            filtered_key.append(c)

    # Fill with the rest of the alphabet (without J)
    for c in string.ascii_uppercase:
        if c == "J":  # I/J are treated same
            continue
        if c not in seen:
            filtered_key.append(c)
            seen.add(c)

    # Create 5x5 matrix
    matrix = [filtered_key[i:i + 5] for i in range(0, 25, 5)]
    return matrix


def find_position(matrix, letter):
    if letter == "J":
        letter = "I"
    for row in range(5):
        for col in range(5):
            if matrix[row][col] == letter:
                return row, col
    return None


def prepare_text(plaintext):
    # Remove non-letters and make uppercase
    text = ''.join([c.upper() for c in plaintext if c.isalpha()])
    text = text.replace("J", "I")

    # Break into digraphs
    digraphs = []
    i = 0
    while i < len(text):
        a = text[i]
        b = ""
        if i + 1 < len(text):
            b = text[i + 1]
        if a == b:
            digraphs.append(a + "X")
            i += 1
        else:
            if b:
                digraphs.append(a + b)
                i += 2
            else:
                digraphs.append(a + "X")
                i += 1
    return digraphs


def playfair_encrypt(plaintext, key):
    matrix = generate_playfair_matrix(key)
    digraphs = prepare_text(plaintext)
    ciphertext = ""

    for pair in digraphs:
        a, b = pair[0], pair[1]
        row1, col1 = find_position(matrix, a)
        row2, col2 = find_position(matrix, b)

        if row1 == row2:  # Same row → shift right
            ciphertext += matrix[row1][(col1 + 1) % 5]
            ciphertext += matrix[row2][(col2 + 1) % 5]
        elif col1 == col2:  # Same column → shift down
            ciphertext += matrix[(row1 + 1) % 5][col1]
            ciphertext += matrix[(row2 + 1) % 5][col2]
        else:  # Rectangle swap
            ciphertext += matrix[row1][col2]
            ciphertext += matrix[row2][col1]

    return ciphertext, matrix


def playfair_decrypt(ciphertext, key):
    matrix = generate_playfair_matrix(key)
    plaintext = ""

    # Split into digraphs
    digraphs = [ciphertext[i:i + 2] for i in range(0, len(ciphertext), 2)]

    for pair in digraphs:
        a, b = pair[0], pair[1]
        row1, col1 = find_position(matrix, a)
        row2, col2 = find_position(matrix, b)

        if row1 == row2:  # Same row → shift left
            plaintext += matrix[row1][(col1 - 1) % 5]
            plaintext += matrix[row2][(col2 - 1) % 5]
        elif col1 == col2:  # Same column → shift up
            plaintext += matrix[(row1 - 1) % 5][col1]
            plaintext += matrix[(row2 - 1) % 5][col2]
        else:  # Rectangle swap
            plaintext += matrix[row1][col2]
            plaintext += matrix[row2][col1]

    return plaintext


# Example usage
plaintext = "The key is hidden under the door pad"
key = "GUIDANCE"

cipher, matrix = playfair_encrypt(plaintext, key)
decrypted = playfair_decrypt(cipher, key)

print("Playfair Matrix:")
for row in matrix:
    print(row)

print("\nPlaintext:", plaintext)
print("Ciphertext:", cipher)
print("Decrypted:", decrypted)
