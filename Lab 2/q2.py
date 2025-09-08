from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Step 1: Define the key and message
key = b'0123456789ABCDEF'  # 16-byte key for AES-128
message = "Sensitive Information"

# Step 2: Create AES cipher in ECB mode
cipher = AES.new(key, AES.MODE_ECB)

# Step 3: Encrypt the message
# AES requires the message to be a multiple of 16 bytes, so we use padding
plaintext_padded = pad(message.encode(), AES.block_size)  # Add padding
ciphertext = cipher.encrypt(plaintext_padded)             # Encrypt
print(f"Ciphertext (in hex): {ciphertext.hex()}")

# Step 4: Decrypt the message
# Create a new AES cipher for decryption using the same key and mode
decipher = AES.new(key, AES.MODE_ECB)
decrypted_padded = decipher.decrypt(ciphertext)           # Decrypt
decrypted_message = unpad(decrypted_padded, AES.block_size).decode()  # Remove padding
print(f"Decrypted Message: {decrypted_message}")