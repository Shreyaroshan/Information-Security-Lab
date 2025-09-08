
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

# Step 1: Define the DES key and message
key = b'A1B2C3D4'          # 8-byte key for DES
message = "Confidential Data"

# Step 2: Create DES cipher in ECB mode
cipher = DES.new(key, DES.MODE_ECB)

# Step 3: Encrypt the message
# DES requires the message to be a multiple of 8 bytes, so we use padding
plaintext_padded = pad(message.encode(), DES.block_size)  # Add padding
ciphertext = cipher.encrypt(plaintext_padded)             # Encrypt
print(f"Ciphertext (in hex): {ciphertext.hex()}")

# Step 4: Decrypt the message
# Create a new DES cipher for decryption using the same key and mode
decipher = DES.new(key, DES.MODE_ECB)
decrypted_padded = decipher.decrypt(ciphertext)           # Decrypt
decrypted_message = unpad(decrypted_padded, DES.block_size).decode()  # Remove padding
print(f"Decrypted Message: {decrypted_message}")
