
from Crypto.PublicKey import RSA

key = RSA.generate(1024)
n, e, d = key.n, key.e, key.d
print("n (modulus):", n)
print("e (public exponent):", e)
print("d (private exponent):", d)
message = b"Asymmetric Encryption"

c = pow(int.from_bytes(message, "big"), e, n)
print("Encrypted message:", hex(c))

m = pow(c, d, n)
print("Decrypted message:", m.to_bytes((m.bit_length() + 7) // 8, "big").decode())


# from sympy import mod_inverse

# # Input the message and the RSA parameters (p, q, e)
# msg = b"Asymmetric Encryption"
# print("Enter p, q, and e values: ")
# p = int(input("p: "))
# q = int(input("q: "))
# e = int(input("e: "))
# n = p * q
# phi_n = (p - 1) * (q - 1)
# d = mod_inverse(e, phi_n)

# c = pow(int.from_bytes(msg, "big"), e, n)
# print("Encrypted message:", hex(c))

# m = pow(c, d, n)
# print("Decrypted message:", m.to_bytes((m.bit_length() + 7) // 8, "big").decode(errors='ignore'))
