from Crypto.Util.number import getPrime, inverse
import base64
import hashlib


class RabinKeyManagement:
    def __init__(self, key_size=1024):
        if key_size < 16 or key_size % 2 != 0:
            raise ValueError("key_size should be an even integer >= 16")
        self.key_size = key_size
        self.keys = {}

    def _get_prime_3mod4(self, bits):
        """Return a prime p with p % 4 == 3"""
        while True:
            p = getPrime(bits)
            if p % 4 == 3:
                return p

    def generate_key_pair(self):
        # Use primes p, q such that p % 4 == q % 4 == 3
        half = self.key_size // 2
        p = self._get_prime_3mod4(half)
        q = self._get_prime_3mod4(half)
        while p == q:
            q = self._get_prime_3mod4(half)
        n = p * q
        public_key = (n,)
        private_key = (p, q)
        return public_key, private_key

    def encrypt(self, public_key, plaintext):
        n = public_key[0]
        pt_bytes = plaintext.encode('utf-8')
        m = int.from_bytes(pt_bytes, byteorder='big')
        if m >= n:
            raise ValueError("Plaintext too large for key size. Use larger key or shorter plaintext.")
        ciphertext_int = pow(m, 2, n)

        # encode ciphertext and hash
        c_bytes = ciphertext_int.to_bytes((ciphertext_int.bit_length() + 7) // 8 or 1, byteorder='big')
        ct_b64 = base64.b64encode(c_bytes).decode('utf-8')
        pt_hash_b64 = base64.b64encode(hashlib.sha256(pt_bytes).digest()).decode('utf-8')
        return ct_b64, pt_hash_b64

    def _crt_combine(self, a1, a2, n1, n2):
        """
        Combine x ≡ a1 (mod n1) and x ≡ a2 (mod n2)
        using CRT. Returns x modulo n1*n2.
        """
        m1 = inverse(n1, n2)
        # ensure the inner multiplication reduces mod n2 before multiplying by n1
        t = ((a2 - a1) * m1) % n2
        x = a1 + n1 * t
        return x % (n1 * n2)

    def decrypt(self, private_key, ciphertext_b64, pt_hash_b64):
        p, q = private_key
        n = p * q

        c_bytes = base64.b64decode(ciphertext_b64)
        c = int.from_bytes(c_bytes, byteorder='big')

        # compute square roots modulo p and q (works because p,q % 4 == 3)
        root_p1 = pow(c, (p + 1) // 4, p)
        root_p2 = (-root_p1) % p
        root_q1 = pow(c, (q + 1) // 4, q)
        root_q2 = (-root_q1) % q

        # combine to get the four square roots modulo n
        roots = [
            self._crt_combine(root_p1, root_q1, p, q),
            self._crt_combine(root_p1, root_q2, p, q),
            self._crt_combine(root_p2, root_q1, p, q),
            self._crt_combine(root_p2, root_q2, p, q),
        ]

        expected_hash = base64.b64decode(pt_hash_b64)

        for r in roots:
            # convert integer to bytes (use at least 1 byte if r == 0)
            blen = (r.bit_length() + 7) // 8 or 1
            candidate_bytes = r.to_bytes(blen, byteorder='big')

            # some plaintexts may have leading zeros suppressed; try adjusting by padding to typical lengths
            # but first check raw candidate
            if hashlib.sha256(candidate_bytes).digest() == expected_hash:
                try:
                    return candidate_bytes.decode('utf-8')
                except UnicodeDecodeError:
                    # Not valid UTF-8, continue searching
                    continue

            # try adding leading zero bytes up to a reasonable limit (in case original plaintext had leading zero bytes)
            # length limit: key size bytes
            max_pad = (n.bit_length() + 7) // 8
            for pad in range(1, 5):  # small number of padding attempts (adjustable)
                pad_bytes = b'\x00' * pad + candidate_bytes
                if hashlib.sha256(pad_bytes).digest() == expected_hash:
                    try:
                        return pad_bytes.decode('utf-8')
                    except UnicodeDecodeError:
                        break

        # if nothing matched
        return None

    def store_key_pair(self, facility_id):
        public_key, private_key = self.generate_key_pair()
        self.keys[facility_id] = {'public_key': public_key, 'private_key': private_key}
        print(f"Keys stored for {facility_id}")

    def get_key_pair(self, facility_id):
        key_pair = self.keys.get(facility_id, None)
        if key_pair:
            return key_pair
        else:
            print("Keys not found.")
            return None

    def revoke_key_pair(self, facility_id):
        if facility_id in self.keys:
            del self.keys[facility_id]
            print(f"Keys revoked for {facility_id}")
        else:
            print("No keys to revoke for", facility_id)

    def renew_keys(self):
        for facility_id in list(self.keys.keys()):
            self.revoke_key_pair(facility_id)
            self.store_key_pair(facility_id)
        print("All keys renewed.")


def menu():
    rkm = RabinKeyManagement()
    print("Key Management System")
    print("1. Generate and Store Key Pair")
    print("2. Retrieve Key Pair")
    print("3. Revoke Key Pair")
    print("4. Renew All Keys")
    print("5. Encrypt and Decrypt Message")
    print("6. Exit")
    while True:
        choice = input("\nChoose an option: ")
        if choice == '1':
            facility_id = input("Enter facility ID: ")
            rkm.store_key_pair(facility_id)
        elif choice == '2':
            facility_id = input("Enter facility ID: ")
            key_pair = rkm.get_key_pair(facility_id)
            if key_pair:
                print(f"Public Key: {key_pair['public_key']}")
                print(f"Private Key: {key_pair['private_key']}")
        elif choice == '3':
            facility_id = input("Enter facility ID: ")
            rkm.revoke_key_pair(facility_id)
        elif choice == '4':
            rkm.renew_keys()
        elif choice == '5':
            facility_id = input("Enter facility ID: ")
            key_pair = rkm.get_key_pair(facility_id)
            if key_pair:
                message = input("Enter message to encrypt: ")
                encrypted_message, message_hash = rkm.encrypt(key_pair['public_key'], message)
                print(f"Encrypted message: {encrypted_message}")
                print(f"Message SHA-256 (base64): {message_hash}")
                decrypted_message = rkm.decrypt(key_pair['private_key'], encrypted_message, message_hash)
                print(f"Decrypted message: {decrypted_message}")
        elif choice == '6':
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    menu()
