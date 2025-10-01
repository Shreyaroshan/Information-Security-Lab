from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long
import socket
import pickle

# Generate RSA keys
key = RSA.generate(2048)
n, e, d = key.n, key.e, key.d
public_key = key.publickey()

message = b'This is a secure message.'
m = bytes_to_long(message)
signature = pow(m, d, n)

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 12345))
server_socket.listen(1)
print("Server listening on port 12345...")

conn, addr = server_socket.accept()
print(f"Connected by {addr}")
data = {'n': n, 'e': e, 'm': m, 'signature': signature}
conn.sendall(pickle.dumps(data))

conn.close()
server_socket.close()