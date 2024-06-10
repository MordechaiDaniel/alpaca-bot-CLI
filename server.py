
import json
import os
import socket
import threading
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.padding import PKCS7
import base64
import requests

# Server configuration
HOST = '0.0.0.0'
PORT = 3002

class TradingBotServer:
    def __init__(self, host, port):
        self.base_url = "https://mordechaicyber.pythonanywhere.com"
        self.host = host
        self.port = port
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((self.host, self.port))
        self.server.listen(5)
        print(f"Server listening on {self.host}:{self.port}")
        self.private_key = None
        self.public_key = None
        self.shared_key = None
        self.parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
        self._generate_dh_keypair()

    def _generate_dh_keypair(self):
        self.private_key = self.parameters.generate_private_key()
        self.public_key = self.private_key.public_key()

    def _compute_shared_key(self, peer_public_key_bytes):
        peer_public_key = serialization.load_pem_public_key(peer_public_key_bytes, backend=default_backend())
        shared_key = self.private_key.exchange(peer_public_key)
        self.shared_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
            backend=default_backend()
        ).derive(shared_key)

    def start(self):
        while True:
            client_socket, addr = self.server.accept()
            threading.Thread(target=self.client_thread, args=(client_socket, addr)).start()

    def client_thread(self, client_socket, address):
        print(f"New connection: {address}")
        try:
            # Send parameters and public key to the client
            params_pem = self.parameters.parameter_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.ParameterFormat.PKCS3
            )
            client_socket.sendall(params_pem)
            client_socket.sendall(self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

            # Receive client's public key
            client_public_key = client_socket.recv(4096)
            self._compute_shared_key(client_public_key)

            while True:
                encrypted_message = client_socket.recv(4096)
                if not encrypted_message:
                    break

                request = self.decrypt_message(encrypted_message)
                data = json.loads(request.decode())
                response = self.handle_request(data)
                client_socket.sendall(self.encrypt_message(json.dumps(response).encode()))
        except Exception as e:
            print(f"Error handling client {address}: {e}")
        finally:
            client_socket.close()

    def send_request(self, endpoint, data):
        url = f"{self.base_url}/{endpoint}"
        response = requests.post(url, json=data)
        return response.json()

    def handle_request(self, data: dict):
        try:
            endpoint = data.pop('command')
            return self.send_request(endpoint=endpoint, data=data)
        except Exception as e:
            return {'error': True,'error_msg': str(e)}

    def encrypt_message(self, message):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.shared_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(message) + padder.finalize()
        ct = encryptor.update(padded_data) + encryptor.finalize()
        return base64.b64encode(iv + ct)

    def decrypt_message(self, encrypted_message):
        encrypted_message = base64.b64decode(encrypted_message)
        iv = encrypted_message[:16]
        ct = encrypted_message[16:]
        cipher = Cipher(algorithms.AES(self.shared_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        unpadder = PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_padded = decryptor.update(ct) + decryptor.finalize()
        return unpadder.update(decrypted_padded) + unpadder.finalize()

if __name__ == "__main__":
    server = TradingBotServer(HOST, PORT)
    server.start()
