import socket
import json
from getpass import getpass
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.padding import PKCS7
import base64
import os

class TradingBotClient:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client.connect((self.host, self.port))
        self.private_key = None
        self.public_key = None
        self.shared_key = None
        self._exchange_keys()
        self.username = None
        self.password = None
        self.data = None

    def _exchange_keys(self):
        # Receive parameters from server
        params_pem = self.client.recv(2048)
        parameters = serialization.load_pem_parameters(params_pem, backend=default_backend())

        # Generate key pair using received parameters
        self.private_key = parameters.generate_private_key()
        self.public_key = self.private_key.public_key()

        # Send public key to server
        self.client.sendall(self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

        # Receive server's public key
        server_public_key = self.client.recv(4096)
        self._compute_shared_key(server_public_key)

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

    def send_request(self, data):
        self.client.sendall(self.encrypt_message(json.dumps(data).encode()))
        return self.receive_response()

    def receive_response(self):
        buffer_size = 4096
        response = b""
        while True:
            part = self.client.recv(buffer_size)
            response += part
            if len(part) < buffer_size:
                break
        return json.loads(self.decrypt_message(response).decode())

    def add_user(self):
        username = input("Username: ")
        password = getpass("Password: ")
        alpaca_key = input("Alpaca Key: ")
        alpaca_secret = input("Alpaca Secret: ")
        config = input("Config (JSON): ")

        request_data = {
            "command": "add_user",
            "username": username,
            "password": password,
            "key": alpaca_key,
            "secret": alpaca_secret,
            "config": config
        }
        response = self.send_request(request_data)
        print(response)

    def authenticate(self):
        username = input("Username: ")
        password = getpass("Password: ")

        request_data = {
            "command": "authenticate",
            "username": username,
            "password": password,
        }
        response = self.send_request(request_data)
        
        if response['error']:
            return False
        else:
            self.username = username
            self.password = password
            self.data = response
            return True

    def update_alpaca_credentials(self):
        username = self.username
        password = self.password
        alpaca_key = input("New Alpaca Key: ")
        alpaca_secret = input("New Alpaca Secret: ")

        request_data = {
            "command": "update_alpaca_credentials",
            "username": username,
            "password": password,
            "key": alpaca_key,
            "secret": alpaca_secret,
        }
        response = self.send_request(request_data)
        print(response)

    def update_configs(self):
        username = self.username
        password = self.password
        configs = input("New Configs (JSON): ")

        request_data = {
            "command": "update_configs",
            "username": username,
            "password": password,
            "configs": json.loads(configs),
        }
        response = self.send_request(request_data)
        print(response)

    def delete_user(self) -> bool:
        username = self.username
        password = self.password

        delete_confirmation = input("Please enter DELETE to confirm deleting your account.\nThere is no reversing this account.\n: ")

        if delete_confirmation == "DELETE":

            request_data = {
                "command": "delete_user",
                "username": username,
                "password": password,
            }
            response:dict = self.send_request(request_data)
            print(response)

            if "error" in response.keys():
                return False
            else:
                return True
        
        else:
            print("Operation cancelled.")
            return False

    def close(self):
        self.client.close()

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
    
    def logout(self):
        self.username = None
        self.password = None
        self.data = None
    
    def sign_in_options(self):

        while True:
            print("1. Get account data")
            print("2. Get basic analysis")
            print("3. Graph view")
            print("3. Update Alpaca Credentials")
            print("4. Update Configs")
            print("5. Delete User")
            print("0. Logout")

            choice = input("Enter choice: ")

            if choice == '0':
                self.logout()
                break
            elif choice == '3':
                self.update_alpaca_credentials()
            elif choice == '4':
                self.update_configs()
            elif choice == '5':
                deleted = self.delete_user()
                if deleted:
                    break
            else:
                print("Invalid choice. Please try again.")

    def start(self):
        while True:
            print("\n1. Login")
            print("2. Sign up")
            print("0. Exit")

            choice = input("Enter choice: ")

            if choice == '0':
                self.close()
                break
            elif choice == '1':
                if self.authenticate():
                    self.sign_in_options()
            elif choice == '2':
                self.add_user()
            else:
                print("Invalid choice. Please try again.")

if __name__ == "__main__":
    client = TradingBotClient('127.0.0.1', 3002)
    client.start()
