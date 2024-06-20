import json
import socket
import threading
import requests

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# Server configuration
HOST = '0.0.0.0'
PORT = 3002

class Encryption:
    """Class to handle encryption and decryption using RSA and AES."""

    @staticmethod
    def generate_rsa_key_pair():
        """
        Generate a new RSA key pair.

        Returns:
            RSA key pair (public and private).
        """
        return RSA.generate(2048)

    @staticmethod
    def decrypt_aes_key(encrypted_aes_key, private_key):
        """
        Decrypt AES key using RSA private key.

        Args:
            encrypted_aes_key (bytes): The AES key encrypted with the RSA public key.
            private_key (RSA key): The RSA private key.

        Returns:
            bytes: The decrypted AES key.
        """
        cipher_rsa = PKCS1_OAEP.new(private_key)
        return cipher_rsa.decrypt(encrypted_aes_key)

    @staticmethod
    def aes_decrypt(ciphertext, key, iv):
        """
        Decrypt ciphertext using AES.

        Args:
            ciphertext (bytes): The encrypted message.
            key (bytes): The AES key.
            iv (bytes): The initialization vector.

        Returns:
            str: The decrypted message.
        """
        cipher_aes = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher_aes.decrypt(ciphertext), AES.block_size).decode('utf-8')

    @staticmethod
    def aes_encrypt(message, key, iv):
        """
        Encrypt a message using AES.

        Args:
            message (bytes): The plaintext message.
            key (bytes): The AES key.
            iv (bytes): The initialization vector.

        Returns:
            bytes: The encrypted message.
        """
        cipher_aes = AES.new(key, AES.MODE_CBC, iv)
        return cipher_aes.encrypt(pad(message, AES.block_size))


class TradingBotServer:
    """
    A server to handle encrypted communications for a trading bot.
    
    Attributes:
        host (str): Server hostname.
        port (int): Server port number.
        server (socket): The server socket.
        base_url (str): Base URL for sending requests.
    """
    def __init__(self, host, port):
        """
        Initialize the server.

        Args:
            host (str): The hostname to bind the server to.
            port (int): The port to bind the server to.
        """
        self.base_url = "https://mordechaicyber.pythonanywhere.com"
        self.host = host
        self.port = port
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((self.host, self.port))
        self.server.listen(5)
        print(f"Server listening on {self.host}:{self.port}")
    
    def start(self):
        """
        Start the server to listen for incoming connections.
        """
        while True:
            client_socket, addr = self.server.accept()
            threading.Thread(target=self.client_thread, args=(client_socket, addr)).start()

    def client_thread(self, client_socket: socket.socket, address):
        """
        Handle client connections in a separate thread.

        Args:
            client_socket (socket.socket): The client socket.
            address (tuple): The address of the client.
        """
        print(f"New connection: {address}")
        try:
            # RSA Keyswap
            rsa_key = Encryption.generate_rsa_key_pair()
            client_socket.sendall(rsa_key.publickey().export_key())
            encrypted_aes_key = client_socket.recv(1024)
            aes_key = Encryption.decrypt_aes_key(encrypted_aes_key, rsa_key)
            # End of Keyswap

            while True:
                ciphertext = client_socket.recv(4096)
                iv = ciphertext[:AES.block_size]
                message = Encryption.aes_decrypt(ciphertext[AES.block_size:], aes_key, iv)

                if not message:
                    break

                data = json.loads(message)
                response = self.handle_request(data)
                response = json.dumps(response).encode()
                iv = get_random_bytes(AES.block_size)
                ciphertext = iv + Encryption.aes_encrypt(response, aes_key, iv)
                client_socket.sendall(ciphertext)

        except Exception as e:
            print(f"Error handling client {address}: {e}")
        finally:
            client_socket.close()
            print(f"Closed {address}")

    def send_request(self, endpoint, data):
        """
        Send a POST request to the specified endpoint with the given data.

        Args:
            endpoint (str): The endpoint to send the request to.
            data (dict): The data to send in the request.

        Returns:
            dict: The response from the server.
        """
        url = f"{self.base_url}/{endpoint}"
        response = requests.post(url, json=data)
        return response.json()

    def handle_request(self, data: dict):
        """
        Handle a request received from the client.

        Args:
            data (dict): The data received from the client.

        Returns:
            dict: The response to send back to the client.
        """
        try:
            endpoint = data.pop('command')
            return self.send_request(endpoint=endpoint, data=data)
        except Exception as e:
            return {'error': True, 'error_msg': str(e)}

if __name__ == "__main__":
    server = TradingBotServer(HOST, PORT)
    server.start()
