import socket
import json
from getpass import getpass
import pyperclip

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

class Encryption:
    """Class to handle encryption and decryption using AES and RSA."""

    @staticmethod
    def generate_aes_key():
        """
        Generate a random AES key.

        Returns:
            bytes: A 24-byte AES key.
        """
        return get_random_bytes(24)

    @staticmethod
    def encrypt_aes_key(aes_key, public_key):
        """
        Encrypt the AES key using an RSA public key.

        Args:
            aes_key (bytes): The AES key to be encrypted.
            public_key (RSA key): The RSA public key.

        Returns:
            bytes: The encrypted AES key.
        """
        cipher_rsa = PKCS1_OAEP.new(public_key)
        return cipher_rsa.encrypt(aes_key)

    @staticmethod
    def aes_decrypt(ciphertext, key, iv):
        """
        Decrypt a ciphertext using AES.

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


class TradingBotClient:
    """
    Client for communicating with the TradingBot server.
    
    Attributes:
        host (str): Server hostname.
        port (int): Server port number.
        client (socket): The client socket.
        public_key (RSA key): The server's RSA public key.
        aes_key (bytes): The AES key used for encryption.
        encrypted_aes_key (bytes): The encrypted AES key.
        username (str): Username for authentication.
        password (str): Password for authentication.
        data (dict): Data received from the server.
    """
    def __init__(self, host, port):
        """
        Initialize the client and set up the encryption.

        Args:
            host (str): The server hostname.
            port (int): The server port number.
        """
        self.host = host
        self.port = port
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client.connect((self.host, self.port))
        self.username = None
        self.password = None
        self.data = None

        # Receive public key from server
        self.public_key = RSA.import_key(self.client.recv(1024))

        # Generate AES key
        self.aes_key = Encryption.generate_aes_key()

        # Encrypt AES key using RSA public key
        self.encrypted_aes_key = Encryption.encrypt_aes_key(self.aes_key, self.public_key)

        # Send encrypted AES key to server
        self.client.sendall(self.encrypted_aes_key)

    def send_request(self, data):
        """
        Send a request to the server.

        Args:
            data (dict): The data to send to the server.

        Returns:
            dict: The server's response.
        """
        encoded_data = json.dumps(data).encode()
        iv = get_random_bytes(AES.block_size)
        ciphertext = iv + Encryption.aes_encrypt(encoded_data, self.aes_key, iv)
        self.client.sendall(ciphertext)
        return self.receive_response()

    def receive_response(self):
        """
        Receive a response from the server.

        Returns:
            dict: The decrypted response from the server.
        """
        buffer_size = 4096
        response = b""
        while True:
            part = self.client.recv(buffer_size)
            response += part
            if len(part) < buffer_size:
                break

        iv = response[:AES.block_size]
        decrypted_reply = Encryption.aes_decrypt(response[AES.block_size:], self.aes_key, iv)
        return json.loads(decrypted_reply)

    def add_user(self):
        """
        Send a request to add a new user to the server.
        """
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
        """
        Authenticate the user with the server.

        Returns:
            bool: True if authentication was successful, False otherwise.
        """
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
        """
        Update Alpaca credentials for the authenticated user.
        """
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
        """
        Update configurations for the authenticated user.
        """
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
        """
        Delete the authenticated user's account.

        Returns:
            bool: True if the account was deleted, False otherwise.
        """
        username = self.username
        password = self.password

        delete_confirmation = input("Please enter DELETE to confirm deleting your account.\nThere is no reversing this account.\n: ")

        if delete_confirmation == "DELETE":
            request_data = {
                "command": "delete_user",
                "username": username,
                "password": password,
            }
            response: dict = self.send_request(request_data)
            print(response)

            if "error" in response.keys():
                return False
            else:
                return True
        else:
            print("Operation cancelled.")
            return False

    def close(self):
        """
        Close the client socket.
        """
        self.client.close()

    def logout(self):
        """
        Log out the authenticated user.
        """
        self.username = None
        self.password = None
        self.data = None

    def settings_options(self):
        """
        Display and handle settings options for the authenticated user.
        """
        while True:
            print("1. Update Alpaca Credentials")
            print("2. Update Configs")
            print("3. Delete User")
            print("0. Go back")

            choice = input("Enter choice: ")

            if choice == '0':
                break
            elif choice == '1':
                self.update_alpaca_credentials()
            elif choice == '2':
                self.update_configs()
            elif choice == '3':
                deleted = self.delete_user()
                if deleted:
                    break
            else:
                print("Invalid choice. Please try again.")

    def display_options(self):
        """
        Display and handle data display options for the authenticated user.
        """
        while True:
            print("1. Copy account data")
            #not enough time to mae graphs using MatPlotLib
            # print("2. Get basic analysis")
            # print("3. Graph view")
            print("4. Copy raw data")
            print("0. Go back")

            choice = input("Enter choice: ")

            if choice == '0':
                break
            elif choice == '1':
                pyperclip.copy(str(self.data['account_data']))
            elif choice == '4':
                pyperclip.copy(str(self.data))
            else:
                print("Invalid choice. Please try again.")
                
    def sign_in_options(self):
        """
        Display and handle sign-in options for the authenticated user.
        """
        while True:
            print("1. Display data")
            print("2. Settings")
            print("0. Logout")

            choice = input("Enter choice: ")

            if choice == '0':
                self.logout()
                break
            elif choice == '1':
                self.display_options()
            elif choice == '2':
                self.settings_options()
            else:
                print("Invalid choice. Please try again.")

    def start(self):
        """
        Start the client and handle user interactions.
        """
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
