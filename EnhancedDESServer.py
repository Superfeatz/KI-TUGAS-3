import socket
import sys
import os
from DES import *
from rsa import RSA, public_key_authority

class EnhancedDESServer:
    def __init__(self, host='localhost', port=5000):
        self.host = host
        self.port = port
        self.socket = None
        self.client_socket = None
        self.client_address = None
        self.des_key = None
        self.rsa = RSA()
        self.client_id = None

    def start(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Add socket reuse option
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.host, self.port))
            self.socket.listen(1)
            print(f"Server listening on {self.host}:{self.port}")
        except Exception as e:
            print(f"Server startup error: {e}")
            sys.exit(1)

    def accept_connection(self):
        try:
            self.client_socket, self.client_address = self.socket.accept()
            print(f"Connection accepted from {self.client_address}")
        except Exception as e:
            print(f"Connection acceptance error: {e}")
            sys.exit(1)

    def exchange_keys(self):
        # Generate RSA key pair
        public_key, private_key = self.rsa.generate_keypair()
        
        # Register public key with authority
        public_key_authority.register_public_key("server", public_key)
        
        # Wait for client key exchange
        key_exchange_msg = self.client_socket.recv(4096).decode()
        client_id, encrypted_des_key = key_exchange_msg.split(':', 1)
        
        # Decrypt DES key using server's private key
        self.des_key = self.rsa.decrypt(int(encrypted_des_key))
        self.client_id = client_id
        
        print(f"Received DES key from {client_id}")
        return self.des_key

    def set_key(self, key):
        self.des_key = key
        # Initialize DES keys using the global keys list from DES.py
        global keys
        keys = [''] * 16
        generate_keys(key)

    def encrypt_message(self, message):
        # Pad message if needed
        while len(message) % 8 != 0:
            message += ' '
            
        encrypted_result = ''
        for i in range(0, len(message), 8):
            block = message[i:i+8]
            encrypted_result += des_encrypt_block(block)
            
        return bin_to_hex(encrypted_result)

    def decrypt_message(self, ciphertext_hex):
        try:
            ciphertext_bin = hex_to_bin(ciphertext_hex)
            decrypted_result = ''
            
            for i in range(0, len(ciphertext_bin), 64):
                block = ciphertext_bin[i:i+64]
                decrypted_result += des_decrypt(block)
                
            return decrypted_result.strip()
        except Exception as e:
            print(f"Decryption error: {e}")
            return None

    def receive_message(self):
        try:
            # Receive encrypted message with larger buffer
            encrypted_msg = self.client_socket.recv(4096).decode()
            if not encrypted_msg:
                return None
                
            # Decrypt the message
            decrypted = self.decrypt_message(encrypted_msg)
            return decrypted
        except Exception as e:
            print(f"Error receiving message: {e}")
            return None
            
    def send_message(self, message):
        if not self.des_key:
            print("Please set encryption key first!")
            return
            
        try:
            # Encrypt the message
            encrypted = self.encrypt_message(message)
            # Send the encrypted message
            self.client_socket.send(encrypted.encode())
        except Exception as e:
            print(f"Error sending message: {e}")

    def close(self):
        if self.client_socket:
            self.client_socket.close()
        if self.socket:
            self.socket.close()

def main():
    server = EnhancedDESServer()
    server.start()
    
    # Accept client connection
    server.accept_connection()
    
    try:
        # Exchange keys first
        des_key = server.exchange_keys()
        print(f"DES Key exchanged securely: {des_key}")
        server.set_key(des_key)
        
        while True:
            # Receive message
            message = server.receive_message()
            if not message:
                print("Client disconnected")
                break
                
            print(f"Received (decrypted): {message}")
            
            # Send response
            response = input("Enter response: ")
            server.send_message(response)
            print("Response sent (encrypted)")
            
    except KeyboardInterrupt:
        print("\nShutting down server...")
    finally:
        server.close()

if __name__ == "__main__":
    main()