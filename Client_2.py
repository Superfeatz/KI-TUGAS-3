from DES import ecb_encrypt, ecb_decrypt
from rsa import encrypt_rsa
import socket
import random
import threading
import sys

def listen_to_server(client_socket, des_key):
    while True:
        try:
            encrypted_data = client_socket.recv(1024)
            if not encrypted_data:
                print("\nDisconnected from server.")
                sys.exit(0)

            decrypted_message = ecb_decrypt(encrypted_data.decode(), des_key)
            # Print dengan newline untuk memisahkan dari input prompt
            print(f"\n{decrypted_message}")
            print("Enter message: ", end='', flush=True)  # Restore input prompt
        except Exception as e:
            print(f"\nError receiving message: {e}")
            sys.exit(1)

def print_help():
    print("""
Available commands:
/help - Show this help message
/list - Show connected clients
@username message - Send private message to specific client
Regular message - Broadcast to all clients
/exit - Exit the chat
    """)

def main():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect(('localhost', 5000))
    except ConnectionRefusedError:
        print("Could not connect to server. Make sure server is running.")
        return

    server_public_key = eval(client_socket.recv(1024).decode())
    print(f"Connected to server. Public Key: {server_public_key}")

    des_key = ''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=8))
    print(f"Generated DES key: {des_key}")

    encrypted_key = encrypt_rsa(server_public_key, des_key)
    client_socket.send(str(encrypted_key).encode())

    print_help()

    listening_thread = threading.Thread(target=listen_to_server, args=(client_socket, des_key))
    listening_thread.daemon = True
    listening_thread.start()

    while True:
        try:
            message = input("Enter message: ")
            if message.lower() == '/exit':
                break
            elif message.lower() == '/help':
                print_help()
                continue

            encrypted_message = ecb_encrypt(message, des_key)
            client_socket.send(encrypted_message.encode())
        except KeyboardInterrupt:
            print("\nExiting...")
            break
        except Exception as e:
            print(f"Error sending message: {e}")
            break

    client_socket.close()

if __name__ == '__main__':
    main()