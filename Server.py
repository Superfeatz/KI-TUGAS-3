from DES import ecb_encrypt, ecb_decrypt
from rsa import generate_keypair, encrypt_rsa, decrypt_rsa
import socket
import threading

clients = {}  # Menyimpan client dan kunci DES mereka

def broadcast_message(message, exclude_client=None):
    """
    Mengirim pesan ke semua client yang terhubung
    """
    for client_id, client_info in clients.items():
        if exclude_client and client_id == exclude_client:
            continue
        try:
            encrypted_msg = ecb_encrypt(message, client_info['key'])
            client_info['conn'].send(encrypted_msg.encode())
        except Exception as e:
            print(f"Error broadcasting to {client_id}: {e}")

def handle_client(conn, address, private_key, public_key):
    client_id = f"{address[0]}:{address[1]}"
    print(f"Connection from: {client_id}")

    try:
        # Kirim public key RSA ke client
        conn.send(str(public_key).encode())

        # Terima encrypted DES key
        encrypted_key = eval(conn.recv(1024).decode())
        des_key = decrypt_rsa(private_key, encrypted_key)
        clients[client_id] = {'conn': conn, 'key': des_key}
        print(f"Received DES key from {client_id}: {des_key}")

        # Broadcast ketika client baru bergabung
        broadcast_message(f"[SERVER] Client {client_id} bergabung ke chat", client_id)

        while True:
            data = conn.recv(1024).decode()
            if not data:
                break

            # Dekripsi pesan dengan kunci DES client pengirim
            decrypt_msg = ecb_decrypt(data, des_key)
            print(f"From {client_id}: {decrypt_msg}")

            # Handle perintah khusus
            if decrypt_msg.startswith("/"):
                handle_commands(decrypt_msg, client_id, des_key, conn)
            # Handle private message
            elif decrypt_msg.startswith("@"):
                handle_private_message(decrypt_msg, client_id, des_key, conn)
            # Handle broadcast message
            else:
                broadcast_message(f"[{client_id}] {decrypt_msg}")

    except Exception as e:
        print(f"Error with {client_id}: {e}")

    finally:
        conn.close()
        del clients[client_id]
        broadcast_message(f"[SERVER] Client {client_id} meninggalkan chat")
        print(f"Connection closed: {client_id}")

def handle_commands(message, client_id, des_key, conn):
    """
    Handle perintah khusus dari client
    """
    command = message[1:].lower()
    if command == "list":
        # Kirim daftar client yang terhubung
        client_list = "Connected clients:\n" + "\n".join(clients.keys())
        encrypted_msg = ecb_encrypt(client_list, des_key)
        conn.send(encrypted_msg.encode())
    elif command == "help":
        help_msg = """
Available commands:
/list - Show connected clients
/help - Show this help message
@username message - Send private message
Regular message - Broadcast to all clients
        """
        encrypted_msg = ecb_encrypt(help_msg, des_key)
        conn.send(encrypted_msg.encode())

def handle_private_message(message, sender_id, des_key, sender_conn):
    """
    Handle private message antar client
    """
    try:
        target_id, private_msg = message[1:].split(" ", 1)
        if target_id in clients:
            target_conn = clients[target_id]['conn']
            target_key = clients[target_id]['key']
            # Kirim ke target
            encrypted_msg = ecb_encrypt(f"[PM from {sender_id}] {private_msg}", target_key)
            target_conn.send(encrypted_msg.encode())
            # Konfirmasi ke pengirim
            confirm_msg = f"[PM to {target_id}] {private_msg}"
            sender_conn.send(ecb_encrypt(confirm_msg, des_key).encode())
        else:
            error_msg = f"Client {target_id} tidak ditemukan."
            sender_conn.send(ecb_encrypt(error_msg, des_key).encode())
    except ValueError:
        error_msg = "Format pesan tidak valid. Gunakan format '@client_id pesan'"
        sender_conn.send(ecb_encrypt(error_msg, des_key).encode())

if __name__ == '__main__':
    public_key, private_key = generate_keypair()
    print(f"Public Key: {public_key}")
    print(f"Private Key: {private_key}")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 5000))
    server_socket.listen(5)
    print("Server listening on localhost:5000...")

    while True:
        conn, address = server_socket.accept()
        threading.Thread(target=handle_client, args=(conn, address, private_key, public_key)).start()