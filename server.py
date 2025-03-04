import socket
import rsa
import threading

# Generar claves RSA del servidor
server_public_key, server_private_key = rsa.newkeys(2048)

# Configurar el servidor
HOST = '127.0.0.1'
PORT = 12345

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen(5)

print("🔹 Servidor escuchando en", HOST, PORT)

# Diccionario para almacenar los clientes {username: (conn, public_key)}
clients = {}

def handle_client(conn, addr):
    try:
        # Enviar la clave pública del servidor
        conn.send(server_public_key.save_pkcs1("PEM"))

        # Recibir la clave pública del cliente
        client_public_key_data = conn.recv(4096)
        client_public_key = rsa.PublicKey.load_pkcs1(client_public_key_data)

        # Recibir el nombre de usuario del cliente
        username = conn.recv(4096).decode()
        clients[username] = (conn, client_public_key)

        print(f"{username} ({addr}) se ha conectado.")

        while True:
            # Recibir mensaje cifrado
            encrypted_data = conn.recv(4096)
            if not encrypted_data:
                break

            # Recibir firma digital
            signature = conn.recv(4096)

            # Descifrar mensaje con la clave privada del servidor
            decrypted_message = rsa.decrypt(encrypted_data, server_private_key).decode()

            # Extraer destinatario y mensaje
            if ":" in decrypted_message:
                recipient, message = decrypted_message.split(":", 1)

                if recipient in clients:
                    recipient_conn, recipient_public_key = clients[recipient]

                    # Verificar la firma digital
                    try:
                        rsa.verify(message.encode(), signature, client_public_key)
                        print(f"Firma válida. {username} envió: {message}")

                        # Cifrar mensaje con la clave pública del destinatario
                        encrypted_response = rsa.encrypt(f"{username}: {message}".encode(), recipient_public_key)

                        # Enviar mensaje cifrado al destinatario
                        recipient_conn.send(encrypted_response)
                    except rsa.VerificationError:
                        print(f"Firma digital inválida de {username}. Mensaje no enviado.")
                else:
                    print(f"Usuario {recipient} no encontrado.")
    except:
        pass
    finally:
        # Cerrar conexión y eliminar usuario de la lista
        if username in clients:
            del clients[username]
            print(f"{username} se ha desconectado.")
        conn.close()

while True:
    conn, addr = server_socket.accept()
    client_thread = threading.Thread(target=handle_client, args=(conn, addr))
    client_thread.start()
