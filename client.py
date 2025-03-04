import socket
import rsa
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox

HOST = '127.0.0.1'
PORT = 12345

# Generar claves RSA del cliente
client_public_key, client_private_key = rsa.newkeys(2048)

# Crear socket y conectar al servidor
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((HOST, PORT))

# Recibir la clave pública del servidor
server_public_key_data = client_socket.recv(4096)
server_public_key = rsa.PublicKey.load_pkcs1(server_public_key_data)

# Enviar la clave pública del cliente
client_socket.send(client_public_key.save_pkcs1("PEM"))

# Pedir nombre de usuario
username = None
while not username:
    username = input("Ingresa tu nombre de usuario: ")
client_socket.send(username.encode())

# Interfaz gráfica con Tkinter
class ChatClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title(f"Chat - {username}")
        self.root.geometry("400x500")

        # Cuadro de mensajes
        self.chat_display = scrolledtext.ScrolledText(self.root, state='disabled', width=50, height=20)
        self.chat_display.pack(pady=10)

        # Campo de entrada
        self.message_entry = tk.Entry(self.root, width=50)
        self.message_entry.pack(pady=5)

        # Botón de enviar
        self.send_button = tk.Button(self.root, text="Enviar", command=self.send_message)
        self.send_button.pack(pady=5)

        # Hilo para recibir mensajes
        threading.Thread(target=self.receive_messages, daemon=True).start()

    def send_message(self):
        message = self.message_entry.get()
        if message:
            try:
                # Firmar el mensaje con la clave privada del cliente
                signature = rsa.sign(message.encode(), client_private_key, 'SHA-256')

                # Cifrar el mensaje con la clave pública del servidor
                encrypted_message = rsa.encrypt(message.encode(), server_public_key)

                # Enviar el mensaje cifrado y la firma digital
                client_socket.send(encrypted_message)
                client_socket.send(signature)

                # Mostrar en la interfaz
                self.update_chat(f"Tú: {message}")

                # Limpiar entrada
                self.message_entry.delete(0, tk.END)
            except Exception as e:
                messagebox.showerror("Error", f"No se pudo enviar el mensaje: {e}")

    def receive_messages(self):
        while True:
            try:
                # Recibir mensaje cifrado
                encrypted_response = client_socket.recv(4096)
                if not encrypted_response:
                    break

                # Desencriptar mensaje con la clave privada del cliente
                decrypted_response = rsa.decrypt(encrypted_response, client_private_key).decode()

                # Mostrar mensaje recibido
                self.update_chat(decrypted_response)
            except:
                break

    def update_chat(self, message):
        self.chat_display.config(state='normal')
        self.chat_display.insert(tk.END, message + "\n")
        self.chat_display.config(state='disabled')
        self.chat_display.yview(tk.END)

# Crear y ejecutar la interfaz
root = tk.Tk()
chat_client = ChatClientGUI(root)
root.mainloop()

client_socket.close()
print("Desconectado del servidor.")
