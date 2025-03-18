import socket
import json
import os
import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def load_private_key(username):
    """
    Load the private key from a file.
    
    :param username: The username associated with the private key.
    :return: The loaded private key object or None if not found.
    """
    private_key_path = f"{username}_private_key.pem"
    if not os.path.exists(private_key_path):
        print(f"Error: {private_key_path} not found!")
        return None
    
    with open(private_key_path, 'rb') as file:
        return serialization.load_pem_private_key(file.read(), password=None, backend=default_backend())

def generate_RSA_key(username):
    """
    Generate and save public/private key pair for a given username.
    
    :param username: The username associated with the keys.
    :return: A tuple containing (private_key, public_key)
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    
    # Save private key
    with open(f"{username}_private_key.pem", "wb") as private_key_file:
        private_key_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Save public key
    with open(f"{username}_public_key.pem", "wb") as public_key_file:
        public_key_file.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    
    return private_key, public_key

def encrypt_message(public_key_pem, message):
    """
    Encrypt a message using the recipient's public key.
    
    :param public_key_pem: The recipient's public key in PEM format.
    :param message: The message to encrypt.
    :return: The encrypted message as a hexadecimal string.
    """
    public_key = serialization.load_pem_public_key(public_key_pem.encode(), backend=default_backend())
    encrypted_message = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_message.hex()

def signed_message(private_key, message):
    """
    Sign a message using the sender's private key.
    
    :param private_key: The sender's private key.
    :param message: The message to sign.
    :return: The message signature as a hexadecimal string.
    """
    signature = private_key.sign(
        message.encode(),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature.hex()

def register_client(client_socket, username):
    """
    Register a new client by generating keys and sending the public key to the server.
    
    :param client_socket: The active socket connection to the server.
    :param username: The username to register.
    :return: Tuple (private_key, public_key) on success, None otherwise.
    """
    private_key, public_key = generate_RSA_key(username)
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    email = input("Enter your email: ")
    # TODO: make input invisible from screen
    password = input("Enter your password: ")
    
    client_socket.send("register".encode())
    registration_data = {'username': username, 'public_key': public_key_pem, "email": email, "password": password}
    client_socket.send(json.dumps(registration_data).encode())
    
    OTP_data = input("Enter OTP: ")
    client_socket.send(OTP_data.encode())
    response = client_socket.recv(1024).decode()
    print(f"Server response: {response}")
    if response != "Registration successful!":
        print("Registration failed!")
        return None
    
    return private_key, public_key

def request_public_key(client_socket, to_client):
    """
    Request the public key of another user from the server.
    
    :param client_socket: The active socket connection to the server.
    :param to_client: The recipient's username.
    :return: The recipient's public key in PEM format.
    """
    client_socket.send(to_client.encode())
    return client_socket.recv(1024).decode()

def login_client(client_socket, username, private_key):
    """
    Authenticate a client with the server using a challenge-response mechanism.
    
    :param client_socket: The active socket connection to the server.
    :param username: The username to log in.
    :param private_key: The user's private key for signing the challenge.
    :return: True if login is successful, False otherwise.
    """
    client_socket.send("login".encode())
    time.sleep(1)
    client_socket.send(username.encode())
    
    challenge = client_socket.recv(1024).decode()
    signed_challenge = signed_message(private_key, challenge)
    client_socket.send(signed_challenge.encode())
    
    # TODO: make input invisible from screen
    # TODO: display minimum requirement for password like minimum character, special character, number etc
    #       if password is not secure enough ask user to change password
    password = input("Enter your password: ")
    client_socket.send(password.encode())
    response = client_socket.recv(1024).decode()
    print(f"Server response: {response}")
    return response == "Login successful!"

def send_message(client_socket, private_key, username):
    client_socket.send("send_message".encode())
    to_client = input("Enter recipient's username: ")
    message = input("Enter your message: ")
    recipient_public_key = request_public_key(client_socket, to_client)
    encrypted_message = encrypt_message(recipient_public_key, message)
    signature = signed_message(private_key, encrypted_message)
    client_socket.sendall(json.dumps({'from_client': username, 'to_client': to_client, 'encrypted_message': encrypted_message, 'signature': signature}).encode())

def main():
    """
    Main function to start the client, handle registration/login, and send messages.
    """
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 5555))
    
    print("Welcome! Please choose an option:")
    print("1. Register")
    print("2. Login")
    choice = input("Choose option (1 or 2): ")
    username = input("Enter your username: ")
    
    private_key = None
    if choice == '1':
        private_key, _ = register_client(client_socket, username)
    elif choice == '2':
        private_key = load_private_key(username)
        if not private_key or not login_client(client_socket, username, private_key):
            client_socket.close()
            return
    else:
        print("Invalid option!")
        client_socket.close()
        return
    
    while True:

        # TODO: make user can receiving messages from other user
        # if you use thread the other code MAY BE disrupted
        # the receive data should include
        # - sender's username
        # - encrypted message
        # - signature
        # you have to request the public key of the server from request_public_key() to validate the signature
        # then decrypt the message using your private key
        # then print the message to the user

        print("\nOptions: [1] Send Message [2] Exit")
        choice = input("Choose an option: ")
        if choice == '2':
            client_socket.send('exit'.encode())
            break
        elif choice == '1':
            send_message(client_socket, private_key, username)
    client_socket.close()

if __name__ == "__main__":
    main()