import socket
import json
import os
import sys
import time
import getpass
import re
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

def validate_password(password):
    """
    Validate the password based on specific criteria.
    
    :param password: The password to validate.
    :return: True if the password meets the criteria, False otherwise.
    """
    if len(password) < 8:
        print("Password must be at least 8 characters long.")
        return False
    if not any(char.isdigit() for char in password):
        print("Password must contain at least one number.")
        return False
    if not any(char.isupper() for char in password):
        print("Password must contain at least one uppercase letter.")
        return False
    if not any(char.islower() for char in password):
        print("Password must contain at least one lowercase letter.")
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        print("Password must contain at least one special character (!@#$%^&*(),.?\":{}|<>).")
        return False
    return True

def validate_email(email):
    """
    Validate if the input is a valid email address.
    
    :param email: The email to validate.
    :return: True if the email is valid, False otherwise.
    """
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(email_regex, email) is not None

def register_client(client_socket, username):
    """
    Register a new client by generating keys and sending the public key to the server.
    
    :param client_socket: The active socket connection to the server.
    :param username: The username to register.
    :return: Tuple (private_key, public_key) on success, None otherwise.
    """
    client_socket.send("register".encode())
    response = client_socket.recv(1024).decode()
    if response != "registration":
        print(f"Server response: {response}")
        client_socket.close()
        return None, None
    private_key, public_key = generate_RSA_key(username)
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    while not username.strip():
        username = input("Username cannot be empty.\nPlease enter your username: ")

    email = input("Enter your email: ")
    while not validate_email(email):
        email = input("Invalid email format.\nPlease enter a valid email: ")
        
    password = getpass.getpass("Enter your password: ")
    while not validate_password(password):
        password = getpass.getpass("Enter your password: ")

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
    response = client_socket.recv(1024).decode()
    if response != "login":
        print(f"Server response: {response}")
        return False
    client_socket.send(username.encode())
    
    challenge = client_socket.recv(1024).decode()
    signed_challenge = signed_message(private_key, challenge)
    client_socket.send(signed_challenge.encode())
    signed_response = client_socket.recv(1024).decode()
    if(signed_response != "valid signature!"):
        print("Invalid signature!")
        return False
    
    # TODO: display minimum requirement for password like minimum character, special character, number etc
    #       if password is not secure enough ask user to change password
    password = getpass.getpass("Enter your password: ")
    try:
        client_socket.send(password.encode())
        response = client_socket.recv(1024).decode()
        print(f"Server response: {response}")
        return response == "Login successful!"
    except Exception as e:
        return False

def send_message(client_socket, private_key, username):
    client_socket.send("send_message".encode())
    response = client_socket.recv(1024).decode()
    if response != "message":
        print(f"Server response: {response}")
        return
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
    
    choice = None
    while choice not in ['1', '2']:
        choice = input("Choose option (1 or 2): ")
        if choice not in ['1', '2']:
            print("Invalid option! Please choose again.")
            
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
        choice = None
        while choice not in ['1', '2']:
            choice = input("Choose option (1 or 2): ")
            if choice not in ['1', '2']:
                print("Invalid option! Please choose again.")
        if choice == '2':
            client_socket.send('exit'.encode())
            break
        elif choice == '1':
            send_message(client_socket, private_key, username)
    client_socket.close()

if __name__ == "__main__":
    main()