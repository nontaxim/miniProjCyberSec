import socket
import json
import os
import sys
import time
import getpass
import re
import threading
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
        # print(f"Error: {private_key_path} not found!")
        print("Please Register User First.")
        return None
    
    with open(private_key_path, 'rb') as file:
        return serialization.load_pem_private_key(file.read(), password=None, backend=default_backend())

def generate_RSA_key(username):
    """
    Generate and save public/private key pair for a given username.
    
    :param username: The username associated with the keys.
    :return: A tuple containing (private_key, public_key)
    """
    private_key_path = f"{username}_private_key.pem"
    public_key_path = f"{username}_public_key.pem"

    if os.path.exists(private_key_path) and os.path.exists(public_key_path):
        print(f"username: {username} already exists.")
        return None, None

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    
    # Save private key
    with open(private_key_path, "wb") as private_key_file:
        private_key_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Save public key
    with open(public_key_path, "wb") as public_key_file:
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

def decrypt_message(private_key, encrypted_message_hex):
    """
    Decrypt a message using the recipient's private key.
    
    :param private_key: The recipient's private key.
    :param encrypted_message_hex: The encrypted message as a hexadecimal string.
    :return: The decrypted message string.
    """
    try:
        decrypted_message = private_key.decrypt(
            bytes.fromhex(encrypted_message_hex),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ).decode()
        return decrypted_message
    except Exception as e:
        print(f"Error decrypting message: {e}")
        return None

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
    if " " in password:
        print("Password must not contain spaces.")
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

def validate_username(username):
    """
    Validate the username to ensure it contains only alphanumeric characters and underscores.
    
    :param username: The username to validate.
    :return: True if the username is valid, False otherwise.
    """
    username_regex = r'^[a-zA-Z0-9_]+$'
    return re.match(username_regex, username) is not None

def register_client(client_socket, username):
    """
    Register a new client by generating keys and sending the public key to the server.
    
    :param client_socket: The active socket connection to the server.
    :param username: The username to register.
    :return: Tuple (private_key, public_key) on success, None otherwise.
    """
    while not username.strip():
        username = input("Username cannot be empty.\nPlease enter your username: ")
    
    private_key, public_key = generate_RSA_key(username)
    if not private_key or not public_key:
        return None, None
    
    client_socket.send("register".encode())
    response = client_socket.recv(1024).decode()
    if response != "registration":
        print(f"Server response: {response}")
        client_socket.close()
        return None, None
    

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    email = input("Enter your email: ")
    while not validate_email(email):
        email = input("Invalid email format.\nPlease enter a valid email: ")
        
    password = getpass.getpass("Enter your password: ")
    while not validate_password(password):
        password = getpass.getpass("Enter your password: ")

    registration_data = {'username': username, 'public_key': public_key_pem, "email": email, "password": password}
    client_socket.send(json.dumps(registration_data).encode())
    
    response = client_socket.recv(1024).decode()
    if response == "Please enter OTP":
        OTP_data = input("Enter OTP: ")  # Read OTP from user
        client_socket.send(OTP_data.encode())  # Send OTP to server
    else:
        print(f"Unexpected server response: {response}")
        return None, None
    
    response = client_socket.recv(1024).decode()
    print(f"Server response: {response}")
    if "successful" not in response:
        print("Registration failed!")
        return None, None
    
    return private_key, public_key

def request_public_key(client_socket, to_client):
    """
    Request the public key of another user from the server.
    
    :param client_socket: The active socket connection to the server.
    :param to_client: The recipient's username.
    :return: The recipient's public key in PEM format.
    """
    client_socket.send(to_client.encode())
    return client_socket.recv(4096).decode()

def login_client(client_socket, username, private_key):
    """
    Authenticate a client with the server using a challenge-response mechanism.
    
    :param client_socket: The active socket connection to the server.
    :param username: The username to log in.
    :param private_key: The user's private key for signing the challenge.
    :return: True if login is successful, False otherwise.
    """
    login_attempts = 0  # Variable to store the number of login attempts

    while login_attempts < 3:  # Allow a maximum of 3 login attempts
        client_socket.send("login".encode())
        time.sleep(0.5)

        response = client_socket.recv(1024).decode()
        if response != "login":
            print(f"Server response: {response}")
            return False
        
        client_socket.send(username.encode())
        
        challenge = client_socket.recv(1024).decode()
        if "not registered" in challenge:
            print(f"Error: {challenge}")
            return False
        elif "Too many login attempts" in challenge:
            print(challenge)
            return False
            
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
            if "successful" in response:
                return True  # Login successful
            elif "Wrong password!" in response:
                print("Remaining attempts: ", 3 - login_attempts)
                login_attempts += 1  # Increment the number of login attempts
        except Exception as e:
            return False
    print("Too many login attempts. Please try again later.")
    return False

def send_message(client_socket, private_key, username):
    """
    Send a message to another client.
    
    :param client_socket: The active socket connection to the server.
    :param private_key: The sender's private key.
    :param username: The sender's username.
    """
    client_socket.send("send_message".encode())

    response = client_socket.recv(1024).decode()
    if response != "message":
        print(f"Server response: {response}")
        return
      
    to_client = input("Enter recipient's username: ")
    while not to_client.strip():
        to_client = input("recipient's username cannot be empty.\nPlease enter your recipient's username: ")

    message = input("Enter your message: ")
    while not message.strip():
        message = input("Message cannot be empty.\nPlease enter your message: ")

    recipient_public_key = request_public_key(client_socket, to_client)
    if not recipient_public_key or recipient_public_key == "Recipient not found!":
        print("Failed to get recipient's public key.")
        return

    encrypted_message = encrypt_message(recipient_public_key, message)
    signature = signed_message(private_key, encrypted_message)

    message_data = {
        'from_client': username,
        'to_client': to_client,
        'encrypted_message': encrypted_message,
        'signature': signature
    }
    print(f"Sending message to {to_client}...")
    client_socket.sendall(json.dumps(message_data).encode())

def receive_messages(client_socket, private_key, stop_event):
    """
    Continuously listen for incoming messages from the server.
    
    :param client_socket: The active socket connection to the server.
    :param private_key: The user's private key for decrypting messages.
    :param stop_event: Threading event to signal when to stop the thread.
    """
    client_socket.settimeout(10.0)
    
    while not stop_event.is_set():
        try:
            data = client_socket.recv(4096)
            if not data:
                print("Server disconnected.")
                break
            
            data_str = data.decode()
            
            if any(x in data_str for x in ["successful", "forwarded", "not found", "not online"]):
                continue

            if "-----BEGIN PUBLIC KEY-----" in data_str:
                sender_public_key = data_str
                message_data = json.loads(client_socket.recv(4096).decode())
                
                if all(k in message_data for k in ["from_client", "encrypted_message", "signature"]):
                    from_client = message_data['from_client']
                    encrypted_message = message_data['encrypted_message']
                    signature = message_data['signature']
                    
                    try:
                        public_key = serialization.load_pem_public_key(sender_public_key.encode(), backend=default_backend())
                        public_key.verify(
                            bytes.fromhex(signature),
                            encrypted_message.encode(),
                            padding.PKCS1v15(),
                            hashes.SHA256()
                        )
                        print("\nSender's signature verified.")
                    except Exception as e:
                        print(f"\nError: Invalid signature from {from_client}")
                        continue
                    
                    decrypted_message = decrypt_message(private_key, encrypted_message)
                    if decrypted_message:
                        print(f"[Message from {from_client}]: {decrypted_message}")
                        print("\nOptions: [1] Send Message [2] Exit")
                    else:
                        print(f"\nError: Could not decrypt message from {from_client}")
                continue
        except socket.timeout:
            continue
        except Exception as e:
            print(f"\nError receiving message: {e}")
            break

def stop_receive_thread(receive_thread, stop_event):
    stop_event.set()
    receive_thread.join()

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
    
    while not validate_username(username):
        username = input("Invalid username format.\n"
                        "A valid username can only contain letters, numbers, and underscores (_).\n"
                        "Please enter a valid username: ")
    
    private_key = None
    if choice == '1':
        private_key, public_key = register_client(client_socket, username)
        if not private_key or not public_key:
            client_socket.close()
            return
    elif choice == '2':
        private_key = load_private_key(username)
        if not private_key or not login_client(client_socket, username, private_key):
            client_socket.close()
            return
    else:
        print("Invalid option!")
        client_socket.close()
        return
    
    stop_event = threading.Event()
    
    receive_thread = threading.Thread(target=receive_messages, args=(client_socket, private_key, stop_event))
    receive_thread.daemon = True
    receive_thread.start()
    
    while True:
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
    stop_receive_thread(receive_thread, stop_event)
    client_socket.close()

if __name__ == "__main__":
    main()