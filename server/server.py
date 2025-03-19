import socket
import json
import pyotp
import base64
import smtplib
from email.mime.text import MIMEText
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from dotenv import load_dotenv
import os
import time
import threading

# Load environment variables from .env file
load_dotenv(dotenv_path="./.env")

# Access the variables
sender_email = os.environ.get("SENDER_EMAIL")
sender_password = os.environ.get("SENDER_PASSWORD")
secret_key = os.environ.get("OTP_SECRET_KEY")
salt = os.environ.get("SALT")

IS_BY_PASS_OTP = False

# Dictionaries to store client details, OTP, sockets, and challenges
clients = {}  # Store clients' details (username -> public_key)
client_otp = {}  # Store OTP for each client
client_sockets = {}  # Store client sockets
challenges = {}

def generate_challenge(username):
    """
        Generate a secure random challenge for the client.
        
        :param username: The username of the client requesting the challenge.
        :return: The generated challenge in hexadecimal format.
    """
    challenge = os.urandom(32).hex()  # Generate a secure random challenge
    timestamp = time.time()  # Store the creation time
    challenges[username] = (challenge, timestamp)  # Save challenge for validation
    return challenge

def validate_secret_key(secret_key):
    try:
        # Decode the Base32 key to ensure it's valid
        base64.b32decode(secret_key, casefold=True)
        return True
    except Exception as e:
        print(f"Invalid secret key: {e}")
        return False
    
def send_otp_email(email, otp, client_socket):
    """
        Send an OTP to the user's email address.
        
        :param email: The recipient email address.
        :param otp: The OTP to be sent.
        :param client_socket: The socket object used to communicate with the client.
    """
    msg = MIMEText(f"Your OTP is: {otp}")
    msg["Subject"] = "Your OTP for Registration"
    msg["From"] = sender_email
    msg["To"] = email

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, email, msg.as_string())
    except smtplib.SMTPAuthenticationError as e:
        print(f"Authentication error: {e}")
        client_socket.close()
    except Exception as e:
        print(f"Failed to send OTP: {e}")
        client_socket.close()

def generate_otp():
    """
        Generate a one-time password (OTP) using pyotp.
        
        :return: The generated OTP.
    """
    totp = pyotp.TOTP(secret_key)  # This should be a secret key per user
    return totp.now()

def verify_otp(username, otp):
    """
        Verify if the OTP provided by the client matches the stored OTP.
        
        :param username: The username of the client.
        :param otp: The OTP received from the client.
        :return: True if the OTP is valid, False otherwise.
    """
    if IS_BY_PASS_OTP or client_otp.get(username) == otp:
        return True
    return False

# TODO: If user register with same username ask user to change username
# TODO: password must reach minimum requirement for security like minimum character, special character, number etc
#       if password is not secure enough ask user to change password
def handle_registration(client_socket):
    """
        Handle the registration process of a new client.
        
        :param client_socket: The socket object used to communicate with the client.
    """
    data = client_socket.recv(1024).decode()
    user_data = json.loads(data)

    username = user_data['username']
    email = user_data['email']
    password = user_data['password']
    public_key = user_data['public_key']

    # Generate OTP and send to client's email
    if not IS_BY_PASS_OTP:
        otp = generate_otp()
        send_otp_email(email, otp, client_socket)
        client_otp[username] = otp
        print(f"Sent OTP to {email}")

    # Wait for OTP from client
    otp_from_client = client_socket.recv(1024).decode()

    if verify_otp(username, otp_from_client):
        
        # TODO: hash password before storing
        # TODO: store in DB not variable like this

        clients[username] = {
            "username": username,
            "email": email,
            "public_key": public_key,
            "password": hash(password),
        }
        print(f"Client {username} registered successfully.")
        client_socket.send("Registration successful!".encode())
    else:
        client_socket.send("Invalid OTP!".encode())

def hash(message):
    """
        Hash a password or other sensitive data.
        
        :param message: The message to be hashed.
        :return: The hashed value of the message.
    """
    # TODO: find & use a secure hashing algorithm & please use some salt
    return message


def handle_login(client_socket):
    """
        Handle the login process of a client.
        
        :param client_socket: The socket object used to communicate with the client.
    """
    data = client_socket.recv(1024).decode()
    username = data

    # Server sends a challenge
    challenge = generate_challenge(username)
    client_socket.send(challenge.encode())

    # Wait for the signed challenge message from the client
    signed_challenge = client_socket.recv(1024).decode()

    if username in clients:
        public_key = serialization.load_pem_public_key(clients[username]["public_key"].encode(), backend=default_backend())
        try:
            public_key.verify(
                bytes.fromhex(signed_challenge),
                challenge.encode(),
                padding.PKCS1v15(),
                hashes.SHA256()
            )
        except Exception as e:
            client_socket.send("Invalid signature!".encode())
            client_socket.close()
    else:
        client_socket.send("Client not registered!".encode())
        client_socket.close()

    print(f"pass challenge for {username}")

    # Wait for password input from client
    print("Waiting for password...")
    password = client_socket.recv(1024).decode()
    print(f"Received password: {password}")

    # TODO: hash password before comparing

    if clients[username]['password'] != password:
        client_socket.send("Invalid password!".encode())
        client_socket.close()
    client_socket.send("Login successful!".encode())

def get_public_key(username):
    """
        Retrieve the public key of a client based on their username.
        
        :param username: The username of the client.
        :return: The client's public key or None if not found.
    """
    if username in clients:
        return clients[username]["public_key"]
    return None

def recv_all(client_socket, buffer_size=1024):
    """
        Receive all data from the client socket until no more data is available.
        
        :param client_socket: The socket object used to communicate with the client.
        :param buffer_size: The buffer size for receiving data (default is 1024).
        :return: The received data as a string.
    """
    data = b''  # Start with an empty byte string
    while True:
        part = client_socket.recv(buffer_size)
        data += part
        if len(part) < buffer_size:
            break  # No more data
    return data.decode()

def handle_message(client_socket):
    """
        Handle the sending of a message from one client to another.
        
        :param client_socket: The socket object used to communicate with the client.
    """
    to_client = client_socket.recv(1024).decode()
    print(f"Message to: {to_client}")
    client_socket.send(get_public_key(to_client).encode())

    # Wait for message data from client
    print("Waiting for message data...")
    data = recv_all(client_socket)
    message_data = json.loads(data)
    print(f"Message data: {message_data}")

    from_client = message_data['from_client']
    to_client = message_data['to_client']
    encrypted_message = message_data['encrypted_message']
    signature = message_data['signature']

    client_socket.send("Message received!".encode())

    # TODO: send message & signed message & sender's username to recipient

def handle_client(client_socket):
    """
        Handle the communication with a connected client.
        
        :param client_socket: The socket object used to communicate with the client.
    """
    while True:
        try:
            data = client_socket.recv(1024).decode()
            if not data:
                break  # Client disconnected
            print(f"Received data: {data}")

            if data == "register":
                handle_registration(client_socket)
            elif data == "login":
                handle_login(client_socket)
            elif data == "send_message":
                print("Handling message...")
                handle_message(client_socket)
            elif data == "exit":
                print("Client requested to exit.")
                break  # Exit loop
        except Exception as e:
            print(f"Error handling client: {e}")
            break  # Stop loop on error

    client_socket.close()
    print("Client disconnected.")

def start_server():
    """
        Start the server and listen for incoming client connections.
        
        This function will handle each client in a separate thread.
    """
    global secret_key
    if not secret_key:
        print("OTP_SECRET_KEY not found in .env. Generating a new one...")
        secret_key = pyotp.random_base32()
        print(f"Generated OTP_SECRET_KEY🔑 successfully")
        
    # Validate the secret key
    if not validate_secret_key(secret_key):
        raise ValueError("Invalid OTP_SECRET_KEY. Please check your .env file or regenerate the key.")
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', 5555))
    server.listen(5)

    print("Server started, waiting for clients...")
    while True:
        client_socket, client_address = server.accept()
        print(f"New connection from {client_address}")
        
        # Handle each client in a separate thread
        client_thread = threading.Thread(target=handle_client, args=(client_socket,))
        client_thread.start()

if __name__ == "__main__":
    start_server()
