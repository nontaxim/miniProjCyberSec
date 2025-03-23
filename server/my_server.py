import base64
import socket
import json
import pyotp
import base64
import smtplib
import sqlite3
import hashlib
from email.mime.text import MIMEText
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from dotenv import load_dotenv
import os
import time
import threading
import re

# Load environment variables from .env file
load_dotenv(dotenv_path="./.env")

# Access the variables
sender_email = os.environ.get("SENDER_EMAIL")
sender_password = os.environ.get("SENDER_PASSWORD")
secret_key = os.environ.get("OTP_SECRET_KEY")
salt = base64.b64decode(os.environ.get("SALT"))

IS_BY_PASS_OTP = False

# Dictionaries to store client details, OTP, sockets, and challenges
clients = {}  # Store clients' details (username -> public_key)
client_otp = {}  # Store OTP for each client
client_sockets = {}  # Store client sockets
challenges = {}


#Initialize the SQLite database and create the users table.
def init_db():
    with sqlite3.connect("user_data.db") as conn:
        cursor = conn.cursor()
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            public_key TEXT NOT NULL
        );
        """)
        conn.commit()

#Securely hash a password with PBKDF2 and return salt + hash.
def hash_password(password, salt):
    if salt is None:
        salt = os.urandom(16)  # Generate new salt
    hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return salt + hashed_password  # Store salt + hash together

 #Add a new user securely to the database
def add_user(username, email, password, public_key):
    print(username, email, password, public_key)
    try:
        with sqlite3.connect("user_data.db") as conn:
            cursor = conn.cursor()
            # salt = os.urandom(16)  # Generate salt for this user
            hashed_password = hash_password(password, salt)
            print(salt)
            try:
                cursor.execute("INSERT INTO users (username, email, password, public_key) VALUES (?, ?, ?, ?)", 
                            (username, email, hashed_password, public_key))
                conn.commit()
                print(f"User {username} added successfully!")
            except sqlite3.IntegrityError:
                print(f"Error: A user with email {email} or username {username} already exists.")
    except Exception as e:
        print(f"Error adding user: {e}")

def get_users():
    """
    Retrieve all users from the database.
    """
    with sqlite3.connect("user_data.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, email FROM users")  # Exclude passwords for security
        users = cursor.fetchall()
    print("\nAll Users:")
    for user in users:
        print(user)

def verify_user(username, password, salt):
    """
    Verify user's login credentials.
    """
    with sqlite3.connect("user_data.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()

    if result:
        stored_password = result[0]
        # CHECK**************** 
        # salt = stored_password[:16]  # Extract salt
        hashed_attempt = hash_password(password, salt)
        return hashed_attempt == stored_password
    return False
  
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

def send_otp_email(email, otp, client_socket):
    """
        Send an OTP to the user's email address.
        
        :param email: The recipient email address.
        :param otp: The OTP to be sent.
        :param client_socket: The socket object used to communicate with the client.
    """

    time.sleep(1)

    # Ensure OTP is a clean string with no hidden characters
    otp = str(otp).strip()  # Strip any leading/trailing whitespace

    # Replace non-breaking space (\xa0) or any unwanted characters
    # otp = otp.replace("\xa0", " ").encode("utf-8", "ignore").decode("utf-8")
    otp = otp.replace("\xa0", " ")
    # Create the email message
    
    msg = MIMEText(f"Your OTP is: {otp}", "plain", "utf-8")
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
    client_socket.send("registration".encode())
    data = client_socket.recv(1024).decode()
    user_data = json.loads(data)

    username = user_data['username']
    email = user_data['email']
    password = user_data['password']
    public_key = user_data['public_key']
    
    # Validate username
    if not username.strip():
        client_socket.send("Invalid username! Username cannot be empty.".encode())
        return

    # Validate email
    if not validate_email(email):
        client_socket.send("Invalid email format!".encode())
        return
    
    # Validate password
    while not validate_password(password):
        client_socket.send("Invalid password! Please enter a stronger password.".encode())
        return

    # Generate OTP and send to client's email
    if not IS_BY_PASS_OTP:
        otp = generate_otp()
        send_otp_email(email, otp, client_socket)
        client_otp[username] = otp
        print(f"Sent OTP to {email}")

    # Request OTP from client
    client_socket.send("Please enter OTP".encode())
    # Wait for OTP from client
    otp_from_client = client_socket.recv(1024).decode()

    if not verify_otp(username, otp_from_client):
        client_socket.send("Invalid OTP!".encode())
        return
    else:
        print("OTP verified! at 215")
        add_user(username, email, password, public_key)
        print(f"Client {username} registered successfully.")
        client_socket.send("Registration successful!".encode())


def handle_login(client_socket):
    """
        Handle the login process of a client.
        
        :param client_socket: The socket object used to communicate with the client.
    """
    client_socket.send("login".encode())
    data = client_socket.recv(1024).decode()
    username = data

    # Server sends a challenge
    challenge = generate_challenge(username)
    client_socket.send(challenge.encode())

    # Wait for the signed challenge message from the client
    signed_challenge = client_socket.recv(1024).decode()

    with sqlite3.connect("user_data.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT public_key FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()

    if result:
    # if username in clients:
        public_key = serialization.load_pem_public_key(result[0].encode(), backend=default_backend())
        try:
            public_key.verify(
                bytes.fromhex(signed_challenge),
                challenge.encode(),
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            client_socket.send("valid signature!".encode())
        except Exception as e:
            client_socket.send("Invalid signature!".encode())
            client_socket.close()  # close the connection after sending the error
            return
    else:
        client_socket.send("Client not registered!".encode())
        client_socket.close()  # close the connection after sending the error
        return

    print(f"pass challenge for {username}")

    # Wait for password input from client
    print("Waiting for password...")
    password = client_socket.recv(1024).decode()
    print(f"Received password: {password}")

    if not verify_user(username, password, salt):
        client_socket.send("Invalid password!".encode())
        client_socket.close()
        return
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
    client_socket.send("message".encode())
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
    init_db()
    start_server()
