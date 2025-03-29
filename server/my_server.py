import base64
import socket
import json
import pyotp
import base64
import smtplib
import sqlite3
import argon2
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from email.mime.text import MIMEText
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from dotenv import load_dotenv , find_dotenv
import os
import time
import threading
import re

# Load environment variables from .env file
load_dotenv(find_dotenv())

# Access the variables
sender_email = os.environ.get("SENDER_EMAIL")
sender_password = os.environ.get("SENDER_PASSWORD")
secret_key = os.environ.get("OTP_SECRET_KEY")
salt = base64.b64decode(os.environ.get("SALT"))

IS_BY_PASS_OTP = False

# Dictionaries to store client details, OTP, sockets, and challenges
#clients = {}  # Store clients' details (username -> public_key)
client_otp = {}  # Store OTP for each client
client_sockets = {}  # Store client sockets
challenges = {}

def get_database_path():
    """Return the appropriate database path based on the APP_MODE."""
    app_mode = os.environ.get("APP_MODE", "production").lower()
    if app_mode == "e2e_test":
        return os.path.join("e2e_tests", "test_user_data.db")  # Testing Database
    return "user_data.db"  # Real Database

def handle_sqlite_error(e):
    """
    Handle SQLite errors and provide detailed messages.
    :param e: The exception object
    """
    if isinstance(e, sqlite3.OperationalError):
        if "permission denied" in str(e).lower():
            print("Permission error: Check the database file permissions.")
        elif "disk I/O error" in str(e).lower():
            print("Disk I/O error: Check the disk space and I/O status.")
        else:
            print(f"Operational error: {e}")
    elif isinstance(e, sqlite3.IntegrityError):
        print(f"Integrity error: {e}")
    elif isinstance(e, sqlite3.ProgrammingError):
        print(f"Programming error: {e}")
    elif isinstance(e, sqlite3.DataError):
        print(f"Data error: {e}")
    elif isinstance(e, sqlite3.DatabaseError):
        print(f"Database error: {e}")
    else:
        print(f"Unexpected SQLite error: {e}")

#Initialize the SQLite database and create the users table.
def init_db():
    db_path = get_database_path()
    conn = None
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        print("Initializing database...")
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
        print("Database initialized successfully.")
    except sqlite3.Error as e: # Handle SQLite errors
        handle_sqlite_error(e)
    finally:
        if conn:
            conn.close()

# Initialize Argon2 hasher
argon2_hasher = PasswordHasher(time_cost=3,memory_cost=65536, parallelism=4)

# Verify a password against its stored Argon2 hash
def hash_password(password):
    return argon2_hasher.hash(password)

def add_user(username, email, password, public_key):
    """
    Add a new user securely to the database.
    """
    db_path = get_database_path()
    hashed_password = hash_password(password)  # Hash the password using Argon2
    conn = None
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if email or username already exists
        cursor.execute("SELECT username, email FROM users WHERE username = ? OR email = ?", (username, email))
        existing_user = cursor.fetchone()
        if existing_user:
            if existing_user[0] == username:
                return "This username already exists"
            if existing_user[1] == email:
                return "This email already exists"

        # Insert new user
        cursor.execute(
            "INSERT INTO users (username, email, password, public_key) VALUES (?, ?, ?, ?)",
            (username, email, hashed_password, public_key)
        )
        conn.commit()
        print(f"User {username} added successfully!")
        return None  # No error
    except sqlite3.IntegrityError:
        return "Error: A user with this email or username already exists."
    except sqlite3.Error as e: # Handle SQLite errors
        handle_sqlite_error(e)
        return "An unexpected error occurred."
    finally:
        if conn:
            conn.close()
  
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
        # Check the mode from environment variable
        app_mode = os.environ.get("APP_MODE", "production").lower()

        if app_mode == "e2e_test":
            print(f"------APP_MODE: {app_mode}-------")
            print(f"using localhost SMTP for testing in port 1025")
            print(f"By Capturing the email using MailHog")
            # Use MailHog for testing
            with smtplib.SMTP("localhost", 1025) as server:
                server.sendmail(sender_email, email, msg.as_string())
        else:
            # Use Gmail SMTP for production
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
        error = add_user(username, email, password, public_key)
        if error:
            print(f"Error adding user: {error}")
            client_socket.send(error.encode())
            return
        client_socket.send("Registration successful!".encode())
        print(f"Client {username} registered successfully.")

    client_sockets[username] = client_socket
    print(f"Client {username} registered. Active clients: {list(client_sockets.keys())}")

def handle_login(client_socket):
    """
    Handle the login process of a client.
    """
    client_socket.send("login".encode())
    try:
        # Receive username
        username = client_socket.recv(1024).decode()
        print(f"Login attempt from: {username}")

        # Fetch stored user data from the database
        db_path = get_database_path()
        conn = None
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT password, public_key FROM users WHERE username = ?", (username,))
            result = cursor.fetchone()
        except sqlite3.Error as e:  # Handle SQLite errors
            handle_sqlite_error(e)
        finally:
            if conn:
                conn.close()

        if result:
            stored_password, public_key_pem = result #get the stored password and public key

            # Server sends a challenge
            challenge = generate_challenge(username)
            client_socket.send(challenge.encode())
            # Wait for signed challenge
            signed_challenge = client_socket.recv(1024).decode()

            try:
                # Load the stored public key and verify the signed challenge
                public_key = serialization.load_pem_public_key(public_key_pem.encode(), backend=default_backend())
                
                public_key.verify(
                    bytes.fromhex(signed_challenge),
                    challenge.encode(),
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )
                client_socket.send("valid signature!".encode())
            except Exception as e:
                print(f"Invalid signature: {e}")
                client_socket.send("Invalid signature!".encode())
                return

            print(f"Challenge passed for {username}")

            # Wait for password input from the client
            password = client_socket.recv(1024).decode()
            print(f"Received password for {username}")
            
            # Simplified Argon2 verification
            try:
                if argon2_hasher.verify(stored_password, password):
                    client_socket.send("Login successful!".encode())
                    client_sockets[username] = client_socket
                    print(f"User {username} logged in successfully.")
                    return
            except VerifyMismatchError:
                pass  # Will send "Wrong password!" below
            except Exception as e:
                print(f"Password verification error: {e}")
            client_socket.send("Wrong password!".encode())
        else:
            client_socket.send("Client not registered!".encode())

    except Exception as e:
        print(f"Error handling login: {e}")
        client_socket.send("An unexpected error occurred.".encode())

    client_sockets[username] = client_socket
    print(f"Client {username} logged in. Active clients: {list(client_sockets.keys())}")

def get_public_key(username):
    """
    Retrieve the public key of a user from the database.
    
    :param username: The username of the user
    :return: The public key as a string or None if not found
    """
    conn = None
    try:
        conn = sqlite3.connect("user_data.db")
        cursor = conn.cursor()
        cursor.execute("SELECT public_key FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        if result:
            return result[0]
        return None
    except sqlite3.Error as e:
        handle_sqlite_error(e)
        return None
    finally:
        if conn:
            conn.close()

def recv_all(client_socket, buffer_size=4096):
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
    """
    client_socket.send("message".encode())
    try:
        to_client = client_socket.recv(1024).decode()
        print(f"Message to: {to_client}")
        
        recipient_public_key = get_public_key(to_client)
        if not recipient_public_key:
            client_socket.send("Recipient not found!".encode())
            return
            
        client_socket.send(recipient_public_key.encode())
        time.sleep(0.5)

        # Wait for message data from client
        print("Waiting for message data...")
        data = recv_all(client_socket)
        message_data = json.loads(data)
        print(f"Message data received from {message_data['from_client']} to {message_data['to_client']}")

        from_client = message_data['from_client']
        to_client = message_data['to_client']
        encrypted_message = message_data['encrypted_message']
        signature = message_data['signature']

        public_key = serialization.load_pem_public_key(get_public_key(from_client).encode(), backend=default_backend())
        try:
            public_key.verify(
                bytes.fromhex(signature),
                encrypted_message.encode(),
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            print("Signature verified.")
        except Exception as e:
            print(f"Invalid signature: {e}")
            client_socket.send("Invalid signature!".encode())
            return
        if to_client in client_sockets:
            recipient_socket = client_sockets[to_client]
            print(f"Forwarding message to {to_client}")
            if recipient_socket.fileno() == -1:  # ReCheck if the socket is closed
                print(f"Recipient {to_client}'s socket is closed.")
                del client_sockets[to_client]  # Remove the closed socket
                client_socket.send("Recipient not online!".encode())
                return
            try:
                sender_public_key = get_public_key(from_client)
                recipient_socket.sendall(sender_public_key.encode())
                time.sleep(0.1)
                recipient_socket.sendall(json.dumps(message_data).encode())
                print(f"Message successfully sent to {to_client}")
                client_socket.send("Message forwarded!".encode())
            except Exception as e:
                print(f"Error forwarding message: {e}")
                client_socket.send("Error forwarding message!".encode())
        else:
            print(f"Recipient {to_client} not online")
            client_socket.send("Recipient not online!".encode())
    except Exception as e:
        print(f"Error in handle_message: {e}")
        client_socket.send("Error processing message!".encode())

def handle_client(client_socket):
    """
    Handle the communication with a connected client.
    """
    try:
        while True:
            try:
                data = client_socket.recv(1024).decode()
                if not data:
                    print("Client disconnected.")
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
                    client_socket.send("Goodbye!".encode())
                    print("Client requested to exit.")
                    break  # Exit loop
            except ConnectionResetError:
                print("Client terminated the connection unexpectedly.")
                break
            except Exception as e:
                print(f"Error handling client: {e}")
                break  # Stop loop on error
    finally:
        # Clean up the client socket and remove from client_sockets
        username_to_remove = None
        for username, socket in client_sockets.items():
            if socket == client_socket:
                username_to_remove = username
                break
        if username_to_remove:
            if username_to_remove in client_sockets:
                del client_sockets[username_to_remove]
                print(f"Cleaned up {username_to_remove} from active clients.")
        client_socket.close()
        # print("client_sockets",client_sockets)
        print("Client socket Disconnected.")

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
    
    print("Starting server...")
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(('0.0.0.0', 5555))
        server.listen(5)
        print("Server started successfully and listening on port 5555.")
    except Exception as e:
        print(f"Error starting server: {e}")
        raise

    try:
        while True:
            client_socket, client_address = server.accept()
            print(f"New connection from {client_address}")
            
            # Handle each client in a separate thread
            client_thread = threading.Thread(target=handle_client, args=(client_socket,))
            client_thread.daemon = True
            client_thread.start()
    except KeyboardInterrupt:
        print("Server shutting down...")
    finally:
        server.close()
        
if __name__ == "__main__":
    init_db()
    start_server()
