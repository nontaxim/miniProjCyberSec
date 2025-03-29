import signal
import os
import json
import pytest
import socket
import requests
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
      
def generate_rsa_key_pair(username):
    """Generate an RSA key pair and save the private and public keys in the e2e_test2 folder."""
    # Generate Private Key and Public Key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    # Create e2e_test2 folder if it does not exist
    key_folder = os.path.join("e2e_tests", "temp_keys")
    os.makedirs(key_folder, exist_ok=True)
    
    # Save Private Key to a .pem file
    private_key_path = os.path.join(key_folder, f"{username}_private_key.pem")
    with open(private_key_path, "wb") as private_key_file:
        private_key_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Save Public Key to a .pem file
    public_key_path = os.path.join(key_folder, f"{username}_public_key.pem")
    with open(public_key_path, "wb") as public_key_file:
        public_key_file.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    
    return public_key_pem

def get_otp_from_email():
    """Fetch OTP from the mock email server (MailHog) to simulate OTP verification during registration."""
    # Retrieve all messages from MailHog
    response = requests.get("http://localhost:8025/api/v2/messages")
    messages = response.json()["items"]
    for message in messages:
        # Decode Base64 from the email body
        encoded_body = message["Content"]["Body"]
        decoded_body = base64.b64decode(encoded_body).decode("utf-8")
        
        # Search for OTP in the decoded message
        if "Your OTP is:" in decoded_body:
            otp = decoded_body.split(":")[1].strip()
            return otp
    return None

def load_private_key(username):
    """
    Load the private key from a file.
    
    :param username: The username associated with the private key.
    :return: The loaded private key object or None if not found.
    """
    key_folder = os.path.join("e2e_tests", "temp_keys")
    private_key_path = os.path.join(key_folder, f"{username}_private_key.pem")
    if not os.path.exists(private_key_path):
        print(f"Error: {private_key_path} not found!")
        return None
    
    with open(private_key_path, 'rb') as file:
        return serialization.load_pem_private_key(file.read(), password=None, backend=default_backend())
    
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


def register_user(client_socket, username, email, password, public_key):
    """Helper function to register a user."""
    # Step 1: Send "register" command
    client_socket.send("register".encode())
    response = client_socket.recv(1024).decode()
    assert response == "registration", "Server did not send 'registration' as expected"

    # Step 2: Send registration data
    registration_data = {
        "username": username,
        "email": email,
        "password": password,
        "public_key": public_key,
    }
    client_socket.send(json.dumps(registration_data).encode())
    response = client_socket.recv(1024).decode()
    assert response == "Please enter OTP", "Server did not request OTP as expected"

    # Step 3: Send OTP
    otp = get_otp_from_email()
    assert otp is not None, "OTP not found in email"
    client_socket.send(otp.encode())
    response = client_socket.recv(1024).decode()
    assert response == "Registration successful!", "Registration failed unexpectedly"
    
def login_user(client_socket, username, password):
    """Helper function to login a user."""
    # Send "login" command    
    client_socket.send("login".encode())
    response = client_socket.recv(1024).decode()
    assert response == "login", "Server did not request to Login as expected"

    # Send Username and Signature
    client_socket.send(username.encode())
    
    challenge = client_socket.recv(1024).decode()
    private_key = load_private_key(username)
    signed_challenge = signed_message(private_key, challenge)
    client_socket.send(signed_challenge.encode())
    
    signed_response = client_socket.recv(1024).decode()
    assert signed_response == "valid signature!", "Invalid signature"

    # Send Password
    client_socket.send(password.encode())
    response = client_socket.recv(1024).decode()
    assert response == "Login successful!", "Login failed unexpectedly"    
    
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