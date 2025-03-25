import json
import sys
import os
import requests
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import base64

# ============================================
# Pytest Test Cases for E2E Registration
# ============================================

# 1. Successful Registration with OTP via Email
#    - Verify that a user can successfully register when providing correct details and a valid OTP.

# 2. Registration Fails with Invalid OTP
#    - Ensure that registration fails when the user provides an incorrect OTP.

# 3. Registration Fails with Duplicate Email
#    - Confirm that registration fails when using an email that already exists in the system.

# 4. Registration Fails with Missing Data
#    - Check that registration fails when required fields (e.g., username or email) are missing.


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


def test_registration_success_with_email(start_server, client_socket):
    """Test End-to-End (E2E) successful registration with OTP sent via email."""
    print("-" * 50)
    # Send the "register" command to the server to initiate the registration process
    client_socket.send("register".encode())
    
    # Generate an RSA key pair for the user
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    # Simulated registration data
    registration_data = {
        "username": "test_user",
        "email": "test_user@example.com",
        "password": "SecurePass123!",
        "public_key": public_key_pem,
    }
    # Send registration data to the server
    client_socket.send(json.dumps(registration_data).encode())

    # Wait for the server to request OTP
    response = client_socket.recv(1024).decode()
    assert response == "Please enter OTP", "Server did not request OTP as expected"
    
    # Fetch OTP from the mock email server
    otp = get_otp_from_email()
    assert otp is not None, "OTP not found in email"

    # Send OTP back to the server
    client_socket.send(otp.encode())
    
    # Verify the response indicates successful registration
    response = client_socket.recv(1024).decode()
    assert response == "Registration successful!"


def test_registration_fail_invalid_otp(start_server, client_socket):
    """Test registration failure when an invalid OTP is provided."""
    print("-" * 50)
    client_socket.send("register".encode())
    
    # Generate an RSA key pair for the user
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    # Simulated registration data
    registration_data = {
        "username": "test_user2",
        "email": "test_user@example.com",
        "password": "SecurePass123!",
        "public_key": public_key_pem,
    }
    client_socket.send(json.dumps(registration_data).encode())

    # Wait for the server to request OTP
    response = client_socket.recv(1024).decode()
    assert response == "Please enter OTP", "Server did not request OTP as expected"

    # Send an invalid OTP
    client_socket.send("wrong_otp".encode())

    # Verify the response indicates registration failure
    response = client_socket.recv(1024).decode()
    assert response == "Invalid OTP!", "Expected error for invalid OTP"


def test_registration_fail_duplicate_email(start_server, client_socket):
    """Test registration failure when a duplicate email is used."""
    print("-" * 50)
    client_socket.send("register".encode())
    
    # Generate an RSA key pair for the user
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    # Simulated registration data with a duplicate email
    registration_data = {
        "username": "test_user3",
        "email": "test_user@example.com",  # Duplicate email
        "password": "SecurePass123!",
        "public_key": public_key_pem,
    }
    client_socket.send(json.dumps(registration_data).encode())
    
    # Wait for the server to request OTP
    response = client_socket.recv(1024).decode()
    assert response == "Please enter OTP", "Server did not request OTP as expected"

    # Fetch OTP from the mock email server
    otp = get_otp_from_email()
    assert otp is not None, "OTP not found in email"

    # Send OTP back to the server
    client_socket.send(otp.encode())
    
    # Verify the response indicates duplicate email error
    response = client_socket.recv(1024).decode()
    assert response == "This email already exists", "Expected error for duplicate email"

def test_registration_fail_duplicate_username(start_server, client_socket):
    """Test registration failure when a duplicate username is used."""
    print("-" * 50)
    client_socket.send("register".encode())
    
    # Generate an RSA key pair for the user
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    # Simulated registration data with a duplicate username
    registration_data = {
        "username": "test_user", # Duplicate username
        "email": "test_user1@example.com", 
        "password": "SecurePass123!",
        "public_key": public_key_pem,
    }
    client_socket.send(json.dumps(registration_data).encode())
    
    # Wait for the server to request OTP
    response = client_socket.recv(1024).decode()
    assert response == "Please enter OTP", "Server did not request OTP as expected"

    # Fetch OTP from the mock email server
    otp = get_otp_from_email()
    assert otp is not None, "OTP not found in email"

    # Send OTP back to the server
    client_socket.send(otp.encode())
    
    # Verify the response indicates duplicate email error
    response = client_socket.recv(1024).decode()
    assert response == "This username already exists", "Expected error for duplicate email"
    
    
def test_registration_fail_missing_data(start_server, client_socket):
    """Test registration failure when required data is missing."""
    print("-" * 50)
    client_socket.send("register".encode())
    
    # Simulated registration data missing the `email` field
    registration_data = {
        "username": "test_user4",
        "password": "SecurePass123!",
        "public_key": "mocked_public_key",
    }
    client_socket.send(json.dumps(registration_data).encode())

    # Verify the response indicates missing data error
    response = client_socket.recv(1024).decode()
    assert response == "Missing data", "Expected error for missing data"
