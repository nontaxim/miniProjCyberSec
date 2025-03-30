import json
import pytest
import socket
import subprocess
import time
import os
import signal
from e2e_test_utils import generate_rsa_key_pair, get_otp_from_email , signed_message , load_private_key
from cryptography.hazmat.primitives.asymmetric import rsa
# ============================================
# Pytest Test Cases for E2E Login
# ============================================

# Test Case 1: Login After Register and Exit
# Purpose: Ensure a user can register, exit the system, and log in again successfully.

# Test Case 2: Login After Restart Server
# Purpose: Verify that a user can log in successfully after the server is restarted.

# Test Case 3: Failed Login with Incorrect Password
# Purpose: Ensure the system rejects login attempts with an incorrect password.

# Test Case 4: Failed Login for Unregistered User
# Purpose: Verify that the system rejects login attempts for users who are not registered.

# Test Case 5: Failed Login with Invalid Digital Signature
# Purpose: Ensure the system rejects login attempts with an invalid digital signature.

# Test Case 6: Failed Login Due to Too Many Attempts
# Purpose: Verify that the system blocks login attempts after exceeding the allowed number of failed attempts.

# Test Case 7: Successful Login After Too Many Attempts
# Purpose: Ensure a user can log in successfully after the cooldown period following too many failed attempts.

pytestmark = [pytest.mark.login, pytest.mark.order(2)] 
def test_login_after_register_and_exit(start_server, client_socket):
    """Test login after registering and choosing exit."""
    # Step 1: Register the user
    client_socket.send("register".encode())
    response = client_socket.recv(1024).decode()
    assert response == "registration", "Server did not send 'registration' as expected"

    username = "test_user"
    email = "test_user@example.com"
    password = "SecurePass123!"
    public_key = generate_rsa_key_pair(username)

    registration_data = {
        "username": username,
        "email": email,
        "password": password,
        "public_key": public_key,
    }
    client_socket.send(json.dumps(registration_data).encode())
    response = client_socket.recv(1024).decode()
    assert response == "Please enter OTP", "Server did not request OTP as expected"

    # Fetch OTP from mock email server
    otp = get_otp_from_email()
    assert otp is not None, "OTP not found in email"
    client_socket.send(otp.encode())
    response = client_socket.recv(1024).decode()
    assert response == "Registration successful!", "Registration failed unexpectedly"

    # Step 2: Choose Exit
    client_socket.send('exit'.encode())
    response = client_socket.recv(1024).decode()
    assert response == "Goodbye!", "Server did not handle exit option correctly"

    # Step 3: Reconnect 
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 5555))
    print("Client ReConnected to server.🤖 ✅")
    
    # Step 4: Login again
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
    
def test_login_after_restart_server(start_server, client_socket):
    """Test login after restarting the server."""
    # Step 1: Restart the server (already started in the fixture)
    
    # Step 2: Login the same credentials
    username = "test_user"
    email = "test_user@example.com"
    password = "SecurePass123!"
    
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

def test_login_fail_incorrect_password(start_server, client_socket):
    """Test login failure when the password is incorrect."""
    # Step 1: Register the user
    client_socket.send("register".encode())
    response = client_socket.recv(1024).decode()
    assert response == "registration", "Server did not send 'registration' as expected"

    username = "test_user3"
    email = "test_user3@example.com"
    password = "SecurePass123!"
    public_key = generate_rsa_key_pair(username)

    registration_data = {
        "username": username,
        "email": email,
        "password": password,
        "public_key": public_key,
    }
    client_socket.send(json.dumps(registration_data).encode())
    response = client_socket.recv(1024).decode()
    assert response == "Please enter OTP", "Server did not request OTP as expected"

    otp = get_otp_from_email()
    assert otp is not None, "OTP not found in email"
    client_socket.send(otp.encode())
    response = client_socket.recv(1024).decode()
    assert response == "Registration successful!", "Registration failed unexpectedly"

    # Step 2: Attempt to login with incorrect password
    client_socket.send("login".encode())
    response = client_socket.recv(1024).decode()
    assert response == "login", "Server did not request to Login as expected"

    client_socket.send(username.encode())
    challenge = client_socket.recv(1024).decode()
    private_key = load_private_key(username)
    signed_challenge = signed_message(private_key, challenge)
    client_socket.send(signed_challenge.encode())

    signed_response = client_socket.recv(1024).decode()
    assert signed_response == "valid signature!", "Invalid signature"

    client_socket.send("wrongpassword".encode())
    response = client_socket.recv(1024).decode()
    assert response == "Wrong password!", "Expected 'Invalid password!' error"
    
    

def test_login_fail_unregistered_user(start_server, client_socket):
    """Test login failure for an unregistered user."""
    # Step 1: Attempt to login with an unregistered username
    username = "unregistered_user"
    password = "password@123123!Q"
    
    client_socket.send("login".encode())
    response = client_socket.recv(1024).decode()
    assert response == "login", "Server did not request to Login as expected"

    # Send Username
    client_socket.send(username.encode())
    response = client_socket.recv(1024).decode()
    
    # Verify server response for unregistered user
    assert response == "Client not registered!", f"Unexpected server response: {response}"

    
def test_login_fail_invalid_signature(start_server, client_socket):
    """Test login failure when the digital signature is invalid."""
    # Step 1: Register the user
    client_socket.send("register".encode())
    response = client_socket.recv(1024).decode()
    assert response == "registration", "Server did not send 'registration' as expected"

    username = "test_user4"
    email = "test_user4@example.com"
    password = "SecurePass123!"
    valid_public_key = generate_rsa_key_pair(username)

    registration_data = {
        "username": username,
        "email": email,
        "password": password,
        "public_key": valid_public_key,
    }
    client_socket.send(json.dumps(registration_data).encode())
    response = client_socket.recv(1024).decode()
    assert response == "Please enter OTP", "Server did not request OTP as expected"

    otp = get_otp_from_email()
    assert otp is not None, "OTP not found in email"
    client_socket.send(otp.encode())
    response = client_socket.recv(1024).decode()
    assert response == "Registration successful!", "Registration failed unexpectedly"

    # Step 2: Attempt to login with an invalid signature
    client_socket.send("login".encode())
    response = client_socket.recv(1024).decode()
    assert response == "login", "Server did not request to Login as expected"

    client_socket.send(username.encode())
    challenge = client_socket.recv(1024).decode()

    # Generate a mismatched key pair to simulate an invalid signature
    invalid_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    invalid_signed_challenge = signed_message(invalid_private_key, challenge)
    client_socket.send(invalid_signed_challenge.encode())

    # Verify the server's response
    response = client_socket.recv(1024).decode()
    assert response == "Invalid signature!", "Expected 'Invalid digital signature!' error"
    
def test_login_fail_too_many_attempts(start_server, client_socket):
    """Test login failure due to too many attempts."""
    # Step 1: Register the user
    client_socket.send("register".encode())
    response = client_socket.recv(1024).decode()
    assert response == "registration", "Server did not send 'registration' as expected"

    username = "test_user5"
    email = "test_user5@example.com"
    password = "SecurePass123!"
    public_key = generate_rsa_key_pair(username)

    registration_data = {
        "username": username,
        "email": email,
        "password": password,
        "public_key": public_key,
    }
    client_socket.send(json.dumps(registration_data).encode())
    response = client_socket.recv(1024).decode()
    assert response == "Please enter OTP", "Server did not request OTP as expected"

    otp = get_otp_from_email()
    assert otp is not None, "OTP not found in email"
    client_socket.send(otp.encode())
    response = client_socket.recv(1024).decode()
    assert response == "Registration successful!", "Registration failed unexpectedly"

    # Step 2: Attempt to login with incorrect password 3 times
    for attempt in range(3):
        client_socket.send("login".encode())
        response = client_socket.recv(1024).decode()
        assert response == "login", "Server did not request to Login as expected"

        client_socket.send(username.encode())
        challenge = client_socket.recv(1024).decode()
        private_key = load_private_key(username)
        signed_challenge = signed_message(private_key, challenge)
        client_socket.send(signed_challenge.encode())

        signed_response = client_socket.recv(1024).decode()
        assert signed_response == "valid signature!", "Invalid signature"

        client_socket.send("wrongpassword".encode())
        response = client_socket.recv(1024).decode()
        assert response == "Wrong password!", f"Unexpected server response: {response}"

    # Step 3: Verify too many attempts message
    client_socket.send("login".encode())
    response = client_socket.recv(1024).decode()
    assert response == "login", "Server did not request to Login as expected"

    client_socket.send(username.encode())
    challenge = client_socket.recv(1024).decode()
    print(challenge)
    assert "Too many login attempts" in challenge, f"Unexpected server response: {challenge}"
    

def test_login_pass_after_too_many_attempts(start_server, client_socket):
    """Test login success after too many attempts."""
      # Step 1: Register the user
    client_socket.send("register".encode())
    response = client_socket.recv(1024).decode()
    assert response == "registration", "Server did not send 'registration' as expected"

    username = "test_user6"
    email = "test_user6@example.com"
    password = "SecurePass123!"
    public_key = generate_rsa_key_pair(username)

    registration_data = {
        "username": username,
        "email": email,
        "password": password,
        "public_key": public_key,
    }
    client_socket.send(json.dumps(registration_data).encode())
    response = client_socket.recv(1024).decode()
    assert response == "Please enter OTP", "Server did not request OTP as expected"

    otp = get_otp_from_email()
    assert otp is not None, "OTP not found in email"
    client_socket.send(otp.encode())
    response = client_socket.recv(1024).decode()
    assert response == "Registration successful!", "Registration failed unexpectedly"

    # Step 2: Attempt to login with incorrect password 3 times
    for attempt in range(3):
        client_socket.send("login".encode())
        response = client_socket.recv(1024).decode()
        assert response == "login", "Server did not request to Login as expected"

        client_socket.send(username.encode())
        challenge = client_socket.recv(1024).decode()
        private_key = load_private_key(username)
        signed_challenge = signed_message(private_key, challenge)
        client_socket.send(signed_challenge.encode())

        signed_response = client_socket.recv(1024).decode()
        assert signed_response == "valid signature!", "Invalid signature"

        client_socket.send("wrongpassword".encode())
        response = client_socket.recv(1024).decode()
        assert response == "Wrong password!", f"Unexpected server response: {response}"

    # Step 3: Verify too many attempts message
    client_socket.send("login".encode())
    response = client_socket.recv(1024).decode()
    assert response == "login", "Server did not request to Login as expected"

    client_socket.send(username.encode())
    challenge = client_socket.recv(1024).decode()
    print(challenge)
    assert "Too many login attempts" in challenge, f"Unexpected server response: {challenge}"
    
    # Step 4: Wait for cooldown period 
    cooldown_time = int(challenge.split(" in")[1].split("seconds.")[0].strip())
    print(f"Waiting for cooldown period of {cooldown_time} seconds...")
    time.sleep(cooldown_time)
    time.sleep(2)  # Additional wait to ensure the server is ready

    # Step 5: Attempt to login with correct password after cooldown
    
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