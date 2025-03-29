import json
import sys
import os
import pytest
import time
from e2e_test_utils import generate_rsa_key_pair , get_otp_from_email

# ============================================
# Pytest Test Cases for E2E Registration
# ============================================

# 1. Successful Registration with OTP via Email
#    - Verify that a user can successfully register when providing correct details and a valid OTP.

# 2. Registration Fails with Invalid OTP
#    - Ensure that registration fails when the user provides an incorrect OTP.

# 3. Registration Fails with Duplicate Email
#    - Confirm that registration fails when using an email that already exists in the system.

# 4. Registration Fails with Duplicate Username
#    - Confirm that registration fails when using a username that already exists in the system.

# 5. Registration Fails with Missing Data
#    - Check that registration fails when required fields (e.g., username or email) are missing.

# 6. Registration Fails with Expired OTP
#    - Ensure that registration fails when the OTP has expired.


pytestmark = [pytest.mark.registration, pytest.mark.order(1)] 
@pytest.mark.order(1)
def test_registration_success_with_email(start_server, client_socket):
    """Test End-to-End (E2E) successful registration with OTP sent via email."""
    print("-" * 50)
    # Send the "register" command to the server to initiate the registration process
    client_socket.send("register".encode())
    
    # รอข้อความ "registration" จากเซิร์ฟเวอร์
    response = client_socket.recv(1024).decode()
    assert response == "registration", "Server did not send 'registration' as expected"
    
    username = "test_user1"
    email = "test_user1@example.com"
    password = "SecurePass123!"
    public_key = generate_rsa_key_pair(username)
    
    username = "test_user1"
    email = "test_user1@example.com"
    password = "SecurePass123!"
    public_key = generate_rsa_key_pair(username)
    
    # Simulated registration data
    registration_data = {
        "username": username,
        "email": email,
        "password": password,
        "public_key": public_key,
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
    
    # รอข้อความ "registration" จากเซิร์ฟเวอร์
    response = client_socket.recv(1024).decode()
    assert response == "registration", "Server did not send 'registration' as expected"
    
    username = "test_user2"
    email = "test_user2@example.com"
    password = "SecurePass123!"
    public_key = generate_rsa_key_pair(username)
    
    username = "test_user2"
    email = "test_user2@example.com"
    password = "SecurePass123!"
    public_key = generate_rsa_key_pair(username)
    
    # Simulated registration data
    registration_data = {
        "username": username,
        "email": email,
        "password": password,
        "public_key": public_key,
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
    
    # รอข้อความ "registration" จากเซิร์ฟเวอร์
    response = client_socket.recv(1024).decode()
    assert response == "registration", "Server did not send 'registration' as expected"
    
    username = "test_user3"
    email = "test_user1@example.com" # Duplicate email
    password = "SecurePass123!"
    public_key = generate_rsa_key_pair(username)
    
    # Simulated registration data
    registration_data = {
        "username": username,
        "email": email,
        "password": password,
        "public_key": public_key,
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
    
    # รอข้อความ "registration" จากเซิร์ฟเวอร์
    response = client_socket.recv(1024).decode()
    assert response == "registration", "Server did not send 'registration' as expected"
    
    username = "test_user1" # Duplicate username
    email = "test_user4@example.com"
    password = "SecurePass123!"
    public_key = generate_rsa_key_pair(username)
    
    # Simulated registration data
    registration_data = {
        "username": username,
        "email": email,
        "password": password,
        "public_key": public_key,
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
    
    # รอข้อความ "registration" จากเซิร์ฟเวอร์
    response = client_socket.recv(1024).decode()
    assert response == "registration", "Server did not send 'registration' as expected"
    
    username = "test_user5"
    password = "SecurePass123!"
    public_key = generate_rsa_key_pair(username)
    
    # Simulated registration data
    registration_data = {
        "username": username,
        "password": password,
        "public_key": public_key,
    }
    client_socket.send(json.dumps(registration_data).encode())

    # Verify the response indicates missing data error
    response = client_socket.recv(1024).decode()
    assert response == "Missing data", "Expected error for missing data"

def test_registration_fail_expired_otp(start_server, client_socket):
    """Test registration failure when OTP has expired."""
    print("-" * 50)
    client_socket.send("register".encode())
    
    # รอข้อความ "registration" จากเซิร์ฟเวอร์
    response = client_socket.recv(1024).decode()
    assert response == "registration", "Server did not send 'registration' as expected"
    
    username = "test_user6"
    email = "test_user6@example.com"
    password = "SecurePass123!"
    public_key = generate_rsa_key_pair(username)
    
    # Simulated registration data
    registration_data = {
        "username": username,
        "email": email,
        "password": password,
        "public_key": public_key,
    }
    client_socket.send(json.dumps(registration_data).encode())
    
    # Wait for the server to request OTP
    response = client_socket.recv(1024).decode()
    assert response == "Please enter OTP", "Server did not request OTP as expected"

    # Fetch OTP from the mock email server
    otp = get_otp_from_email()
    assert otp is not None, "OTP not found in email"

    # Simulate OTP expiration by waiting for the time limit to pass
    time.sleep(5)  # Assuming the OTP expires in 5 s in test environment
    time.sleep(2) # Wait for a second to ensure OTP is expired

    # Send OTP back to the server
    client_socket.send(otp.encode())
    
    # Verify the response indicates OTP expiration
    response = client_socket.recv(1024).decode()
    assert response == "Invalid OTP!", "Expected error for expired OTP"