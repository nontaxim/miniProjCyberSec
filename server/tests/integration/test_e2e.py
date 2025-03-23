import os
import subprocess
import socket
import time
import pytest
import json

SERVER_HOST = "localhost"
SERVER_PORT = 5555

@pytest.fixture(scope="module")
def start_server():
    """
    Start the server in a separate thread for testing.
    """
    server_script = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../my_server.py"))
    
    server_process = subprocess.Popen(
        ["python3", server_script],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    time.sleep(2)  # Wait for the server to start
    if server_process.poll() is not None:
        # Server process exited prematurely, print stderr for debugging
        stderr = server_process.stderr.read().decode()
        print(f"Server failed to start:\n{stderr}")
        pytest.fail("Server failed to start")
    yield
    server_process.terminate()
    server_process.wait()

def test_e2e_register_and_login(start_server):
    """
    Test E2E flow for client registration and login.
    """
    # Simulate client registration
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((SERVER_HOST, SERVER_PORT))

    # Register a new user
    client_socket.send("register".encode())
    time.sleep(1)
    registration_data = {
        "username": "test_user",
        "email": "test@example.com",
        "password": "SecurePass123!",
        "public_key": "mocked_public_key"
    }
    client_socket.send(json.dumps(registration_data).encode())
    otp = "123456"  # Mock OTP
    client_socket.send(otp.encode())
    response = client_socket.recv(1024).decode()
    assert response == "Registration successful!"

    # Login with the same user
    client_socket.send("login".encode())
    time.sleep(1)
    client_socket.send("test_user".encode())
    challenge = client_socket.recv(1024).decode()
    signed_challenge = "mocked_signed_challenge"  # Mock signed challenge
    client_socket.send(signed_challenge.encode())
    client_socket.send("SecurePass123!".encode())
    response = client_socket.recv(1024).decode()
    assert response == "Login successful!"

    client_socket.close()