import pytest
import subprocess
import time
import socket
import os
import signal
import sqlite3
import requests
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

@pytest.fixture(scope="session", autouse=True)
def set_test_mode():
    """Set APP_MODE to 'test' for all tests."""
    os.environ["APP_MODE"] = "e2e_test"
    print(f"APP_MODE set to: {os.environ['APP_MODE']}") 
    
@pytest.fixture(scope="module", autouse=True)
def reset_database():
    """Reset the database before each test module."""
    db_path = os.path.join("e2e_tests", "test_user_data.db")  # ใช้ฐานข้อมูลสำหรับการทดสอบ
    if os.path.exists(db_path):
        print("Resetting database for module...")
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            # Delete all data in the users table
            cursor.execute("DELETE FROM users")
            conn.commit()
        print("Database reset completed for module.")
    else:
        print(f"Database file '{db_path}' does not exist. Skipping reset.")
        
@pytest.fixture(scope="session", autouse=True)
def cleanup_database():
    """Remove the test database file after all tests are completed."""
    yield  # รอให้การทดสอบทั้งหมดเสร็จสิ้น
    db_path = os.path.join("e2e_tests", "test_user_data.db")  # ใช้ฐานข้อมูลสำหรับการทดสอบ
    if os.path.exists(db_path):
        print(f"Removing database file '{db_path}'...")
        os.remove(db_path)
        print("Database file removed.")
    else:
        print(f"Database file '{db_path}' does not exist. No cleanup needed.")
       
        
@pytest.fixture(scope="module", autouse=True)
def cleanup_pem_files():
    """Remove all .pem files in the temp_keys folder after the module is completed."""
    yield
    temp_keys_folder = os.path.join("e2e_tests", "temp_keys")
    for file in os.listdir(temp_keys_folder):
        if file.endswith(".pem"):
            os.remove(os.path.join(temp_keys_folder, file))
    print("Removed all .pem files in the temp_keys folder.")
            
@pytest.fixture(scope="function")
def start_server():
    """Start the server in a subprocess for each test case."""
    print("Starting server...")
    server_process = subprocess.Popen(
        ["python3", "server/my_server.py"],
        stdout=None,  # Show stdout directly in the terminal
        stderr=None,  # Show stderr directly in the terminal
    )
    # Check if the server is ready
    max_retries = 15  # Maximum number of retries
    retry_interval = 0.5  # Wait time between retries (seconds)
    for _ in range(max_retries):
        try:
            # Attempt to connect to the server
            with socket.create_connection(('localhost', 5555), timeout=1):
                print("Server started successfully.🌐 ✅")
                break
        except (ConnectionRefusedError, OSError):
            time.sleep(retry_interval)
    else:
        # If the server is not ready after multiple attempts
        print("Server failed to start.❌")
        server_process.terminate()
        raise RuntimeError("Failed to start server")

    try:
        yield server_process
    finally:
        print("Stopping server...")
        server_process.terminate()
        server_process.wait()
        print("Server stopped.")
    

@pytest.fixture(scope="function")
def client_socket():
    """Create a client socket connection for each test case."""
    if not hasattr(client_socket, "_client_count"):
        client_socket._client_count = 0  # Initialize client count
    client_socket._client_count += 1  # Increment client count

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('localhost', 5555))
    print(f"Client{client_socket._client_count} connected to server.🤖 ✅")
    try:
        yield client
    finally:
        print(f"Client{client_socket._client_count} disconnecting from server.🔌 ❌")
        try:
            client.send("exit".encode())  # Notify server to close the connection
        except BrokenPipeError:
            print("BrokenPipeError: Unable to send 'exit' as the connection is already closed.")
        finally:
            client.close()
        
        
def generate_rsa_key_pair(username):
    """Generate an RSA key pair and save the private and public keys in the e2e_test2 folder."""
    # สร้าง Private Key และ Public Key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    # สร้างโฟลเดอร์ e2e_test2 หากยังไม่มี
    key_folder = os.path.join("e2e_tests", "temp_keys")
    os.makedirs(key_folder, exist_ok=True)
    
    # บันทึก Private Key ลงในไฟล์ .pem
    private_key_path = os.path.join(key_folder, f"{username}_private_key.pem")
    with open(private_key_path, "wb") as private_key_file:
        private_key_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # บันทึก Public Key ลงในไฟล์ .pem
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