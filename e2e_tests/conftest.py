import pytest
import subprocess
import time
import socket
import os
import signal
import sqlite3

@pytest.fixture(scope="session", autouse=True)
def set_test_mode():
    """Set APP_MODE to 'test' for all tests."""
    os.environ["APP_MODE"] = "e2e_test"
    print(f"APP_MODE set to: {os.environ['APP_MODE']}") 
    
@pytest.fixture(scope="module", autouse=True)
def reset_database():
    """Reset the database before each test module."""
    db_path = os.path.join("e2e_tests", "test_user_data.db")  # Use a test database
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
    yield  # Wait for all tests to complete
    db_path = os.path.join("e2e_tests", "test_user_data.db")  # Use a test database
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
    if os.path.exists(temp_keys_folder):
        for file in os.listdir(temp_keys_folder):
            if file.endswith(".pem"):
                os.remove(os.path.join(temp_keys_folder, file))
        print("Removed all .pem files in the temp_keys folder.")
    else:
        print(f"Directory '{temp_keys_folder}' does not exist. Skipping cleanup.")
        
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
    max_retries = 20  # Maximum number of retries
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