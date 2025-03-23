import pytest
import subprocess
import time
import socket
import os
import signal


@pytest.fixture(scope="session", autouse=True)
def start_server():
    """Start the server in a subprocess for the entire test session."""
    print("Starting server...")
    server_process = subprocess.Popen(
        ["python3", "server/my_server.py"],
        stdout=None,  # แสดง stdout ในเทอร์มินัลโดยตรง
        stderr=None,  # แสดง stderr ในเทอร์มินัลโดยตรง
    )
    time.sleep(2)  # Wait for the server to start

    # ตรวจสอบว่า server เริ่มต้นได้สำเร็จหรือไม่
    if server_process.poll() is not None:
        print("Server failed to start.")
        raise RuntimeError("Failed to start server")

    print("Server started successfully.")
    yield
    print("Stopping server...")
    os.kill(server_process.pid, signal.SIGTERM)
    print("Server stopped.")

@pytest.fixture
def client_socket():
    """Create a client socket connection."""
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('localhost', 5555))
    try:
        yield client
    finally:
        client.send("exit".encode())  # แจ้ง server ให้ปิดการเชื่อมต่อ
        client.close()