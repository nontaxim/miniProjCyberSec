import pytest
import json
import time
import socket
from cryptography.hazmat.primitives.asymmetric import rsa
from e2e_test_utils import generate_rsa_key_pair, get_otp_from_email , signed_message , load_private_key , encrypt_message , register_user, decrypt_message , login_user

# ============================================
# Pytest Test Cases for E2E Send Message
# ============================================

# เป้าหมายของการทดสอบ
# ทดสอบว่าผู้ใช้สามารถส่งข้อความไปยังผู้รับได้สำเร็จ
# ทดสอบว่าผู้รับสามารถรับข้อความที่ถูกส่งมาได้
# ทดสอบกรณีที่ผู้รับไม่ออนไลน์
# ตรวจสอบว่าระบบปฏิเสธข้อความที่มีลายเซ็นไม่ถูกต้อง
# ตรวจสอบว่าระบบส่งข้อความไปยังกรณีที่ผู้รับ (recipient) ไม่ได้ลงทะเบียนในระบบ

pytestmark = [pytest.mark.send_received_message, pytest.mark.order(3)] 
def test_send_message_success(start_server):
    """Test that a message is successfully sent and received."""
    # Step 1: Register the Sender
    # Start the client1 socket
    client1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client1.connect(('localhost', 5555))
    # Sender registration
    username = "sender1"
    email = "sender1_user@example.com"
    password = "SecurePass123!"
    public_key = generate_rsa_key_pair(username)
    register_user(client1, username, email, password, public_key)

    # Step 2: Register the Recipient
    # Start the client2 socket
    client2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client2.connect(('localhost', 5555))
    # Recipient registration
    username = "recipient1"
    email = "recipient1_user@example.com"
    password = "SecurePass123!"
    public_key = generate_rsa_key_pair(username)
    register_user(client2, username, email, password, public_key)

    print("Sender and Recipient registered successfully.📝 ✅")
    
    # Step 3: Sender sends a message
    client1.send("send_message".encode())
    response = client1.recv(1024).decode()
    assert response == "message"
    
    username = "sender1"
    to_client = "recipient1"
    message = "This is a test message"
    sender_private_key = load_private_key(username)
    
    # request recipient's public key
    client1.send(to_client.encode())
    recipient_public_key = client1.recv(4096).decode()
    
    encrypted_message = encrypt_message(recipient_public_key, message)
    signature = signed_message(sender_private_key, encrypted_message)
    
    message_data = {
        'from_client': username,
        'to_client': to_client,
        'encrypted_message': encrypted_message,
        'signature': signature
    }
    
    client1.sendall(json.dumps(message_data).encode())

    # Verify recipient receives the message
    response = client1.recv(1024).decode()
    assert response == "Message forwarded!", "Message was not forwarded successfully"

def test_send_message_recipient_receives_message(start_server):
    """Test that the recipient successfully receives the message."""
    # Step 1: Register the Sender
    # Start the client1 socket
    client1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client1.connect(('localhost', 5555))
    # Sender registration
    username = "sender2"
    email = "sender2_user@example.com"
    password = "SecurePass123!"
    public_key = generate_rsa_key_pair(username)
    register_user(client1, username, email, password, public_key)

    # Step 2: Register the Recipient
    # Start the client2 socket
    client2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client2.connect(('localhost', 5555))
    # Recipient registration
    username = "recipient2"
    email = "recipient2_user@example.com"
    password = "SecurePass123!"
    public_key = generate_rsa_key_pair(username)
    register_user(client2, username, email, password, public_key)

    print("Sender and Recipient registered successfully.📝 ✅")

    # Step 3: Sender sends a message
    client1.send("send_message".encode())
    response = client1.recv(1024).decode()
    assert response == "message"
    
    username = "sender2"
    to_client = "recipient2"
    message = "This is a test message to recipient2"
    sender_private_key = load_private_key(username)
    
    # request recipient's public key
    client1.send(to_client.encode())
    recipient_public_key = client1.recv(4096).decode()
    
    encrypted_message = encrypt_message(recipient_public_key, message)
    signature = signed_message(sender_private_key, encrypted_message)
    
    message_data = {
        'from_client': username,
        'to_client': to_client,
        'encrypted_message': encrypted_message,
        'signature': signature
    }
    
    client1.sendall(json.dumps(message_data).encode())

    # Verify recipient receives the message
    response = client1.recv(1024).decode()
    assert response == "Message forwarded!", "Message was not forwarded successfully"

    # Step 4: Recipient receives the message
    response = client2.recv(4096).decode()
    print("Message received by recipient:", response)

    # Step 5: Decrypt the message
    recipient_private_key = load_private_key(to_client)
    decrypted_message = decrypt_message(recipient_private_key, encrypted_message)
    print("Decrypted message:", decrypted_message)
    assert decrypted_message == message, "Recipient did not receive the correct message"
  
  
def test_send_message_invalid_signature(start_server):
    """Test that the server rejects a message with an invalid signature."""
    # Step 1: Register the Sender
    # Start the client1 socket
    client1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client1.connect(('localhost', 5555))
    # Sender registration
    username = "sender4"
    email = "sender4_user@example.com"
    password = "SecurePass123!"
    public_key = generate_rsa_key_pair(username)
    register_user(client1, username, email, password, public_key)

    # Step 2: Register the Recipient
    # Start the client2 socket
    client2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client2.connect(('localhost', 5555))
    # Recipient registration
    username = "recipient4"
    email = "recipient4_user@example.com"
    password = "SecurePass123!"
    public_key = generate_rsa_key_pair(username)
    register_user(client2, username, email, password, public_key)

    print("Sender and Recipient registered successfully.📝 ✅")

    # Step 3: Sender sends a message with an invalid signature
    client1.send("send_message".encode())
    response = client1.recv(1024).decode()
    assert response == "message"
    
    username = "sender4"
    to_client = "recipient4"
    message = "This is a test message to recipient4"
    
    # Generate an invalid signature using a different private key
    invalid_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2022,
    )
    
    # request recipient's public key
    client1.send(to_client.encode())
    recipient_public_key = client1.recv(4096).decode()
    print("Recipient Public Key:", recipient_public_key)
    
    encrypted_message = encrypt_message(recipient_public_key, message)
    invalid_signature = signed_message(invalid_private_key, encrypted_message)
    
    message_data = {
        'from_client': username,
        'to_client': to_client,
        'encrypted_message': encrypted_message,
        'signature': invalid_signature # Use Invalid signature
    }
    
    client1.sendall(json.dumps(message_data).encode())

    # Verify server response
    response = client1.recv(1024).decode()
    assert response == "Invalid signature!", "Server did not reject invalid signature"    
    
    
def test_send_message_recipient_not_found(start_server):
    """Test that the server handles the case where the recipient is not found."""
    # Step 1: Register the Sender
    # Start the client1 socket
    client1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client1.connect(('localhost', 5555))
    # Sender registration
    username = "sender5"
    email = "sender5_user@example.com"
    password = "SecurePass123!"
    public_key = generate_rsa_key_pair(username)
    register_user(client1, username, email, password, public_key)

    # Step 2: Sender sends a message to a non-existent recipient
    client1.send("send_message".encode())
    response = client1.recv(1024).decode()
    assert response == "message"
    
    username = "sender5"
    to_client = "notfound" # Recipient not found
    message = "This is a test message"
    sender_private_key = load_private_key(username)
    
    # request recipient's public key
    client1.send(to_client.encode())
    recipient_public_key = client1.recv(4096).decode()
    print("Recipient Public Key:", recipient_public_key)
    
    assert recipient_public_key == "Recipient not found!", "Server did not handle non-existent recipient correctly"
        
    
def test_send_message_recipient_not_online(start_server):
    """Test that the server handles the case where the recipient is not online."""
    # Step 1: Register the Sender
    # Start the client1 socket
    client1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client1.connect(('localhost', 5555))
    # Sender registration
    username = "sender3"
    email = "sender3_user@example.com"
    password = "SecurePass123!"
    public_key = generate_rsa_key_pair(username)
    register_user(client1, username, email, password, public_key)

    # Step 2: Register the Recipient
    # Start the client2 socket
    client2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client2.connect(('localhost', 5555))
    # Recipient registration
    username = "offline_user"
    email = "offline_user@example.com"
    password = "SecurePass123!"
    public_key = generate_rsa_key_pair(username)
    register_user(client2, username, email, password, public_key)

    print("Sender and Recipient registered successfully.📝 ✅")
    
    # Step 3: Recipient logs out
    client2.send('exit'.encode())
    response = client2.recv(1024).decode()
    assert response == "Goodbye!", "Server did not handle exit option correctly"
    
    # Sender sends a message to a non-existent recipient
    # Step 4: Sender sends a message to a not online recipient
    client1.send("send_message".encode())
    response = client1.recv(1024).decode()
    assert response == "message"
    
    username = "sender3"
    to_client = "offline_user"
    message = "This is a test message"
    sender_private_key = load_private_key(username)
    
    # request recipient's public key
    client1.send(to_client.encode())
    recipient_public_key = client1.recv(4096).decode()
    print("Recipient Public Key:", recipient_public_key)
    
    encrypted_message = encrypt_message(recipient_public_key, message)
    signature = signed_message(sender_private_key, encrypted_message)
    
    message_data = {
        'from_client': username,
        'to_client': to_client,
        'encrypted_message': encrypted_message,
        'signature': signature
    }
    
    client1.sendall(json.dumps(message_data).encode())

    # Verify server response
    response = client1.recv(1024).decode()
    assert response == "Recipient not online!", "Server did not handle offline recipient correctly"
    