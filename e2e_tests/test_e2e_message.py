import json
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# สร้าง public/private key mock
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
public_key = private_key.public_key()
mocked_public_key = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode('utf-8')



def test_send_message_success(start_server, client_socket):
    """Test successful message sending."""
    # ลงทะเบียนผู้ส่ง
    client_socket.send("register".encode())
    registration_data = {
        "username": "test_user",
        "email": "test@example.com",
        "password": "SecurePass123!",
        "public_key": mocked_public_key
    }
    client_socket.send(json.dumps(registration_data).encode())
    response = client_socket.recv(1024).decode()
    assert response == "Please enter OTP"
    client_socket.send("123456".encode())
    response = client_socket.recv(1024).decode()
    assert response == "Registration successful!"
    
    # ลงทะเบียนผู้รับ
    client_socket.send("register".encode())
    registration_data = {
        "username": "recipient_user",
        "email": "recipient@example.com",
        "password": "RecipientPass123!",
        "public_key": mocked_public_key
    }
    client_socket.send(json.dumps(registration_data).encode())
    response = client_socket.recv(1024).decode()
    assert response == "Please enter OTP"
    client_socket.send("123456".encode())
    response = client_socket.recv(1024).decode()
    assert response == "Registration successful!"
    
    # ทดสอบส่งข้อความ
    client_socket.send("send_message".encode())
    message_data = {
        "from_client": "test_user",
        "to_client": "recipient_user",
        "encrypted_message": "mocked_encrypted_message",
        "signature": "mocked_signature"
    }
    client_socket.send(json.dumps(message_data).encode())
    response = client_socket.recv(1024).decode()
    assert response == "Message received!"