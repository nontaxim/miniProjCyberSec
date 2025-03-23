import json

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# สร้าง public/private key mock
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
public_key = private_key.public_key()

# แปลง public key เป็น PEM format
mocked_public_key = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode('utf-8')

def test_registration_success(start_server, client_socket):
    """Test successful registration."""
    client_socket.send("register".encode())
    username = "test_user"
    email = "test@example.com"
    password = "SecurePass123!"
    
    # ส่งข้อมูลการลงทะเบียน
    registration_data = {
        "username": username,
        "email": email,
        "password": password,
        "public_key": mocked_public_key
    }
    client_socket.send(json.dumps(registration_data).encode())
    
    # รอให้ server ตอบกลับก่อนส่ง OTP
    response = client_socket.recv(1024).decode()
    assert response == "Please enter OTP"  # ตรวจสอบว่า server ขอ OTP

    # ส่ง OTP
    otp = "123456"
    client_socket.send(otp.encode())
    
    # ตรวจสอบ response
    response = client_socket.recv(1024).decode()
    assert response == "Registration successful!"