import json
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

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

def test_login_success(start_server, client_socket):
    """Test successful login"""
    # ลงทะเบียนผู้ใช้ก่อน
    client_socket.send("register".encode())
    registration_data = {
        "username": "test_user",
        "email": "test@example.com",
        "password": "SecurePass123!",
        "public_key": mocked_public_key
    }
    client_socket.send(json.dumps(registration_data).encode())
    
    # รอให้ server ขอ OTP
    response = client_socket.recv(1024).decode()
    assert response == "Please enter OTP"  # ตรวจสอบว่า server ขอ OTP

    # ส่ง OTP
    client_socket.send("123456".encode())
    response = client_socket.recv(1024).decode()
    assert response == "Registration successful!"  # ตรวจสอบว่า server ยืนยันการลงทะเบียนสำเร็จ
    
    # ทดสอบล็อกอิน
    client_socket.send("login".encode())
    client_socket.send("test_user".encode())
    
    # รอรับ challenge จาก server
    challenge = client_socket.recv(1024).decode()
    assert challenge != ""  # ตรวจสอบว่า server ส่ง challenge กลับมา

    # สร้างลายเซ็นที่ถูกต้อง
    signed_challenge = private_key.sign(
        challenge.encode(),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    client_socket.send(signed_challenge.hex().encode())  # ส่งลายเซ็น
    response = client_socket.recv(1024).decode()
    assert response == "valid signature!"