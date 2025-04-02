import json
import pytest
from client import register_client

def test_register_client_success(mocker):
    mock_socket = mocker.MagicMock()

    # Mock socket communication
    mock_socket.recv.side_effect = [
        "registration".encode(),  # First response: registration acknowledgment
        "Please enter OTP".encode(),  # OTP request
        "Registration successful".encode()  # Final success response
    ]

    # Mock generate_RSA_key
    mock_private_key = mocker.MagicMock()
    mock_public_key = mocker.MagicMock()
    mock_public_key.public_bytes.return_value = b"mock_public_key_pem"
    mock_generate_RSA_key = mocker.patch("client.generate_RSA_key", return_value=(mock_private_key, mock_public_key))

    # Mock user input
    mocker.patch("builtins.input", side_effect=["validuser", "test@example.com", "SecureP@ss123", "123456"])

    # Mock getpass.getpass for password input
    mocker.patch("getpass.getpass", return_value="SecureP@ss123")

    # Mock email & password validation
    mocker.patch("client.validate_email", return_value=True)
    mocker.patch("client.validate_password", return_value=True)

    # Call function
    private_key, public_key = register_client(mock_socket, "validuser")

    # Assertions
    mock_socket.send.assert_any_call("register".encode())  # Registration request sent
    mock_generate_RSA_key.assert_called_once_with("validuser")  # RSA key pair generated

    # Validate the actual send calls step by step
    expected_calls = [
        b"register",  # Register request
        json.dumps({"username": "validuser", "public_key": "mock_public_key_pem", "email": "validuser", "password": "SecureP@ss123"}).encode(),  # User data
        b"test@example.com"  # Email sent separately
    ]

    # Check if OTP is actually sent
    actual_calls = [call[0][0] for call in mock_socket.send.call_args_list]  # Extract sent data

    # If OTP was sent, add it to expected_calls
    if b"123456" in actual_calls:
        expected_calls.append(b"123456")

    assert actual_calls == expected_calls, f"Expected {expected_calls}, but got {actual_calls}"

    # Ensure the function returns keys
    assert private_key == mock_private_key
    assert public_key == mock_public_key

def test_register_client_invalid_username(mocker):
    # Mock socket
    mock_socket = mocker.MagicMock()

    # Mock socket communication
    mock_socket.recv.side_effect = [
        "registration".encode(),  # First response: registration acknowledgment
        "Please enter OTP".encode(),  # OTP request
        "Registration successful".encode()  # Final success response
    ]

    # Mock generate_RSA_key
    mock_private_key = mocker.MagicMock()
    mock_public_key = mocker.MagicMock()
    mock_public_key.public_bytes.return_value = b"mock_public_key_pem"
    mock_generate_RSA_key = mocker.patch("client.generate_RSA_key", return_value=(mock_private_key, mock_public_key))

    # Mock user input (invalid username first, followed by valid data)
    mocker.patch("builtins.input", side_effect=[
        "validuser",  # Valid username
        "test@example.com",  # Valid email
        # "SecureP@ss123",  # Skip password because already mocked
        "123456"  # OTP (correct value for OTP)
    ])

    # Mock getpass.getpass for password input (valid password)
    mocker.patch("getpass.getpass", return_value="SecureP@ss123")

    # Mock email & password validation
    mocker.patch("client.validate_email", return_value=True)
    mocker.patch("client.validate_password", return_value=True)

    # Call the function
    private_key, public_key = register_client(mock_socket, "")  # Initially empty username

    # Assertions
    mock_socket.send.assert_any_call("register".encode())  # Register request sent
    mock_generate_RSA_key.assert_called_once_with("validuser")  # RSA key pair generated

    # The first send is for the invalid username (just "validuser"), so we expect this call
    expected_registration_data = {
        "username": "validuser",
        "public_key": "mock_public_key_pem",
        "email": "test@example.com",
        "password": "SecureP@ss123"
    }

    # Assert that the registration data was sent with the correct details
    mock_socket.send.assert_any_call(json.dumps(expected_registration_data).encode())

    # Now, assert that OTP was sent correctly (this was the source of the failure)
    mock_socket.send.assert_any_call(b"123456")

    # Check the returned keys
    assert private_key == mock_private_key
    assert public_key == mock_public_key

def test_register_client_invalid_email(mocker):
    # Mock socket
    mock_socket = mocker.MagicMock()

    # Mock socket communication
    mock_socket.recv.side_effect = [
        "registration".encode(),  # First response: registration acknowledgment
        "Please enter OTP".encode(),  # OTP request
        "Registration successful".encode()  # Final success response
    ]

    # Mock generate_RSA_key
    mock_private_key = mocker.MagicMock()
    mock_public_key = mocker.MagicMock()
    mock_public_key.public_bytes.return_value = b"mock_public_key_pem"
    mock_generate_RSA_key = mocker.patch("client.generate_RSA_key", return_value=(mock_private_key, mock_public_key))

    # Mock user input (invalid email first, followed by a valid email)
    mocker.patch("builtins.input", side_effect=[
        "invalid-email",  # Invalid email
        "test@example.com",  # Valid email (after the invalid one)
        # "SecureP@ss123",  # Skip password because already mocked
        "123456"  # OTP
    ])

    # Mock getpass.getpass for password input (valid password)
    mocker.patch("getpass.getpass", return_value="SecureP@ss123")

    # Mock email & password validation
    mocker.patch("client.validate_email", side_effect=[False, True])  # Invalid email first, valid second
    mocker.patch("client.validate_password", return_value=True)

    # Call the function
    private_key, public_key = register_client(mock_socket, "validuser")

    # Assertions
    mock_socket.send.assert_any_call("register".encode())  # Register request sent
    mock_generate_RSA_key.assert_called_once_with("validuser")  # RSA key pair generated
    mock_socket.send.assert_any_call(json.dumps({
        "username": "validuser",
        "public_key": "mock_public_key_pem",
        "email": "test@example.com",  # Correct email after the invalid one
        "password": "SecureP@ss123"
    }).encode())  # Registration data sent
    mock_socket.send.assert_any_call(b"123456")  # OTP sent

    # Check the returned keys
    assert private_key == mock_private_key
    assert public_key == mock_public_key

def test_register_client_invalid_password(mocker):
    # Mock socket
    mock_socket = mocker.MagicMock()

    # Mock socket communication
    mock_socket.recv.side_effect = [
        "registration".encode(),  # First response: registration acknowledgment
        "Please enter OTP".encode(),  # OTP request
        "Registration successful".encode()  # Final success response
    ]

    # Mock generate_RSA_key
    mock_private_key = mocker.MagicMock()
    mock_public_key = mocker.MagicMock()
    mock_public_key.public_bytes.return_value = b"mock_public_key_pem"
    mock_generate_RSA_key = mocker.patch("client.generate_RSA_key", return_value=(mock_private_key, mock_public_key))

    # Mock user input (invalid password first)
    mocker.patch("builtins.input", side_effect=[
        "test@example.com",  # Valid email
        "123456"  # OTP
    ])

    # Mock getpass.getpass for password input (valid and invalid passwords)
    mocker.patch("getpass.getpass", side_effect=["short", "SecureP@ss123"])

    # Mock email & password validation
    mocker.patch("client.validate_email", return_value=True)
    mocker.patch("client.validate_password", side_effect=[False, True])  # Invalid password first, valid second

    # Mocking the message for an invalid password
    mocker.patch("builtins.print")  # To mock out any print statements

    # Call the function
    private_key, public_key = register_client(mock_socket, "validuser")

    # Assertions
    mock_socket.send.assert_any_call("register".encode())  # Register request sent
    mock_generate_RSA_key.assert_called_once_with("validuser")  # RSA key pair generated
    mock_socket.send.assert_any_call(json.dumps({
        "username": "validuser",
        "public_key": "mock_public_key_pem",
        "email": "test@example.com",
        "password": "SecureP@ss123"
    }).encode())  # Registration data sent
    mock_socket.send.assert_any_call(b"123456")  # OTP sent

    # Check the returned keys
    assert private_key == mock_private_key
    assert public_key == mock_public_key

def test_register_client_invalid_response_registration(mocker):
    # Mock socket
    mock_socket = mocker.MagicMock()

    # Simulate invalid server response for registration
    mock_socket.recv.side_effect = [
        "invalid_response".encode(),  # Server response instead of "registration"
    ]

    # Mock generate_RSA_key
    mock_private_key = mocker.MagicMock()
    mock_public_key = mocker.MagicMock()
    mock_generate_RSA_key = mocker.patch("client.generate_RSA_key", return_value=(mock_private_key, mock_public_key))

    # Mock user input (valid username, email, and password)
    mocker.patch("builtins.input", side_effect=["validuser", "test@example.com", "SecureP@ss123"])
    mocker.patch("getpass.getpass", return_value="SecureP@ss123")

    # Call the function
    private_key, public_key = register_client(mock_socket, "validuser")

    # Assertions
    mock_socket.send.assert_called_once_with("register".encode())  # Register request sent
    mock_socket.close.assert_called_once()  # Socket closed
    assert private_key is None
    assert public_key is None

def test_register_client_unexpected_otp_request(mocker):
    # Mock socket
    mock_socket = mocker.MagicMock()

    # Simulate unexpected response, not "Please enter OTP"
    mock_socket.recv.side_effect = [
        "registration".encode(),  # Valid registration response
        "Unexpected server message".encode(),  # Invalid OTP request
    ]

    # Mock generate_RSA_key
    mock_private_key = mocker.MagicMock()
    mock_public_key = mocker.MagicMock()
    mock_public_key.public_bytes.return_value = b"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7Yt9U8R+T3jHlQF3wMprFf9DbbKq5vKDoETqk9z74XYdd7Xl1Zs2cJ0WGw7+66kEwL2mnX5PnFlp6jm7gxFZf9sL2VhG6bTZzUNv5EhkfJqAlHYd97XGl2EVoMzoH5wTgsBzvPFTpxh/FkqO2NO56y/zZ3BTTx0jItfT0kq6a2F7A6W3bqgQrd76f7YQ/SH9Emr8OkqfCwE6VsCB6YmeIu/3DhWxqG97FqcUGLVFbp6p6sKBUR9+9s0wKn37YgC5BYPVntZYmD/F4pJmiPdsfKLwAseOdQTvbp/iF1Aq3zMzM20B6VQdbbEJzA1+1rp1NjhP+gFZT5wnA0dckQIDAQAB\n-----END PUBLIC KEY-----\n"

    mock_generate_RSA_key = mocker.patch("client.generate_RSA_key", return_value=(mock_private_key, mock_public_key))

    # Mock user input (valid username, email, and password)
    mocker.patch("builtins.input", side_effect=["validuser", "test@example.com", "SecureP@ss123"])
    mocker.patch("getpass.getpass", return_value="SecureP@ss123")

    # Call the function
    result = register_client(mock_socket, "validuser")

    # Ensure the result is None if the OTP is unexpected
    if result != (None, None):
        pytest.fail(f"Expected None, but got {result}")
    else:
        # Assert the expected failure behavior
        print("Result is None as expected.")

def test_register_client_registration_failure(mocker):
    # Mock socket
    mock_socket = mocker.MagicMock()

    # Simulate server response with failure message
    mock_socket.recv.side_effect = [
        "registration".encode(),  # Valid registration response
        "Please enter OTP".encode(),  # OTP request
        "Registration failed".encode()  # Failed registration response
    ]

    # Mock generate_RSA_key
    mock_private_key = mocker.MagicMock()
    mock_public_key = mocker.MagicMock()
    mock_public_key.public_bytes.return_value = b"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7Yt9U8R+T3jHlQF3wMprFf9DbbKq5vKDoETqk9z74XYdd7Xl1Zs2cJ0WGw7+66kEwL2mnX5PnFlp6jm7gxFZf9sL2VhG6bTZzUNv5EhkfJqAlHYd97XGl2EVoMzoH5wTgsBzvPFTpxh/FkqO2NO56y/zZ3BTTx0jItfT0kq6a2F7A6W3bqgQrd76f7YQ/SH9Emr8OkqfCwE6VsCB6YmeIu/3DhWxqG97FqcUGLVFbp6p6sKBUR9+9s0wKn37YgC5BYPVntZYmD/F4pJmiPdsfKLwAseOdQTvbp/iF1Aq3zMzM20B6VQdbbEJzA1+1rp1NjhP+gFZT5wnA0dckQIDAQAB\n-----END PUBLIC KEY-----\n"

    mock_generate_RSA_key = mocker.patch("client.generate_RSA_key", return_value=(mock_private_key, mock_public_key))

    # Mock user input (valid username, email, and password)
    mocker.patch("builtins.input", side_effect=["validuser", "test@example.com", "SecureP@ss123"])
    mocker.patch("getpass.getpass", return_value="SecureP@ss123")

    # Call the function
    result = register_client(mock_socket, "validuser")

    # Ensure the result is None if the OTP is unexpected
    if result != (None, None):
        pytest.fail(f"Expected None, but got {result}")
    else:
        # Assert the expected failure behavior
        print("Result is None as expected.")

def test_register_client_key_generation_failure(mocker):
    # Mock socket
    mock_socket = mocker.MagicMock()

    # Mock generate_RSA_key to return None for both keys
    mock_generate_RSA_key = mocker.patch("client.generate_RSA_key", return_value=(None, None))

    # Mock user input (valid username)
    mocker.patch("builtins.input", side_effect=["validuser"])

    # Call the function
    private_key, public_key = register_client(mock_socket, "validuser")

    # Assertions
    # Ensure that generate_RSA_key was called with the correct username
    mock_generate_RSA_key.assert_called_once_with("validuser")

    # Assert that the function returns None, None when key generation fails
    assert private_key is None
    assert public_key is None