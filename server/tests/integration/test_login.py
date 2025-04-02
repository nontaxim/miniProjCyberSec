import sqlite3
import time
from unittest.mock import patch
import pytest
from pytest_mock import MockerFixture
from my_server import handle_login
from cryptography.exceptions import InvalidSignature
from argon2 import PasswordHasher

# Fixture to create an in-memory SQLite database
@pytest.fixture
def test_db(mocker: MockerFixture):
    """Fixture to create an in-memory SQLite database for testing."""
    conn = sqlite3.connect(":memory:")  # Use an in-memory database
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            public_key TEXT NOT NULL
        )
    """)
    conn.commit()

    # Patch sqlite3.connect to return this test database
    mocker.patch("sqlite3.connect", return_value=conn)

    yield conn  # Provide the connection to the test

    conn.close()  # Cleanup after the test

@pytest.fixture
def populate_db(test_db):
    """Inserts a test user into the in-memory SQLite database for login tests."""
    cursor = test_db.cursor()

    cursor.execute("""
        INSERT INTO users (username, password, public_key, email)
        VALUES (?, ?, ?, ?)
    """, ("test_user", "SecurePass123!", "mocked_public_key", "test@example.com"))

    test_db.commit()  # Ensure changes are committed to the in-memory database

@pytest.fixture
def mock_hash(mocker: MockerFixture) -> None:
    """Mock the hash function to return the same password as the input received."""
    def side_effect(password: str, salt: str) -> str:
        return password  # Return the password as-is, ignoring the salt
    
    # Patch the hash_password function to use the side effect
    mocker.patch("my_server.hash_password", side_effect=side_effect)

# Mock socket for client communication
@pytest.fixture
def mock_socket(mocker: MockerFixture) -> None:
    """Mock socket for client communication."""
    mock = mocker.Mock()
    mock.recv.side_effect = [
        "test_user".encode(),  # First call: Username as bytes
        "abcdef1234567890".encode(),  # Second call: Signed challenge as bytes
        "SecurePass123!".encode()  # Third call: Password as bytes
    ]
    return mock

# Mock socket for client communication
@pytest.fixture
def mock_invalid_password_socket(mocker: MockerFixture) -> None:
    """Mock socket for client communication in invalid password."""
    mock = mocker.Mock()
    mock.recv.side_effect = [
        "test_user".encode(),  # First call: Username as bytes
        "abcdef1234567890".encode(),  # Second call: Signed challenge as bytes
        "SomewrongPass".encode()  # Third call: Password as bytes
    ]
    return mock

# Mock the generate_challenge function
@pytest.fixture
def mock_generate_challenge(mocker: MockerFixture) -> None:
    """Mock the generate_challenge function."""
    mocker.patch("my_server.generate_challenge", return_value="mocked_challenge")

# Mock the public_key.verify method to always succeed (i.e., no exception)
@pytest.fixture
def mock_verify_signature(mocker: MockerFixture) -> None:
    """Mock the verify method to always succeed."""
    # Mock the public_key and its verify method to always return None (success)
    mock_public_key = mocker.Mock()
    mock_public_key.verify.return_value = None  # Always succeeds, no exception
    # Mock the method used in the handle_login function to return the mocked public key
    mocker.patch("cryptography.hazmat.primitives.serialization.load_pem_public_key", return_value=mock_public_key)

# Mock the public_key.verify method to raise an exception (simulate invalid signature)
@pytest.fixture
def mock_invalid_verify_signature(mocker: MockerFixture) -> None:
    """Mock the verify method to raise InvalidSignature (invalid signature)."""
    mock_public_key = mocker.Mock()
    mock_public_key.verify.side_effect = InvalidSignature()  # Simulate invalid signature exception
    mocker.patch("cryptography.hazmat.primitives.serialization.load_pem_public_key", return_value=mock_public_key)

@pytest.fixture
def mock_argon2_verify_true(mocker):
    """Mock the argon2 hasher verify method to always return True."""
    return mocker.patch.object(PasswordHasher, 'verify', return_value=True)

# -----------------------------------------------------------------------------------------------

# Test the handle_login function when the client is registered
def test_handle_login(mock_socket: MockerFixture, test_db, populate_db: None, mock_hash, mock_generate_challenge: None, mock_verify_signature: None, mock_argon2_verify_true) -> None:
    """Test user login using pytest with an in-memory database."""
    handle_login(mock_socket)

    # Verify the expected response was sent through the socket
    mock_socket.send.assert_called_with(b"Login successful!")  # Verify expected response

# Test the handle_login function when the client is not registered
def test_client_not_registered(mock_socket: MockerFixture, test_db, mock_hash, mock_generate_challenge: None, mock_verify_signature: None) -> None:
    """Test login when the client is not registered."""
    handle_login(mock_socket)

    # Verify the server sends the "Client not registered!" message
    mock_socket.send.assert_called_with(b"Client not registered!")
    mock_socket.close.assert_called_once()  # Ensure the connection is closed

# Test case to verify handling of invalid password
def test_client_invalid_password(mock_invalid_password_socket: MockerFixture, test_db, populate_db: None, mock_generate_challenge: None, mock_verify_signature: None) -> None:
    """Test login when the client enters an invalid password."""
    handle_login(mock_invalid_password_socket)

    # Verify the server sends the "Wrong password!" message
    mock_invalid_password_socket.send.assert_called_with(b"Wrong password!")
    
# Test the handle_login function with an invalid signature
def test_handle_login_invalid_signature(mock_socket: MockerFixture, test_db, populate_db: None, mock_generate_challenge: None, mock_invalid_verify_signature: None) -> None:
    """Test login with invalid signature."""
    handle_login(mock_socket)

    # Verify the server sends the "Invalid signature!" message
    mock_socket.send.assert_called_with(b"Invalid signature!")
    mock_socket.close.assert_called_once()  # Ensure the connection is closed
