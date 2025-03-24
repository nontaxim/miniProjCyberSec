import sqlite3
import pytest
import json
from pytest_mock import MockerFixture
from my_server import handle_registration, client_otp, clients
from typing import Generator

# Fixture to mock socket for client communication with valid OTP
@pytest.fixture
def mock_socket_valid_otp(mocker: MockerFixture) -> None:
    """Mock socket for client communication with valid OTP."""
    mock = mocker.Mock()
    mock.recv.side_effect = [
        json.dumps({
            "username": "test_user",
            "email": "test@example.com",
            "password": "SecurePass123!",
            "public_key": "some_public_key"
        }).encode(),
        "123456".encode()  # Valid OTP input
    ]
    return mock

# Fixture to mock socket for client communication with invalid OTP
@pytest.fixture
def mock_socket_invalid_otp(mocker: MockerFixture) -> None:
    """Mock socket for client communication with invalid OTP."""
    mock = mocker.Mock()
    mock.recv.side_effect = [
        json.dumps({
            "username": "test_user",
            "email": "test@example.com",
            "password": "SecurePass123!",
            "public_key": "some_public_key"
        }).encode(),
        "654321".encode()  # Invalid OTP input
    ]
    return mock

# Fixture to mock the generate_otp function
@pytest.fixture
def mock_generate_otp(mocker: MockerFixture) -> None:
    """Mock the generate_otp function."""
    mocker.patch("my_server.generate_otp", return_value="123456")

# Fixture to mock the send_otp_email function
@pytest.fixture
def mock_send_email(mocker: MockerFixture) -> None:
    """Mock the send_otp_email function."""
    mock = mocker.Mock()
    mocker.patch("my_server.send_otp_email", mock)
    return mock

# Fixture to pre-set OTP for test_user
@pytest.fixture
def setup_otp() -> None:
    """Pre-set OTP for test_user."""
    client_otp["test_user"] = "123456"

# Fixture to clear the clients dictionary before and after test
@pytest.fixture
def clear_clients() -> Generator[None, None, None]:
    """Ensure clients dictionary is reset before and after test."""
    clients.clear()
    yield
    clients.clear()

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

# Test valid OTP registration
def test_handle_registration_valid_otp(
    mock_socket_valid_otp: object,
    test_db: sqlite3.Connection,
    mock_generate_otp: None,
    mock_send_email: None,
    setup_otp: None
) -> None:
    """Test user registration with an actual in-memory SQLite database."""
    
    handle_registration(mock_socket_valid_otp)  # Now it will use test_db

    # Validate the user exists in the database
    cursor: sqlite3.Cursor = test_db.cursor()
    cursor.execute("SELECT username FROM users WHERE username = ?", ("test_user",))
    result: tuple[str] | None = cursor.fetchone()

    assert result is not None, "User test_user was not found in the database."
    assert result[0] == "test_user", "Username does not match expected value."

# Test invalid OTP registration
def test_handle_registration_invalid_otp(mock_socket_invalid_otp: None, mock_generate_otp: None, 
                                          mock_send_email: None, setup_otp: None, 
                                          clear_clients: None) -> None:
    """Test user registration with invalid OTP."""
    
    # Call the registration function
    handle_registration(mock_socket_invalid_otp)

    # Assertions
    mock_send_email.assert_called_once()  # Check if email was sent
    mock_socket_invalid_otp.send.assert_called_with(b"Invalid OTP!")  # Check invalid OTP response
    assert "test_user" not in clients  # Ensure user was not registered

# Test invalid username (empty username)
def test_handle_registration_invalid_username(mock_socket_invalid_otp: object, mock_generate_otp: None,
                                              mock_send_email: None) -> None:
    """Test user registration with an empty username."""

    # Mock the socket's recv to simulate an empty username
    mock_socket_invalid_otp.recv.side_effect = [
        json.dumps({
            "username": "",  # Empty username
            "email": "test@example.com",
            "password": "SecurePass123!",
            "public_key": "some_public_key"
        }).encode(),
        "123456".encode()  # Valid OTP input
    ]

    # Call the registration function
    handle_registration(mock_socket_invalid_otp)

    # Check if the error message for invalid username was sent
    mock_socket_invalid_otp.send.assert_called_with(b"Invalid username! Username cannot be empty.")

# Test invalid email format
def test_handle_registration_invalid_email(mock_socket_invalid_otp: object, mock_generate_otp: None,
                                           mock_send_email: None) -> None:
    """Test user registration with an invalid email format."""

    # Mock the socket's recv to simulate an invalid email
    mock_socket_invalid_otp.recv.side_effect = [
        json.dumps({
            "username": "test_user",
            "email": "invalid-email",  # Invalid email format
            "password": "SecurePass123!",
            "public_key": "some_public_key"
        }).encode(),
        "123456".encode()  # Valid OTP input
    ]

    # Call the registration function
    handle_registration(mock_socket_invalid_otp)

    # Check if the error message for invalid email was sent
    mock_socket_invalid_otp.send.assert_called_with(b"Invalid email format!")

# Test invalid password format
def test_handle_registration_invalid_password(mock_socket_invalid_otp: object, mock_generate_otp: None,
                                              mock_send_email: None) -> None:
    """Test user registration with an invalid password."""

    # Mock the socket's recv to simulate an invalid password
    mock_socket_invalid_otp.recv.side_effect = [
        json.dumps({
            "username": "test_user",
            "email": "test@example.com",
            "password": "weakpass",  # Invalid password (e.g., too weak)
            "public_key": "some_public_key"
        }).encode(),
        "123456".encode()  # Valid OTP input
    ]

    # Call the registration function
    handle_registration(mock_socket_invalid_otp)

    # Check if the error message for invalid password was sent
    mock_socket_invalid_otp.send.assert_called_with(b"Invalid password! Please enter a stronger password.")
