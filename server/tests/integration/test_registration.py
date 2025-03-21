import pytest
import json
from pytest_mock import MockerFixture
from unittest.mock import MagicMock
from my_server import handle_registration, client_otp, clients
from typing import Generator

# Fixture to mock socket for client communication with valid OTP
@pytest.fixture
def mock_socket_valid_otp(mocker: MockerFixture) -> MagicMock:
    """Mock socket for client communication with valid OTP."""
    mock = mocker.MagicMock()
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
def mock_socket_invalid_otp(mocker: MockerFixture) -> MagicMock:
    """Mock socket for client communication with invalid OTP."""
    mock = mocker.MagicMock()
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
def mock_send_email(mocker: MockerFixture) -> MagicMock:
    """Mock the send_otp_email function."""
    mock = mocker.MagicMock()
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

# Test valid OTP registration
def test_handle_registration_valid_otp(mock_socket_valid_otp: MagicMock, mock_generate_otp: None, 
                                        mock_send_email: MagicMock, setup_otp: None, 
                                        clear_clients: None) -> None:
    """Test user registration with valid OTP."""
    
    # Call the registration function
    handle_registration(mock_socket_valid_otp)

    # Assertions
    mock_send_email.assert_called_once()  # Check if email was sent
    mock_socket_valid_otp.send.assert_called_with(b"Registration successful!")  # Check success response
    assert "test_user" in clients  # Check if user was registered

# Test invalid OTP registration
def test_handle_registration_invalid_otp(mock_socket_invalid_otp: MagicMock, mock_generate_otp: None, 
                                          mock_send_email: MagicMock, setup_otp: None, 
                                          clear_clients: None) -> None:
    """Test user registration with invalid OTP."""
    
    # Call the registration function
    handle_registration(mock_socket_invalid_otp)

    # Assertions
    mock_send_email.assert_called_once()  # Check if email was sent
    mock_socket_invalid_otp.send.assert_called_with(b"Invalid OTP!")  # Check invalid OTP response
    assert "test_user" not in clients  # Ensure user was not registered
