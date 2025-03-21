import pytest
import json
from pytest_mock import MockerFixture
from unittest.mock import MagicMock
from my_server import handle_registration, client_otp, clients
from typing import Generator

@pytest.fixture
def mock_socket(mocker: MockerFixture) -> MagicMock:
    """Mock socket for client communication."""
    mock = mocker.MagicMock()
    mock.recv.side_effect = [
        json.dumps({
            "username": "test_user",
            "email": "test@example.com",
            "password": "SecurePass123!",
            "public_key": "some_public_key"
        }).encode(),
        "123456".encode()  # OTP input
    ]
    return mock

@pytest.fixture
def mock_generate_otp(mocker: MockerFixture) -> None:
    """Mock the generate_otp function."""
    mocker.patch("my_server.generate_otp", return_value="123456")

@pytest.fixture
def mock_send_email(mocker: MockerFixture) -> MagicMock:
    """Mock the send_otp_email function."""
    mock = mocker.MagicMock()
    mocker.patch("my_server.send_otp_email", mock)
    return mock

@pytest.fixture
def setup_otp() -> None:
    """Pre-set OTP for test_user."""
    client_otp["test_user"] = "123456"

@pytest.fixture
def clear_clients() -> Generator[None, None, None]:
    """Ensure clients dictionary is reset before and after test."""
    clients.clear()
    yield
    clients.clear()

def test_handle_registration(mock_socket: MagicMock, mock_generate_otp: None, 
                             mock_send_email: MagicMock, setup_otp: None, 
                             clear_clients: None) -> None:
    """Test user registration using pytest."""
    handle_registration(mock_socket)

    # Assertions
    mock_send_email.assert_called_once()  # Check if email was sent
    mock_socket.send.assert_called_with(b"Registration successful!")  # Check success response
    assert "test_user" in clients  # Check if user was registered
