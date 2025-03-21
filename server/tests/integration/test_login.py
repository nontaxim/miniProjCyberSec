import pytest
from pytest_mock import MockerFixture
from unittest.mock import MagicMock
from my_server import handle_login

# Mock socket for client communication
@pytest.fixture
def mock_socket() -> MagicMock:
    """Mock socket for client communication."""
    mock = MagicMock()
    mock.recv.side_effect = [
        "test_user".encode(),  # Username
        "mocked_signed_challenge".encode(),  # Signed challenge
        "SecurePass123!".encode()  # Correct password
    ]
    return mock

# Mock the clients dictionary with user data
@pytest.fixture
def mock_clients(mocker: MockerFixture) -> None:
    """Mock the clients dictionary with user data."""
    fake_clients = {
        "test_user": {
            "password": "SecurePass123!",
            "public_key": "-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsKoqar6k/jIK02MtSysnsqDDmtGwyGAH6NGoC75ucnn4915NJRPTWpa94uk9VqQR+IclY/BJ00LIpxggkG0svBJG9HXIzxQuwZvEGC3pZls1QIA7ai0AnDGGO1fANKJii/Ue6r7fUyPPiPMq8SBB7tYTQmrsY8H3YpfxwKgBpTLLhC9zkBfE/+YtzWqedW0RdGJtxkz0OtS+l47I9nl8xibAgT/0FMc83h6a6tT8FPJZASP9XX53fTj5EMza2Ava71chUBujkEoGz9A8R9NrkcHzW8r8S4Ohus8RZkfoxxnDpbJ9HA2ZOxuuZwb09vbZhei+OpVeSJA5sSHMX8J49wIDAQAB-----END PUBLIC KEY-----"
        }
    }
    mocker.patch("my_server.clients", fake_clients)

# Mock the generate_challenge function
@pytest.fixture
def mock_generate_challenge(mocker: MockerFixture) -> None:
    """Mock the generate_challenge function."""
    mocker.patch("my_server.generate_challenge", return_value="mocked_challenge")

# Test the handle_login function
def test_handle_login(mock_socket: MagicMock, mock_clients: None, mock_generate_challenge: None) -> None:
    """Test user login using pytest."""
    handle_login(mock_socket)

    # Verify the expected response was sent through the socket
    mock_socket.send.assert_called_with(b"Login successful!")  # Verify expected response
