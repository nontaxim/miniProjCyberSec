import pytest
from pytest_mock import MockerFixture
from my_server import handle_login
from cryptography.exceptions import InvalidSignature

# Mock socket for client communication
@pytest.fixture
def mock_socket(mocker: MockerFixture) -> None:
    """Mock socket for client communication."""
    mock = mocker.Mock()
    mock.recv.side_effect = [
        "test_user".encode(),  # Username as bytes
        "abcdef1234567890".encode(),  # Signed challenge as bytes
        "SecurePass123!".encode()  # Correct password as bytes
    ]
    return mock

# Mock the clients dictionary with user data (for registered user)
@pytest.fixture
def mock_clients(mocker: MockerFixture) -> None:
    """Mock the clients dictionary with user data."""
    fake_clients = {
        "test_user": {
            "password": "SecurePass123!",
            "public_key": "mocked_public_key"  # Just a placeholder since we're mocking verify
        }
    }
    mocker.patch("my_server.clients", fake_clients)

# Mock the clients dictionary with no registered user (for unregistered user scenario)
@pytest.fixture
def mock_clients_no_user(mocker: MockerFixture) -> None:
    """Mock the clients dictionary with no registered users."""
    fake_clients = {}  # Empty dictionary, no users
    mocker.patch("my_server.clients", fake_clients)

# Mock the clients dictionary with invalid password (for invalid password scenario)
@pytest.fixture
def mock_clients_invalid_password(mocker: MockerFixture) -> None:
    """Mock the clients dictionary with invalid password."""
    fake_clients = {
        "test_user": {
            "password": "some_password",
            "public_key": "mocked_public_key"  # Just a placeholder since we're mocking verify
        }
    }
    mocker.patch("my_server.clients", fake_clients)

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

# -----------------------------------------------------------------------------------------------

# Test the handle_login function when the client is registered
def test_handle_login(mock_socket: MockerFixture, mock_clients: None, mock_generate_challenge: None, mock_verify_signature: None) -> None:
    """Test user login using pytest."""
    handle_login(mock_socket)

    # Verify the expected response was sent through the socket
    mock_socket.send.assert_called_with(b"Login successful!")  # Verify expected response

# Test the handle_login function when the client is not registered
def test_client_not_registered(mock_socket: MockerFixture, mock_clients_no_user: None, mock_generate_challenge: None, mock_verify_signature: None) -> None:
    """Test login when the client is not registered."""
    handle_login(mock_socket)

    # Verify the server sends the "Client not registered!" message
    mock_socket.send.assert_called_with(b"Client not registered!")
    mock_socket.close.assert_called_once()  # Ensure the connection is closed

# Test the handle_login function when the client enters invalid password
def test_client_invalid_password(mock_socket: MockerFixture, mock_clients_invalid_password: None, mock_generate_challenge: None, mock_verify_signature: None) -> None:
    """Test login when the client enters an invalid password."""
    handle_login(mock_socket)

    # Verify the server sends the "Invalid password!" message
    mock_socket.send.assert_called_with(b"Invalid password!")
    mock_socket.close.assert_called_once()  # Ensure the connection is closed

# Test the handle_login function with an invalid signature
def test_handle_login_invalid_signature(mock_socket: MockerFixture, mock_clients: None, 
                                         mock_generate_challenge: None, mock_invalid_verify_signature: None) -> None:
    """Test login with invalid signature."""
    handle_login(mock_socket)

    # Verify the server sends the "Invalid signature!" message
    mock_socket.send.assert_called_with(b"Invalid signature!")
    mock_socket.close.assert_called_once()  # Ensure the connection is closed
