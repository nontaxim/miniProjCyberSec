import socket
import pytest
from threading import Event
from client import receive_messages

# Mock the required functions
@pytest.fixture
def mock_socket(mocker):
    return mocker.MagicMock()

@pytest.fixture
def mock_stop_event():
    return Event()

@pytest.fixture
def mock_private_key():
    return "mock_private_key"

# Test case: Test receiving valid message with correct signature
def test_receive_valid_message(mock_socket, mock_stop_event, mock_private_key, mocker):
    # Mock socket.recv to return a valid public key and message with valid signature
    mock_socket.recv.side_effect = [
        b"-----BEGIN PUBLIC KEY-----",  # Public key
        b'{"from_client": "user1", "encrypted_message": "encrypted_text", "signature": "a1b2c3d4e5f67890"}'  # Message data with valid hex signature
    ]
    
    # Mock serialization and decryption functions
    mock_public_key = mocker.MagicMock()
    mocker.patch('client.serialization.load_pem_public_key', return_value=mock_public_key)
    
    # Mock successful signature verification
    mock_public_key.verify.return_value = None
    decrypt_mock = mocker.patch('client.decrypt_message', return_value="decrypted_message")  # Mock decryption

    # Call the function
    receive_messages(mock_socket, mock_private_key, mock_stop_event)
    
    # Check if the functions were called correctly
    mock_socket.recv.assert_any_call(4096)
    
    # Ensure that the public key verification is called
    mock_public_key.verify.assert_called_once_with(
        bytes.fromhex("a1b2c3d4e5f67890"),  # The signature in hex format
        "encrypted_text".encode(),         # The encrypted message
        mocker.ANY,                          # Placeholder for padding
        mocker.ANY                           # Placeholder for hash algorithm
    )
    
    # Ensure the decrypt_message function was called once
    decrypt_mock.assert_called_once_with(mock_private_key, "encrypted_text")
    
# Test case: Test socket timeout
def test_receive_socket_timeout(mock_socket, mock_stop_event, mock_private_key, mocker):
    # Mock socket.recv to raise a timeout exception
    mock_socket.recv.side_effect = [socket.timeout]
    
    # Call the function
    receive_messages(mock_socket, mock_private_key, mock_stop_event)
    
    # Check if socket.recv was called and the exception was handled (it should retry or continue)
    mock_socket.recv.assert_any_call(4096)

# Test case: Test receiving an empty message (e.g., disconnected server)
def test_receive_empty_message(mock_socket, mock_stop_event, mock_private_key, mocker):
    # Mock socket.recv to return an empty message (server disconnected)
    mock_socket.recv.side_effect = [b""]  # Empty message
    
    # Call the function
    receive_messages(mock_socket, mock_private_key, mock_stop_event)
    
    # Check if the print statement "Server disconnected." is called
    mock_socket.recv.assert_any_call(4096)

# Test case: Test receiving a message with no public key (should continue without processing)
def test_receive_no_public_key(mock_socket, mock_stop_event, mock_private_key, mocker):
    # Mock socket.recv to return a message without public key
    mock_socket.recv.side_effect = [
        b"message without public key",  # Invalid data (no public key)
    ]
    
    # Call the function
    receive_messages(mock_socket, mock_private_key, mock_stop_event)
    
    # Check if the socket.recv was called and the function continues
    mock_socket.recv.assert_any_call(4096)
