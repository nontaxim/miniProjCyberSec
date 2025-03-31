import json
import pytest
from unittest.mock import MagicMock
from pytest_mock import mocker
from my_server import handle_message
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding

# Fixture to mock the client socket
@pytest.fixture
def mock_client_socket():
    mock_socket = MagicMock()
    mock_socket.recv.return_value = b'client2'  # Simulate receiving the recipient's username
    return mock_socket

# Fixture to mock message data
@pytest.fixture
def mock_message_data():
    return {
        'from_client': 'client1',
        'to_client': 'client2',
        'encrypted_message': 'encrypted_msg',
        'signature': 'abcdef1234567890'  # Example valid hex signature
    }

def test_handle_message_valid(mock_client_socket, mock_message_data, mocker):
    """Test valid message forwarding."""
    # Mock get_public_key to return a valid public key
    mocker.patch("my_server.get_public_key", return_value="valid_public_key_for_client2")
    
    # Mock recv_all to return the expected message data as JSON
    mocker.patch("my_server.recv_all", return_value=json.dumps(mock_message_data))

    # Patch the client_sockets dictionary in my_server.py to simulate 'client2' being online
    mock_client_socket_recipient = MagicMock()
    mocker.patch.dict('my_server.client_sockets', {'client2': mock_client_socket_recipient})

    # Mock the cryptography load_pem_public_key to prevent errors with malformed PEM files
    mocker.patch.object(serialization, 'load_pem_public_key', return_value=MagicMock())

    # Mock signature verification to always succeed (no exception raised)
    mocker.patch.object(rsa.RSAPublicKey, 'verify', return_value=None)  # Make the verify method always return None, as if the signature is valid

    # Call handle_message
    handle_message(mock_client_socket)

    # Assert that the message was forwarded to the recipient
    mock_client_socket_recipient.sendall.assert_any_call(json.dumps(mock_message_data).encode())

    # Assert that the sender received confirmation that the message was forwarded
    mock_client_socket.send.assert_any_call(b"Message forwarded!")

    # Assert that the public key was sent before the message
    mock_client_socket_recipient.sendall.assert_any_call(b'valid_public_key_for_client2')



def test_handle_message_recipient_not_found(mock_client_socket, mock_message_data, mocker):
    """Test when the recipient's public key is not found."""
    # Mock get_public_key to return None (no recipient found)
    mocker.patch("my_server.get_public_key", return_value=None)

    # Call handle_message
    handle_message(mock_client_socket)

    # Assert that the client received the "Recipient not found!" message
    mock_client_socket.send.assert_any_call(b"Recipient not found!")

def test_handle_message_invalid_signature(mock_client_socket, mock_message_data, mocker):
    """Test when the signature is invalid."""
    # Mock get_public_key to return a valid public key
    mocker.patch("my_server.get_public_key", return_value="public_key_of_client2")
    
    # Mock recv_all to return the expected message data
    mocker.patch("my_server.recv_all", return_value=json.dumps(mock_message_data))

    # Simulate an invalid signature by patching the verify method to raise an exception
    mocker.patch.object(serialization, 'load_pem_public_key', return_value=MagicMock(
        verify=MagicMock(side_effect=Exception("Invalid signature"))
    ))

    # Call handle_message
    handle_message(mock_client_socket)

    # Assert that the client received the "Invalid signature!" message
    mock_client_socket.send.assert_any_call(b"Invalid signature!")

def test_handle_message_recipient_not_online(mock_client_socket, mock_message_data, mocker):
    """Test when the recipient is not online (socket closed)."""
    # Mock get_public_key to return a valid public key
    mocker.patch("my_server.get_public_key", return_value="public_key_of_client2")
    
    # Mock recv_all to return the expected message data
    mocker.patch("my_server.recv_all", return_value=json.dumps(mock_message_data))

    # Simulate that the recipient is not online by making their socket unavailable
    recipient_socket = MagicMock()
    recipient_socket.fileno.return_value = -1  # Simulate a closed socket
    mocker.patch.dict('my_server.client_sockets', {'client2': recipient_socket})

    # Mock the cryptography load_pem_public_key to prevent errors with malformed PEM files
    mocker.patch.object(serialization, 'load_pem_public_key', return_value=MagicMock())

    # Mock signature verification to always succeed (no exception raised)
    mocker.patch.object(rsa.RSAPublicKey, 'verify', return_value=None)  # Make the verify method always return None, as if the signature is valid


    # Call handle_message
    handle_message(mock_client_socket)

    # Assert that the client received the "Recipient not online!" message
    mock_client_socket.send.assert_any_call(b"Recipient not online!")
