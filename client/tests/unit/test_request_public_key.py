import pytest
from client import request_public_key

def test_request_public_key_success(mocker):
    # Mock the client socket
    mock_socket = mocker.MagicMock()

    # Define the test data
    to_client = "targetuser"
    expected_public_key = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7Yt9U8R+T3jHlQF3wMprFf9DbbKq5vKDoETqk9z74XYdd7Xl1Zs2cJ0WGw7+66kEwL2mnX5PnFlp6jm7gxFZf9sL2VhG6bTZzUNv5EhkfJqAlHYd97XGl2EVoMzoH5wTgsBzvPFTpxh/FkqO2NO56y/zZ3BTTx0jItfT0kq6a2F7A6W3bqgQrd76f7YQ/SH9Emr8OkqfCwE6VsCB6YmeIu/3DhWxqG97FqcUGLVFbp6p6sKBUR9+9s0wKn37YgC5BYPVntZYmD/F4pJmiPdsfKLwAseOdQTvbp/iF1Aq3zMzM20B6VQdbbEJzA1+1rp1NjhP+gFZT5wnA0dckQIDAQAB\n-----END PUBLIC KEY-----\n"

    # Mock the recv method to return the expected public key
    mock_socket.recv.return_value = expected_public_key.encode()

    # Call the function
    result = request_public_key(mock_socket, to_client)

    # Assert that send was called with the correct parameters
    mock_socket.send.assert_called_once_with(to_client.encode())

    # Assert that the result matches the expected public key
    assert result == expected_public_key


def test_request_public_key_no_response(mocker):
    # Mock the client socket
    mock_socket = mocker.MagicMock()

    # Define the test data
    to_client = "targetuser"

    # Mock the recv method to return an empty response (no public key)
    mock_socket.recv.return_value = b""

    # Call the function
    result = request_public_key(mock_socket, to_client)

    # Assert that send was called with the correct parameters
    mock_socket.send.assert_called_once_with(to_client.encode())

    # Assert that the result is an empty string or None (depending on the behavior)
    assert result == ""  # Or use None if that's the expected behavior when no key is returned


def test_request_public_key_with_error(mocker):
    # Mock the client socket
    mock_socket = mocker.MagicMock()

    # Define the test data
    to_client = "targetuser"

    # Simulate an error by raising an exception in recv
    mock_socket.recv.side_effect = Exception("Socket error")

    # Call the function and assert that it raises an exception
    with pytest.raises(Exception, match="Socket error"):
        request_public_key(mock_socket, to_client)
