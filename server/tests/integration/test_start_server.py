import pytest
from my_server import start_server, handle_client
import pyotp
import socket

# Test for start_server function
def test_start_server(mocker):
    """Test that start_server behaves as expected."""
    
    # Ensure secret_key is unset, so the code inside the 'if not secret_key' block is triggered
    mocker.patch("my_server.secret_key", None)
    
    # Mock pyotp.random_base32 to simulate a successful OTP_SECRET_KEY generation
    mocker.patch("pyotp.random_base32", return_value="test_secret_key")
    
    # Mock validate_secret_key to always return True (i.e., the key is valid)
    validate_secret_key_mock = mocker.patch("my_server.validate_secret_key", return_value=True)
    
    # Mock socket creation and server binding
    mock_server = mocker.Mock()
    mocker.patch("socket.socket", return_value=mock_server)
    
    # Mock the accept method of the server to simulate client connections
    mock_client_socket = mocker.Mock()
    mock_client_address = ("127.0.0.1", 12345)
    mock_server.accept.side_effect = [(mock_client_socket, mock_client_address), KeyboardInterrupt]  # Simulate one connection and then stop
    
    # Mock threading.Thread to prevent actual threading and function execution
    mock_thread = mocker.patch("threading.Thread")
    
    # Call the function under test
    start_server()

    # Assert that pyotp.random_base32 was called to generate the secret key
    pyotp.random_base32.assert_called_once()

    # Assert that validate_secret_key was called with the generated secret key
    validate_secret_key_mock.assert_called_once_with("test_secret_key")

    # Assert that socket.socket() was called to create the server socket
    mock_server.setsockopt.assert_called_once_with(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Assert that the server attempted to bind to address '0.0.0.0' on port 5555
    mock_server.bind.assert_called_once_with(('0.0.0.0', 5555))

    # Assert that the server is set to listen
    mock_server.listen.assert_called_once_with(5)

    # Assert that threading.Thread was called to handle the client connection
    mock_thread.assert_called_once_with(target=handle_client, args=(mock_client_socket,))

    # Assert that server.close() will be called in the finally block after the server stops
    mock_server.close.assert_called_once()

# Test for raising ValueError when OTP_SECRET_KEY is invalid
def test_invalid_secret_key(mocker):
    """Test that ValueError is raised if OTP_SECRET_KEY is invalid."""
    
    # Ensure secret_key is unset, so the code inside the 'if not secret_key' block is triggered
    mocker.patch("my_server.secret_key", None)
    
    # Mock pyotp.random_base32 to simulate a successful OTP_SECRET_KEY generation
    mocker.patch("pyotp.random_base32", return_value="test_secret_key")
    
    # Mock validate_secret_key to return False (i.e., the key is invalid)
    mocker.patch("my_server.validate_secret_key", return_value=False)
    
    # Call the function under test and assert that the ValueError is raised
    with pytest.raises(ValueError, match="Invalid OTP_SECRET_KEY. Please check your .env file or regenerate the key."):
        start_server()

# Test for general exception handling when starting the server
def test_server_startup_exception(mocker):
    """Test that the server raises an exception and handles it gracefully."""

    # Ensure secret_key is unset, so the code inside the 'if not secret_key' block is triggered
    mocker.patch("my_server.secret_key", None)

    # Mock pyotp.random_base32 to simulate a successful OTP_SECRET_KEY generation
    mocker.patch("pyotp.random_base32", return_value="test_secret_key")

    # Mock validate_secret_key to always return True (i.e., the key is valid)
    mocker.patch("my_server.validate_secret_key", return_value=True)

    # Mock socket creation and simulate an exception during server binding
    mock_server = mocker.Mock()
    mock_server.bind.side_effect = Exception("Socket bind error")  # Simulate error during bind
    mocker.patch("socket.socket", return_value=mock_server)

    # Mock threading.Thread to prevent actual threading and function execution
    mock_thread = mocker.patch("threading.Thread")

    # Patch print globally
    mock_print = mocker.patch("builtins.print")

    # Call the function under test and assert that the exception is handled properly
    with pytest.raises(Exception, match="Socket bind error"):
        start_server()

    # Ensure that the error message is printed
    mock_print.assert_any_call("Error starting server: Socket bind error")
