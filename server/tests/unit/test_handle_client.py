import pytest
from pytest_mock import MockerFixture
from my_server import handle_client, handle_registration, handle_login, handle_message

# Test case for when client sends 'register'
def test_handle_client_register(mocker: MockerFixture):
    """Test that handle_client calls handle_registration when 'register' is received."""
    # Mock the client socket
    mock_socket = mocker.Mock()

    # Mock the 'recv' method to return 'register'
    mock_socket.recv.side_effect = [
        "register".encode(),  # Simulate receiving "register"
        b""  # Simulate client disconnecting
    ]

    # Mock the handle_registration function
    mock_handle_registration = mocker.patch("my_server.handle_registration")

    # Call the function under test
    handle_client(mock_socket)

    # Assert handle_registration was called once
    mock_handle_registration.assert_called_once_with(mock_socket)

# Test case for when client sends 'login'
def test_handle_client_login(mocker: MockerFixture):
    """Test that handle_client calls handle_login when 'login' is received."""
    # Mock the client socket
    mock_socket = mocker.Mock()

    # Mock the 'recv' method to return 'login'
    mock_socket.recv.side_effect = [
        "login".encode(),  # Simulate receiving "login"
        b""  # Simulate client disconnecting
    ]

    # Mock the handle_login function
    mock_handle_login = mocker.patch("my_server.handle_login")

    # Call the function under test
    handle_client(mock_socket)

    # Assert handle_login was called once
    mock_handle_login.assert_called_once_with(mock_socket)

# Test case for when client sends 'send_message'
def test_handle_client_send_message(mocker: MockerFixture):
    """Test that handle_client calls handle_message when 'send_message' is received."""
    # Mock the client socket
    mock_socket = mocker.Mock()

    # Mock the 'recv' method to return 'send_message'
    mock_socket.recv.side_effect = [
        "send_message".encode(),  # Simulate receiving "send_message"
        b""  # Simulate client disconnecting
    ]

    # Mock the handle_message function
    mock_handle_message = mocker.patch("my_server.handle_message")

    # Call the function under test
    handle_client(mock_socket)

    # Assert handle_message was called once
    mock_handle_message.assert_called_once_with(mock_socket)

# Test case for when client sends 'exit'
def test_handle_client_exit(mocker: MockerFixture):
    """Test that handle_client exits when 'exit' is received."""
    # Mock the client socket
    mock_socket = mocker.Mock()

    # Mock the 'recv' method to return 'exit'
    mock_socket.recv.side_effect = [
        "exit".encode(),  # Simulate receiving "exit"
        b""  # Simulate client disconnecting
    ]

    # Call the function under test
    handle_client(mock_socket)

    # Assert that client_socket.close was called
    mock_socket.close.assert_called_once()

# Test case for when client sends invalid data (exception is raised)
def test_handle_client_invalid_data(mocker: MockerFixture):
    """Test that handle_client handles exceptions correctly."""
    # Mock the client socket
    mock_socket = mocker.Mock()

    # Mock the 'recv' method to raise an exception
    mock_socket.recv.side_effect = Exception("Test Exception")

    # Mock the handle_registration, handle_login, and handle_message functions (they shouldn't be called)
    mock_handle_registration = mocker.patch("my_server.handle_registration")
    mock_handle_login = mocker.patch("my_server.handle_login")
    mock_handle_message = mocker.patch("my_server.handle_message")

    # Call the function under test
    handle_client(mock_socket)

    # Assert that none of the handler functions were called due to the exception
    mock_handle_registration.assert_not_called()
    mock_handle_login.assert_not_called()
    mock_handle_message.assert_not_called()

    # Assert that client_socket.close was called
    mock_socket.close.assert_called_once()

