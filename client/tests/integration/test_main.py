import pytest
from client import main

@pytest.fixture
def mock_socket(mocker):
    return mocker.patch('socket.socket', autospec=True)

@pytest.fixture
def mock_register_client(mocker):
    return mocker.patch('client.register_client', return_value=("private_key", "other_value"))

@pytest.fixture
def mock_load_private_key(mocker):
    return mocker.patch('client.load_private_key', return_value="private_key")

@pytest.fixture
def mock_login_client(mocker):
    return mocker.patch('client.login_client', return_value=True)

@pytest.fixture
def mock_receive_messages(mocker):
    return mocker.patch('client.receive_messages')

@pytest.fixture
def mock_send_message(mocker):
    return mocker.patch('client.send_message')

@pytest.fixture
def mock_stop_receive_thread(mocker):
    return mocker.patch('client.stop_receive_thread')

def test_main(mock_socket, mock_register_client, mock_load_private_key, mock_login_client, mock_receive_messages, mock_send_message, mock_stop_receive_thread, mocker):
    # Mock the input function to simulate user interaction
    mocker.patch('builtins.input', side_effect=['1', 'test_user', '1', '2'])  # Simulate user choosing 'Register', entering a username, and sending a message
    
    # Call the main function
    main()

    # Ensure that socket was connected
    mock_socket().connect.assert_called_once_with(('localhost', 5555))

    # Test if the register_client was called (for 'Register' option)
    mock_register_client.assert_called_once_with(mock_socket(), 'test_user')

    # Test that the receive_messages function was called
    mock_receive_messages.assert_called_once()

    # Test that send_message was called (for the option to send a message)
    mock_send_message.assert_called_once()

    # Test if stop_receive_thread was called to stop the receiving thread
    mock_stop_receive_thread.assert_called_once()

    # Ensure socket close was called at the end
    mock_socket().close.assert_called_once()
