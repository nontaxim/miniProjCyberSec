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

@pytest.fixture
def mock_validate_username(mocker):
    return mocker.patch('client.validate_username', side_effect=[False, False, True])  # Simulate invalid inputs before a valid one

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

def test_main_invalid_option2(mock_socket, mock_register_client, mock_load_private_key, mock_login_client, mock_receive_messages, mock_send_message, mock_stop_receive_thread, mocker):
    # Mock the input function to simulate user interaction
    mocker.patch('builtins.input', side_effect=['1', 'test_user', '3', '1', '2'])  # Simulate user choosing 'Register', entering a username, and sending a message

    mock_print = mocker.patch("builtins.print")
    
    # Call the main function
    main()

    # Ensure that socket was connected
    mock_socket().connect.assert_called_once_with(('localhost', 5555))

    # Test if the register_client was called (for 'Register' option)
    mock_register_client.assert_called_once_with(mock_socket(), 'test_user')

    # check is print "Invalid option"
    mock_print.assert_any_call("Invalid option! Please choose again.")

    # Test that the receive_messages function was called
    mock_receive_messages.assert_called_once()

    # Test that send_message was called (for the option to send a message)
    mock_send_message.assert_called_once()

    # Test if stop_receive_thread was called to stop the receiving thread
    mock_stop_receive_thread.assert_called_once()

    # Ensure socket close was called at the end
    mock_socket().close.assert_called_once()

def test_main_invalid_option1(mock_socket, mock_register_client, mock_load_private_key, mock_login_client, mock_receive_messages, mock_send_message, mock_stop_receive_thread, mocker):
    """Test invalid menu selection and ensure the prompt repeats until valid input is given."""
    
    mock_print = mocker.patch("builtins.print")
    
    # Mock input to provide invalid choices before selecting a valid one
    mocker.patch('builtins.input', side_effect=['3', 'x', '1', 'test_user', '1', '2'])  

    main()

    # Ensure that invalid option message was printed twice
    mock_print.assert_any_call("Invalid option! Please choose again.")
    mock_print.assert_any_call("Invalid option! Please choose again.")

def test_main_invalid_username(
    mock_socket,
    mock_register_client,
    mock_load_private_key,
    mock_login_client,
    mock_receive_messages,
    mock_send_message,
    mock_stop_receive_thread,
    mocker
):
    """Test invalid username format and ensure the prompt repeats until a valid username is entered."""

    # Patch validate_username to return False twice before returning True
    mock_validate_username = mocker.patch('client.validate_username', side_effect=[False, False, True])

    # Mock input to simulate invalid usernames followed by a valid one
    mock_input = mocker.patch('builtins.input', side_effect=['1', 'invalid@user', 'bad username!', 'valid_user', '2'])

    main()

    # Ensure username validation was checked multiple times
    assert mock_validate_username.call_count == 3

    # Check if the error message is present in the input prompts
    input_calls = [call.args[0] for call in mock_input.call_args_list]
    
    expected_message = "Invalid username format."
    assert any(expected_message in msg for msg in input_calls), f"Expected '{expected_message}' in input prompts but got {input_calls}"

def test_main_register_fails(mock_socket, mocker):
    """Test if the client socket closes when registration fails due to missing private/public key."""
    
    # Mock register_client to return failure (None values)
    mock_register_client = mocker.patch('client.register_client', return_value=(None, None))

    # Mock input to choose 'Register' and enter a valid username
    mocker.patch('builtins.input', side_effect=['1', 'valid_user'])

    main()

    # Ensure socket is closed upon registration failure
    mock_socket().close.assert_called_once()

def test_main_login_fails(mock_socket, mock_load_private_key, mocker):
    """Test if the client socket closes when login fails due to invalid private key or authentication failure."""
    
    # Mock load_private_key to return None (simulating failure)
    mock_load_private_key.return_value = None

    # Mock input to choose 'Login' and enter a valid username
    mocker.patch('builtins.input', side_effect=['2', 'valid_user'])

    main()

    # Ensure socket is closed upon login failure
    mock_socket().close.assert_called_once()
