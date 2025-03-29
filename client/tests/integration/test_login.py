from client import login_client

def test_login_client_success(mocker):
    # Mock the client socket
    mock_socket = mocker.MagicMock()

    # Define the test data
    username = "testuser"
    private_key = mocker.MagicMock()  # Assuming you have a valid private_key object
    expected_challenge = "challenge_string"

    # Mock the socket responses for a successful login process
    mock_socket.recv.side_effect = [
        "login".encode(),  # First response: login challenge
        expected_challenge.encode(),  # Challenge from the server
        "valid signature!".encode(),  # Valid signature response
        "successful login!".encode(),  # Password acceptance message
    ]
    
    # Mock the signed_message function to return a signed challenge
    mock_signed_challenge = "signed_challenge_string"
    mocker.patch("client.signed_message", return_value=mock_signed_challenge)

    # Mock the getpass function to return a password
    mocker.patch("getpass.getpass", return_value="SecureP@ss123")

    # Call the function
    result = login_client(mock_socket, username, private_key)

    # Verify socket interactions
    mock_socket.send.assert_any_call("login".encode())
    mock_socket.send.assert_any_call(username.encode())
    mock_socket.send.assert_any_call(mock_signed_challenge.encode())

    # Ensure that the password is sent after the valid signature
    mock_socket.send.assert_any_call("SecureP@ss123".encode())

    # Check that the function returns the expected result for a successful login
    assert result == True



def test_login_client_invalid_challenge(mocker):
    # Mock the client socket
    mock_socket = mocker.MagicMock()

    # Define the test data
    username = "testuser"
    private_key = mocker.MagicMock()

    # Simulate an invalid challenge from the server
    mock_socket.recv.side_effect = [
        "login".encode(),  # First response: login challenge
        "not registered".encode(),  # Error message from server (not registered)
    ]

    # Call the function
    result = login_client(mock_socket, username, private_key)

    # Verify that the function returns False due to an invalid challenge
    assert result is False


def test_login_client_invalid_signature(mocker):
    # Mock the client socket
    mock_socket = mocker.MagicMock()

    # Define the test data
    username = "testuser"
    private_key = mocker.MagicMock()
    expected_challenge = "challenge_string"

    # Mock the socket responses for an invalid signature
    mock_socket.recv.side_effect = [
        "login".encode(),  # First response: login challenge
        expected_challenge.encode(),  # Challenge from the server
        "invalid signature!".encode(),  # Invalid signature response
    ]
    
    # Mock the signed_message function to return a signed challenge
    mock_signed_challenge = "signed_challenge_string"
    mocker.patch("client.signed_message", return_value=mock_signed_challenge)

    # Call the function
    result = login_client(mock_socket, username, private_key)

    # Verify that the function returns False due to an invalid signature
    assert result is False

def test_login_client_server_error(mocker):
    # Mock the client socket
    mock_socket = mocker.MagicMock()

    # Define the test data
    username = "testuser"
    private_key = mocker.MagicMock()

    # Simulate a server that doesn't respond with the expected "login" message
    mock_socket.recv.side_effect = [
        "unexpected_response".encode(),  # Invalid server response
    ]

    # Call the function
    result = login_client(mock_socket, username, private_key)

    # Verify that the function returns False due to the unexpected server response
    assert result is False
