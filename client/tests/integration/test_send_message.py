import json
from client import send_message

def test_send_message(mocker):
    # Mock the client socket
    mock_socket = mocker.MagicMock()

    # Mock the server response for the 'message' command
    mock_socket.recv.side_effect = [
        "message".encode(),  # First server response: "message"
        "recipient_public_key".encode(),  # Simulate receiving a public key for recipient
    ]

    # Mock the input calls to simulate user input
    mocker.patch("builtins.input", side_effect=["recipient_user", "Hello there!"])

    # Mock the request_public_key function to return a mock public key
    mock_request_public_key = mocker.patch("client.request_public_key", return_value="mock_public_key")

    # Mock the encrypt_message function to return an encrypted message
    mock_encrypt_message = mocker.patch("client.encrypt_message", return_value="encrypted_message")

    # Mock the signed_message function to return a mock signature
    mock_signed_message = mocker.patch("client.signed_message", return_value="mock_signature")

    # Define the test data
    private_key = mocker.MagicMock()  # Mock private key
    username = "testuser"

    # Call the send_message function
    send_message(mock_socket, private_key, username)

    # Verify that the socket's send methods were called with the expected data
    # Verifying that the "send_message" command was sent
    mock_socket.send.assert_any_call("send_message".encode())

    # Verifying the message data being sent
    message_data = {
        'from_client': username,
        'to_client': "recipient_user",
        'encrypted_message': "encrypted_message",
        'signature': "mock_signature"
    }
    
    mock_socket.sendall.assert_any_call(json.dumps(message_data).encode())

    # Verify that request_public_key was called correctly
    mock_request_public_key.assert_called_once_with(mock_socket, "recipient_user")

    # Verify that encrypt_message and signed_message were called correctly
    mock_encrypt_message.assert_called_once_with("mock_public_key", "Hello there!")
    mock_signed_message.assert_called_once_with(private_key, "encrypted_message")


def test_send_message_invalid_response(mocker):
    # Mock the client socket
    mock_socket = mocker.MagicMock()

    # Simulate invalid server response (not "message") by using a generator for side_effect
    def mock_recv(*args, **kwargs):
        return b"invalid_response"  # Simulate invalid response on first call

    mock_socket.recv.side_effect = mock_recv

    # Call the function
    send_message(mock_socket, "private_key", "testuser")

    # Verify that the server response was printed
    mock_socket.send.assert_called_once_with("send_message".encode())
    mock_socket.recv.assert_called_once()

    # Capture printed output using mocker.patch for print function
    mock_print = mocker.patch("builtins.print")
    send_message(mock_socket, "private_key", "testuser")
    mock_print.assert_called_with("Server response: invalid_response")
