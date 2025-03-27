import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from client import signed_message

@pytest.fixture
def mock_private_key(mocker):
    # Mock the private key object
    mock_key = mocker.MagicMock()
    
    # Mock the sign method
    mock_key.sign.return_value = b"mock_signature_bytes"  # Mocked signature bytes
    
    return mock_key

def test_signed_message(mock_private_key):
    # Inputs
    private_key = mock_private_key
    message = "Hello, World!"
    
    # Expected signature in hex format
    expected_signature_hex = "6d6f636b5f7369676e61747572655f6279746573"  # This is just a mock placeholder

    # Call the function
    signature_hex = signed_message(private_key, message)

    # Check that the sign method was called with the correct arguments
    call_args = mock_private_key.sign.call_args[0]
    actual_message, actual_padding, actual_algorithm = call_args
    
    # Check if the correct message was passed for signing
    assert actual_message == message.encode()
    
    # Verify padding is PKCS1v15
    assert isinstance(actual_padding, padding.PKCS1v15)
    
    # Verify hashing algorithm is SHA256
    assert isinstance(actual_algorithm, hashes.SHA256)
    
    # Ensure the returned signature is the mocked one (converted to hex)
    assert signature_hex == expected_signature_hex  # Expected hex of "mock_signature_bytes"

    # Assert that the sign method was called exactly once
    mock_private_key.sign.assert_called_once()
