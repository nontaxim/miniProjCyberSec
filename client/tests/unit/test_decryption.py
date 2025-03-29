import pytest
from cryptography.hazmat.primitives.asymmetric import padding
from client import decrypt_message

@pytest.fixture
def mock_private_key(mocker):
    # Mock the private key object
    mock_key = mocker.MagicMock()
    
    # Mock the decrypt method
    mock_key.decrypt.return_value = b"decrypted_message"  # Mock the output of decryption
    
    return mock_key

def test_decrypt_message(mock_private_key, mocker):
    # Inputs
    private_key = mock_private_key
    encrypted_message_hex = "656e637279707465645f6d657373616765"  # Hex string representing "encrypted_message"
    
    # Call the function
    decrypted_message = decrypt_message(private_key, encrypted_message_hex)

    # Check that the decrypt method was called with the correct arguments
    call_args = mock_private_key.decrypt.call_args[0]
    actual_encrypted_message, actual_padding = call_args
    
    # Check if the message passed to decrypt is the correct byte representation of the encrypted message
    assert actual_encrypted_message == bytes.fromhex(encrypted_message_hex)
    
    # Check if the padding used is correct
    assert isinstance(actual_padding, padding.OAEP)
    
    # Compare the decrypted message with the expected result
    assert decrypted_message == "decrypted_message"

    # Assert that the decrypt method was called exactly once
    mock_private_key.decrypt.assert_called_once()

def test_decrypt_message_exception(mock_private_key, mocker):
    # Force the decrypt method to raise an exception
    mock_private_key.decrypt.side_effect = Exception("Decryption failed")

    # Inputs
    private_key = mock_private_key
    encrypted_message_hex = "invalid_hex_string"

    # Call the function and expect it to handle the exception gracefully
    decrypted_message = decrypt_message(private_key, encrypted_message_hex)

    # Ensure the function returned None due to the exception
    assert decrypted_message is None