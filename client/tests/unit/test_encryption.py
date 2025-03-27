import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from client import encrypt_message

@pytest.fixture
def mock_public_key(mocker):
    # Mock the public key object
    mock_key = mocker.MagicMock()
    
    # Mock the encrypt method
    mock_key.encrypt.return_value = b"encrypted_message_bytes"  # Mock the output of encryption
    
    return mock_key

def test_encrypt_message(mock_public_key, mocker):
    # Mock load_pem_public_key to return the mocked public key
    mocker.patch("cryptography.hazmat.primitives.serialization.load_pem_public_key", return_value=mock_public_key)

    # Inputs
    public_key_pem = "fake_public_key_pem"
    message = "Hello, World!"

    # Define the expected OAEP padding
    expected_padding = padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
    
    # Call the function
    encrypted_message = encrypt_message(public_key_pem, message)

    # Check that the encrypt method was called with the correct arguments
    call_args = mock_public_key.encrypt.call_args[0]
    actual_message, actual_padding = call_args

    # Print the attributes of the MGF1 object explicitly
    for attr in dir(expected_padding):
        if not attr.startswith('__'):  # Skip dunder methods
            print(f"{attr}: {getattr(expected_padding, attr)}")
    
    # Compare the message and padding explicitly
    assert actual_message == message.encode()
    
    # Compare the padding explicitly
    assert isinstance(actual_padding, padding.OAEP)
    
    # Compare the MGF1 algorithm correctly
    assert isinstance(actual_padding.mgf, padding.MGF1)
    
    # Check the algorithm used in MGF1 (this matches the _algorithm attribute)
    assert actual_padding.mgf._algorithm.name == expected_padding.mgf._algorithm.name
    
    # Compare the algorithm of OAEP
    assert actual_padding.algorithm.name == expected_padding.algorithm.name
    assert actual_padding._label == expected_padding._label

    # Assert that the output is as expected (the mock return value)
    assert encrypted_message == "656e637279707465645f6d6573736167655f6279746573"  # The hex string of the mock return value
