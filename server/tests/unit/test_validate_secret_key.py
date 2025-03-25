from base64 import b32encode
from pytest_mock import MockerFixture
from my_server import validate_secret_key

# Test with a valid Base32 secret key
def test_valid_secret_key() -> None:
    valid_key: str = b32encode(b"myvalidsecretkey").decode("utf-8")  # Example valid key in Base32 encoding
    result: bool = validate_secret_key(valid_key)
    assert result is True, "Valid secret key should return True"


# Test with an invalid Base32 secret key
def test_invalid_secret_key() -> None:
    invalid_key: str = "invalidkey!"  # An invalid Base32 key (non-Base32 characters)
    result: bool = validate_secret_key(invalid_key)
    assert result is False, "Invalid secret key should return False"


# Test case when the secret key is empty
def test_empty_secret_key(mocker: MockerFixture) -> None:
    # Mock base64.b32decode to raise an exception for empty input
    mock_b32decode = mocker.patch('base64.b32decode', side_effect=Exception("Invalid secret key: Empty key provided"))
    
    result: bool = validate_secret_key("")
    
    # Assert the result is False since the empty string should return False
    assert result is False, "Empty secret key should return False"
