from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from client import generate_RSA_key

def test_generate_RSA_key_key_does_not_exist(mocker):
    username = "testuser"

    # Mock rsa.generate_private_key
    mock_private_key = mocker.MagicMock()
    mock_public_key = mocker.MagicMock()
    mock_private_key.public_key.return_value = mock_public_key

    mock_generate_private_key = mocker.patch(
        "cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key",
        return_value=mock_private_key,
    )

    # Mock open to avoid actual file I/O
    mock_open = mocker.patch("builtins.open", mocker.mock_open())

    # Mock private_bytes and public_bytes
    mock_private_key.private_bytes.return_value = b"mock_private_key_data"
    mock_public_key.public_bytes.return_value = b"mock_public_key_data"

    # Call function
    private_key, public_key = generate_RSA_key(username)

    # Ensure key generation was called with expected parameters
    mock_generate_private_key.assert_called_once_with(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )

    # Ensure private key methods were called correctly
    mock_private_key.private_bytes.assert_called_once_with(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=mocker.ANY,  # Fix for NoEncryption() identity issue
    )

    # Ensure public key methods were called correctly
    mock_public_key.public_bytes.assert_called_once_with(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Ensure files were opened correctly
    mock_open.assert_any_call(f"{username}_private_key.pem", "wb")
    mock_open.assert_any_call(f"{username}_public_key.pem", "wb")

    # Ensure private and public key data were written to files
    handle = mock_open()
    handle.write.assert_any_call(b"mock_private_key_data")
    handle.write.assert_any_call(b"mock_public_key_data")

def test_generate_RSA_key_key_exists(mocker):
    username = "testuser"

    # Mock print function to capture the output
    mock_print = mocker.patch("builtins.print")

    # Mock os.path.exists to return True (key pair already exists)
    mocker.patch("os.path.exists", side_effect=lambda path: path.endswith("_private_key.pem") or path.endswith("_public_key.pem"))

    # Call function again, this time it should print that the keys already exist
    private_key, public_key = generate_RSA_key(username)

    # Ensure the "already exists" message is printed
    mock_print.assert_called_with(f"username: {username} already exists.")

    # Ensure None, None is returned when keys already exist
    assert private_key is None
    assert public_key is None