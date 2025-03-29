from cryptography.hazmat.backends import default_backend
from client import load_private_key


def test_load_private_key_success(mocker):
    username = "testuser"
    private_key_pem = b"-----BEGIN PRIVATE KEY-----\n...fake_private_key...\n-----END PRIVATE KEY-----"  # Mock key data

    # Mock os.path.exists to return True
    mocker.patch("os.path.exists", return_value=True)

    # Mock open to return the fake private key
    mock_open = mocker.mock_open(read_data=private_key_pem)
    mocker.patch("builtins.open", mock_open)

    # Mock load_pem_private_key to return a mock key object
    mock_load_key = mocker.patch("cryptography.hazmat.primitives.serialization.load_pem_private_key")
    mock_load_key.return_value = "mock_private_key_object"

    private_key = load_private_key(username)

    # Assertions
    mock_load_key.assert_called_once_with(private_key_pem, password=None, backend=default_backend())
    assert private_key == "mock_private_key_object"


def test_load_private_key_file_not_found(mocker):
    username = "testuser"

    # Mock os.path.exists to return False
    mocker.patch("os.path.exists", return_value=False)

    private_key = load_private_key(username)

    # Ensure None is returned when the file does not exist
    assert private_key is None
