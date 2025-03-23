import pytest
from pytest_mock import MockerFixture
from my_server import generate_otp, verify_otp, client_otp

@pytest.fixture
def mock_secret_key(mocker: MockerFixture) -> None:
    """Mock the secret key used in OTP generation."""
    mocker.patch("my_server.secret_key", "JBSWY3DPEHPK3PXP")

@pytest.fixture
def setup_otp() -> None:
    """Set up a test OTP for a user."""
    client_otp["test_user"] = "123456"

def test_generate_otp(mock_secret_key: None) -> None:
    """Test OTP generation."""
    otp: str = generate_otp()
    assert len(otp) == 6  # OTP should be 6 digits

def test_verify_otp(setup_otp: None) -> None:
    """Test OTP verification."""
    assert verify_otp("test_user", "123456")  # Correct OTP should return True
    assert not verify_otp("test_user", "654321")  # Incorrect OTP should return False
