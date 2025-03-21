import pytest
import my_server as my_server

@pytest.fixture
def setup_otp() -> None:
    """Set up a test OTP for a user."""
    my_server.client_otp["test_user"] = "123456"

def test_verify_otp(setup_otp: None) -> None:
    """Test OTP verification."""
    assert my_server.verify_otp("test_user", "123456") is True  # Correct OTP should return True
    assert my_server.verify_otp("test_user", "654321") is False  # Incorrect OTP should return False
