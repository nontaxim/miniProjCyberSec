from pytest_mock import MockerFixture
import my_server as my_server

def test_generate_otp(mocker: MockerFixture) -> None:
    """
    Test the OTP generation using pyotp with a mocked secret key.

    :param mocker: pytest-mock fixture for mocking functionality.
    :return: None
    """
    # Define secret_key as a string
    secret_key: str = "JBSWY3DPEHPK3PXP"

    # Mock the secret_key in the mix module
    mocker.patch.object(my_server, "secret_key", secret_key)

    # Generate OTP using the mocked secret_key
    otp: str = my_server.generate_otp()

    # Ensure the OTP is a string of digits
    assert isinstance(otp, str)  # Ensure OTP is a string
    assert otp.isdigit()  # Ensure OTP is numeric
    assert len(otp) == 6  # Ensure OTP has a length of 6 digits
