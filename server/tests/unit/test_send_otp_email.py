from unittest.mock import MagicMock
from pytest_mock import MockerFixture
import my_server as my_server

def test_send_otp_email(mocker: MockerFixture) -> None:
    """
    Test that the send_otp_email function sends an OTP via email using SMTP.

    :param mocker: pytest-mock fixture used for mocking.
    :return: None
    """
    # Use mocker to patch SMTP_SSL in my_server.smtplib
    mock_smtp = mocker.patch("my_server.smtplib.SMTP_SSL")

    # Create a mock instance for the SMTP connection
    mock_smtp_instance = MagicMock()

    # Mock the context manager behavior
    mock_smtp.return_value.__enter__.return_value = mock_smtp_instance

    # Call the function you want to test
    my_server.send_otp_email("test@example.com", "123456", None)

    # Ensure SMTP_SSL was called with the correct arguments
    mock_smtp.assert_called_once_with("smtp.gmail.com", 465)

    # Verify that login and sendmail were called
    mock_smtp_instance.login.assert_called_once_with(my_server.sender_email, my_server.sender_password)
    mock_smtp_instance.sendmail.assert_called_once()
