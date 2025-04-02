import smtplib
import my_server

def test_send_otp_email_success(mocker) -> None:
    """
    Test that the send_otp_email function sends an OTP via email successfully.
    """
    # Mock SMTP_SSL and its behavior
    mock_smtp = mocker.patch("my_server.smtplib.SMTP_SSL")
    mock_smtp_instance = mocker.MagicMock()
    mock_smtp.return_value.__enter__.return_value = mock_smtp_instance

    # Create a mock for the client socket
    mock_client_socket = mocker.MagicMock()

    # Call the function
    my_server.send_otp_email("test@example.com", "123456", mock_client_socket)

    # Check that SMTP_SSL and other methods were called
    mock_smtp.assert_called_once_with("smtp.gmail.com", 465)
    mock_smtp_instance.login.assert_called_once_with(my_server.sender_email, my_server.sender_password)
    mock_smtp_instance.sendmail.assert_called_once()
    mock_client_socket.close.assert_not_called()  # Ensure the socket close wasn't called

def test_send_otp_email_auth_error(mocker) -> None:
    """
    Test that the send_otp_email function handles SMTPAuthenticationError.
    """
    # Mock SMTP_SSL and simulate an authentication error
    mock_smtp = mocker.patch("my_server.smtplib.SMTP_SSL")
    mock_smtp_instance = mocker.MagicMock()
    mock_smtp.return_value.__enter__.return_value = mock_smtp_instance

    # Simulate SMTPAuthenticationError
    mock_smtp_instance.login.side_effect = smtplib.SMTPAuthenticationError(1, "Authentication error")

    # Create a mock for the client socket
    mock_client_socket = mocker.MagicMock()

    # Call the function and check for exception handling
    my_server.send_otp_email("test@example.com", "123456", mock_client_socket)

    # Ensure the authentication error was handled and the client socket was closed
    mock_client_socket.close.assert_called_once()

def test_send_otp_email_general_exception(mocker) -> None:
    """
    Test that the send_otp_email function handles general exceptions.
    """
    # Mock SMTP_SSL and simulate a general exception
    mock_smtp = mocker.patch("my_server.smtplib.SMTP_SSL")
    mock_smtp_instance = mocker.MagicMock()
    mock_smtp.return_value.__enter__.return_value = mock_smtp_instance

    # Simulate a general exception during sending email
    mock_smtp_instance.sendmail.side_effect = Exception("Some error occurred")

    # Create a mock for the client socket
    mock_client_socket = mocker.MagicMock()

    # Call the function and check for exception handling
    my_server.send_otp_email("test@example.com", "123456", mock_client_socket)

    # Ensure the general exception was handled and the client socket was closed
    mock_client_socket.close.assert_called_once()

def test_send_otp_email_e2e_test_mode(mocker) -> None:
    """
    Test that the send_otp_email function sends an OTP using MailHog when app_mode is "e2e_test".
    """
    # Mock app_mode to be "e2e_test"
    mocker.patch("my_server.app_mode", "e2e_test")

    # Mock SMTP and its behavior for MailHog (localhost SMTP)
    mock_smtp = mocker.patch("my_server.smtplib.SMTP")
    mock_smtp_instance = mocker.MagicMock()
    mock_smtp.return_value.__enter__.return_value = mock_smtp_instance

    # Create a mock for the client socket
    mock_client_socket = mocker.MagicMock()

    # Mock print to capture printed output
    mock_print = mocker.patch("builtins.print")

    # Call the function
    my_server.send_otp_email("test@example.com", "123456", mock_client_socket)

    # Check that SMTP is called with localhost and port 1025
    mock_smtp.assert_called_once_with("localhost", 1025)
    mock_smtp_instance.sendmail.assert_called_once()

    # Check that the print statements related to MailHog are called
    mock_print.assert_any_call("------APP_MODE: e2e_test-------")
    mock_print.assert_any_call("using localhost SMTP for testing in port 1025")
    mock_print.assert_any_call("By Capturing the email using MailHog")

    # Ensure the client socket was not closed in this case
    mock_client_socket.close.assert_not_called()
