import pytest
import sqlite3
from my_server import add_user

@pytest.fixture
def mock_database(mocker):
    """Fixture to mock the database connection and cursor."""
    mock_conn = mocker.Mock()
    mock_cursor = mocker.Mock()
    mock_conn.cursor.return_value = mock_cursor
    return mock_conn, mock_cursor

@pytest.fixture
def mock_hash_password(mocker):
    """Fixture to mock the password hashing function."""
    return mocker.patch("my_server.hash_password", return_value="hashed_password")

def test_add_user_success(mock_database, mock_hash_password, mocker):
    """Test the scenario when adding a new user is successful."""
    username = "new_user"
    email = "new_user@example.com"
    password = "password123"
    public_key = "public_key_string"

    # Mock database behavior
    mock_conn, mock_cursor = mock_database
    mock_cursor.fetchone.return_value = None  # Simulate no existing user

    # Mock sqlite3.connect to return our mock connection
    mocker.patch("sqlite3.connect", return_value=mock_conn)

    # Call add_user function
    result = add_user(username, email, password, public_key)

    # Assert that no error message is returned (successful user addition)
    assert result is None
    mock_cursor.execute.assert_called_with(
        "INSERT INTO users (username, email, password, public_key) VALUES (?, ?, ?, ?)",
        (username, email, "hashed_password", public_key)
    )
    mock_conn.commit.assert_called_once()

def test_add_user_username_exists(mock_database, mock_hash_password, mocker):
    """Test the scenario when the username already exists."""
    username = "existing_user"
    email = "new_user@example.com"
    password = "password123"
    public_key = "public_key_string"

    # Mock database behavior (simulate existing username)
    mock_conn, mock_cursor = mock_database
    mock_cursor.fetchone.return_value = (username, "existing_user@example.com")  # Simulate that the username already exists

    # Mock sqlite3.connect to return our mock connection
    mocker.patch("sqlite3.connect", return_value=mock_conn)

    # Call add_user function
    result = add_user(username, email, password, public_key)

    # Assert that the username already exists error is returned
    assert result == "This username already exists"

def test_add_user_email_exists(mock_database, mock_hash_password, mocker):
    """Test the scenario when the email already exists."""
    username = "new_user"
    email = "existing_email@example.com"
    password = "password123"
    public_key = "public_key_string"

    # Mock database behavior (simulate existing email)
    mock_conn, mock_cursor = mock_database
    mock_cursor.fetchone.return_value = (None, email)  # Simulate that the email already exists

    # Mock sqlite3.connect to return our mock connection
    mocker.patch("sqlite3.connect", return_value=mock_conn)

    # Call add_user function
    result = add_user(username, email, password, public_key)

    # Assert that the email already exists error is returned
    assert result == "This email already exists"

def test_add_user_integrity_error(mock_database, mock_hash_password, mocker):
    """Test the scenario when there is an integrity error (e.g., duplicate username or email)."""
    username = "new_user"
    email = "new_user@example.com"
    password = "password123"
    public_key = "public_key_string"

    # Mock sqlite3 to raise an IntegrityError (simulate unique constraint violation)
    mock_conn, mock_cursor = mock_database
    mock_cursor.fetchone.return_value = None  # Simulate no existing user
    mocker.patch("sqlite3.connect", return_value=mock_conn)
    mock_cursor.execute.side_effect = sqlite3.IntegrityError("UNIQUE constraint failed")

    # Call add_user function
    result = add_user(username, email, password, public_key)

    # Assert that the integrity error message is returned
    assert result == "Error: A user with this email or username already exists."

def test_add_user_sqlite_error(mock_database, mock_hash_password, mocker):
    """Test the scenario when there is a general SQLite error."""
    username = "new_user"
    email = "new_user@example.com"
    password = "password123"
    public_key = "public_key_string"

    # Mock sqlite3 to raise a general SQLite error
    mock_conn, mock_cursor = mock_database
    mock_cursor.fetchone.return_value = None  # Simulate no existing user
    mocker.patch("sqlite3.connect", return_value=mock_conn)
    mock_cursor.execute.side_effect = sqlite3.Error("Database error")

    # Call add_user function
    result = add_user(username, email, password, public_key)

    # Assert that the SQLite error message is returned
    assert result == "An unexpected error occurred."

def test_add_user_conn_close(mock_database, mock_hash_password, mocker):
    """Test that the connection is closed after adding a new user."""
    username = "new_user"
    email = "new_user@example.com"
    password = "password123"
    public_key = "public_key_string"

    # Mock UNIT_TESTING to ensure it's not True, so the connection should be closed
    mocker.patch("my_server.UNIT_TESTING", False)

    # Mock database behavior (simulate no existing user)
    mock_conn, mock_cursor = mock_database
    mock_cursor.fetchone.return_value = None  # Simulate no existing user

    # Mock sqlite3.connect to return our mock connection
    mocker.patch("sqlite3.connect", return_value=mock_conn)

    # Call add_user function
    add_user(username, email, password, public_key)

    # Check that conn.close() is called after the database operation
    mock_conn.close.assert_called_once()

def test_add_user_conn_not_close_in_unit_testing(mock_database, mock_hash_password, mocker):
    """Test that the connection is NOT closed when UNIT_TESTING is True."""
    username = "new_user"
    email = "new_user@example.com"
    password = "password123"
    public_key = "public_key_string"

    # Mock UNIT_TESTING to True, so the connection should NOT be closed
    mocker.patch("my_server.UNIT_TESTING", True)

    # Mock database behavior (simulate no existing user)
    mock_conn, mock_cursor = mock_database
    mock_cursor.fetchone.return_value = None  # Simulate no existing user

    # Mock sqlite3.connect to return our mock connection
    mocker.patch("sqlite3.connect", return_value=mock_conn)

    # Call add_user function
    add_user(username, email, password, public_key)

    # Check that conn.close() is NOT called when UNIT_TESTING is True
    mock_conn.close.assert_not_called()
