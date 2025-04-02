import pytest
import sqlite3
from unittest import mock
from my_server import get_public_key, handle_sqlite_error, get_database_path

@pytest.fixture
def mock_database():
    """Mock the database connection and cursor."""
    mock_conn = mock.Mock()
    mock_cursor = mock.Mock()
    mock_conn.cursor.return_value = mock_cursor
    return mock_conn, mock_cursor

def test_get_public_key_found(mock_database):
    """Test when the public key is found in the database."""
    username = "test_user"
    expected_public_key = "public_key_string"

    # Mock database behavior
    mock_conn, mock_cursor = mock_database
    mock_cursor.fetchone.return_value = [expected_public_key]  # Simulate that a result was found

    # Mock sqlite3.connect to return our mock connection
    with mock.patch("sqlite3.connect", return_value=mock_conn):
        public_key = get_public_key(username)
    
    # Assert that the public key was returned
    assert public_key == expected_public_key

def test_get_public_key_not_found(mock_database):
    """Test when the public key is not found in the database."""
    username = "test_user"

    # Mock database behavior
    mock_conn, mock_cursor = mock_database
    mock_cursor.fetchone.return_value = None  # Simulate no result

    # Mock sqlite3.connect to return our mock connection
    with mock.patch("sqlite3.connect", return_value=mock_conn):
        public_key = get_public_key(username)

    # Assert that None is returned when no public key is found
    assert public_key is None

def test_get_public_key_sqlite_error(mock_database):
    """Test when a sqlite3.Error occurs."""
    username = "test_user"

    # Mock database behavior
    mock_conn, mock_cursor = mock_database
    mock_cursor.execute.side_effect = sqlite3.Error("Database error")  # Simulate a database error

    # Mock sqlite3.connect to return our mock connection
    with mock.patch("sqlite3.connect", return_value=mock_conn), mock.patch("my_server.handle_sqlite_error") as mock_handle_sqlite_error:
        public_key = get_public_key(username)
    
    # Assert that None is returned on error and error handler is called
    assert public_key is None
    mock_handle_sqlite_error.assert_called_once()

def test_get_public_key_unit_testing_flag(mock_database):
    """Test the UNIT_TESTING flag to ensure connection is not closed."""
    username = "test_user"
    expected_public_key = "public_key_string"

    # Mock database behavior
    mock_conn, mock_cursor = mock_database
    mock_cursor.fetchone.return_value = [expected_public_key]  # Simulate that a result was found

    # Set UNIT_TESTING to True
    global UNIT_TESTING
    UNIT_TESTING = True

    # Mock sqlite3.connect to return our mock connection
    with mock.patch("sqlite3.connect", return_value=mock_conn):
        public_key = get_public_key(username)

    # Assert that the public key was returned and the connection is not closed
    assert public_key == expected_public_key
    mock_conn.close.assert_not_called()

def test_get_public_key_without_unit_testing_flag(mock_database, mocker):
    """Test the connection close behavior when UNIT_TESTING is False."""
    username = "test_user"
    expected_public_key = "public_key_string"

    # Mock database behavior
    mock_conn, mock_cursor = mock_database
    mock_cursor.fetchone.return_value = [expected_public_key]  # Simulate that a result was found

    # Mock UNIT_TESTING to be False
    mocker.patch("my_server.UNIT_TESTING", False)

    # Mock sqlite3.connect to return our mock connection
    mocker.patch("sqlite3.connect", return_value=mock_conn)
    
    public_key = get_public_key(username)

    # Assert that the public key was returned and the connection was closed
    assert public_key == expected_public_key
    mock_conn.close.assert_called_once()  # Check if close() was called exactly once