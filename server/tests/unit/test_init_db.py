import sqlite3
import pytest
from unittest.mock import MagicMock
from my_server import init_db, handle_sqlite_error

@pytest.fixture
def test_db(mocker):
    """Fixture to create an in-memory SQLite database."""
    # Create an in-memory database for testing
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()

    # Create the users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            public_key TEXT NOT NULL
        );
    """)
    conn.commit()

    # Patch sqlite3.connect to return this test database
    mocker.patch("sqlite3.connect", return_value=conn)

    yield conn  # This will be the connection used in the test

    # Cleanup
    conn.close()

def test_init_db_success(test_db, mocker):
    """Test if the init_db function creates the users table successfully."""
    # Call the init_db function
    init_db()  # This should create the table in the in-memory database

    # Check if the 'users' table exists
    cursor = test_db.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users';")
    result = cursor.fetchone()

    assert result is not None, "The 'users' table should be created."
    assert result[0] == "users", "The 'users' table should be named 'users'."

    # Check the columns of the 'users' table
    cursor.execute("PRAGMA table_info(users);")
    columns = cursor.fetchall()

    # List of expected columns in the 'users' table
    expected_columns = ['id', 'username', 'email', 'password', 'public_key']

    # Check if the columns match the expected columns
    actual_columns = [column[1] for column in columns]  # Extract column names from PRAGMA result

    assert sorted(actual_columns) == sorted(expected_columns), "The 'users' table columns are incorrect."

    # Optionally, check the column types as well
    expected_column_types = ['INTEGER', 'TEXT', 'TEXT', 'TEXT', 'TEXT']
    actual_column_types = [column[2] for column in columns]  # Extract column types

    assert sorted(actual_column_types) == sorted(expected_column_types), "The column types in 'users' table are incorrect."

def test_init_db_sqlite_error(mocker):
    """Test the scenario when there is an SQLite error while initializing the database."""
    # Mock sqlite3.connect to raise an error
    mock_connect = mocker.patch("sqlite3.connect", side_effect=sqlite3.Error("Database connection error"))
    
    # Mock handle_sqlite_error to verify if it is called
    mock_handle_error = mocker.patch("my_server.handle_sqlite_error", autospec=True)

    # Call init_db, which should now raise an SQLite error
    init_db()

    # Assert that handle_sqlite_error is called when an SQLite error occurs
    mock_handle_error.assert_called_once_with(mock_connect.side_effect)

def test_init_db_conn_close(test_db, mocker):
    """Test that the connection is closed after initializing the database."""
    # Mock UNIT_TESTING to ensure it's not True, so the connection should be closed
    mocker.patch("my_server.UNIT_TESTING", False)

    # Create a mock for sqlite3.connect to track the connection close
    mock_conn = mocker.MagicMock()
    mocker.patch("sqlite3.connect", return_value=mock_conn)

    # Call the init_db function
    init_db()

    # Check that conn.close() is called after the database initialization
    mock_conn.close.assert_called_once()

def test_init_db_conn_not_close_in_unit_testing(test_db, mocker):
    """Test that the connection is NOT closed when UNIT_TESTING is True."""
    # Mock UNIT_TESTING to True, so the connection should NOT be closed
    mocker.patch("my_server.UNIT_TESTING", True)

    # Create a mock for sqlite3.connect to track the connection close
    mock_conn = mocker.MagicMock()
    mocker.patch("sqlite3.connect", return_value=mock_conn)

    # Call the init_db function
    init_db()

    # Check that conn.close() is NOT called when UNIT_TESTING is True
    mock_conn.close.assert_not_called()
