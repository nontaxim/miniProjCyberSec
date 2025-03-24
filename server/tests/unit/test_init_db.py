import sqlite3
import pytest
from pytest_mock import MockerFixture
from my_server import init_db  # Adjust the import based on your project structure

@pytest.fixture
def test_db(mocker: MockerFixture):
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


def test_init_db(test_db):
    """Test if the init_db function creates the users table with the correct columns."""
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
