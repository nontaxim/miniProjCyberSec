import pytest
import sqlite3
from pytest_mock import MockerFixture
from my_server import verify_user  # Adjust import according to your project structure

@pytest.fixture
def mock_hash(mocker: MockerFixture) -> None:
    """Mock the hash function to return the same password as the input received."""
    def side_effect(password: str, salt: str) -> str:
        return password  # Return the password as-is, ignoring the salt
    
    # Patch the hash_password function to use the side effect
    mocker.patch("my_server.hash_password", side_effect=side_effect)

# Fixture to create an in-memory SQLite database
@pytest.fixture
def test_db(mocker: MockerFixture):
    """Fixture to create an in-memory SQLite database for testing."""
    conn = sqlite3.connect(":memory:")  # Use an in-memory database
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            public_key TEXT NOT NULL
        )
    """)
    conn.commit()

    # Patch sqlite3.connect to return this test database
    mocker.patch("sqlite3.connect", return_value=conn)

    yield conn  # Provide the connection to the test

    conn.close()  # Cleanup after the test

@pytest.fixture
def populate_db(test_db):
    """Inserts a test user into the in-memory SQLite database for login tests."""
    cursor = test_db.cursor()

    cursor.execute("""
        INSERT INTO users (username, password, public_key, email)
        VALUES (?, ?, ?, ?)
    """, ("test_user", "SecurePass123!", "mocked_public_key", "test@example.com"))

    test_db.commit()  # Ensure changes are committed to the in-memory database


def test_verify_user_valid_credentials(test_db, populate_db, mock_hash):
    """Test the case where the username and password are correct."""
    username = "test_user"
    password = "SecurePass123!"
    salt = b""  # Salt should be bytes, not string
    
    # Call the function under test
    result = verify_user(username, password, salt)
    
    # Debug print statements to check the actual return values
    print(f"Result: {result}")
    
    # Assert the result is True (valid credentials)
    assert result is True

def test_verify_user_invalid_password(test_db, populate_db, mock_hash):
    """Test the case where the password is incorrect."""
    username = "test_user"
    password = "incorrect_password"
    salt = b""  # Salt should be bytes, not string
        
    # Call the function under test
    result = verify_user(username, password, salt)

    # Assert the result is False (incorrect password)
    assert result is False

def test_verify_user_non_existent_user(test_db, populate_db, mock_hash):
    """Test the case where the username doesn't exist."""
    username = "non_existent_user"
    password = "password"
    salt = b""  # Salt should be bytes, not string

    # Call the function under test
    result = verify_user(username, password, salt)

    # Assert the result is False (user does not exist)
    assert result is False

def test_verify_user_empty_username(test_db, populate_db, mock_hash):
    """Test the case where the username is empty."""
    username = ""
    password = "password"
    salt = b""  # Salt should be bytes, not string
    
    # Call the function under test
    result = verify_user(username, password, salt)

    # Assert the result is False (empty username should fail)
    assert result is False
