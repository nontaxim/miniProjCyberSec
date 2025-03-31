import os
from unittest.mock import patch
from my_server import get_database_path  # Adjust the import based on your project structure

def test_get_database_path_e2e_test():
    """Test if the correct database path is returned when app_mode is 'e2e_test'."""
    # Mock app_mode to return 'e2e_test'
    with patch("my_server.app_mode", "e2e_test"):
        db_path = get_database_path()
    
    expected_path = os.path.join("e2e_tests", "test_user_data.db")
    assert db_path == expected_path, f"Expected {expected_path}, but got {db_path}"

def test_get_database_path_default():
    """Test if the correct database path is returned when app_mode is not 'e2e_test'."""
    # Mock app_mode to return a non-'e2e_test' value (default behavior)
    with patch("my_server.app_mode", "production"):
        db_path = get_database_path()
    
    expected_path = "user_data.db"
    assert db_path == expected_path, f"Expected {expected_path}, but got {db_path}"
