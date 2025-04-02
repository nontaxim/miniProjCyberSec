import sqlite3
from my_server import handle_sqlite_error


# Test case for OperationalError with 'permission denied'
def test_handle_permission_denied_error(mocker):
    """Test SQLite OperationalError with 'permission denied'."""
    error = sqlite3.OperationalError("permission denied")
    
    mock_print = mocker.patch("builtins.print")
    handle_sqlite_error(error)
    mock_print.assert_called_with("Permission error: Check the database file permissions.")


# Test case for OperationalError with 'disk I/O error'
def test_handle_disk_io_error(mocker):
    """Test SQLite OperationalError with 'disk I/O error'."""
    error = sqlite3.OperationalError("disk I/O error")
    
    mock_print = mocker.patch("builtins.print")
    handle_sqlite_error(error)
    mock_print.assert_called_with("Disk I/O error: Check the disk space and I/O status.")


# Test case for other OperationalError
def test_handle_other_operational_error(mocker):
    """Test SQLite OperationalError with other message."""
    error = sqlite3.OperationalError("Some operational error")
    
    mock_print = mocker.patch("builtins.print")
    handle_sqlite_error(error)
    mock_print.assert_called_with(f"Operational error: {error}")


# Test case for IntegrityError
def test_handle_integrity_error(mocker):
    """Test SQLite IntegrityError."""
    error = sqlite3.IntegrityError("Some integrity error")
    
    mock_print = mocker.patch("builtins.print")
    handle_sqlite_error(error)
    mock_print.assert_called_with(f"Integrity error: {error}")


# Test case for ProgrammingError
def test_handle_programming_error(mocker):
    """Test SQLite ProgrammingError."""
    error = sqlite3.ProgrammingError("Some programming error")
    
    mock_print = mocker.patch("builtins.print")
    handle_sqlite_error(error)
    mock_print.assert_called_with(f"Programming error: {error}")


# Test case for DataError
def test_handle_data_error(mocker):
    """Test SQLite DataError."""
    error = sqlite3.DataError("Some data error")
    
    mock_print = mocker.patch("builtins.print")
    handle_sqlite_error(error)
    mock_print.assert_called_with(f"Data error: {error}")


# Test case for DatabaseError
def test_handle_database_error(mocker):
    """Test SQLite DatabaseError."""
    error = sqlite3.DatabaseError("Some database error")
    
    mock_print = mocker.patch("builtins.print")
    handle_sqlite_error(error)
    mock_print.assert_called_with(f"Database error: {error}")


# Test case for unexpected SQLite error
def test_handle_unexpected_sqlite_error(mocker):
    """Test an unexpected SQLite error."""
    error = sqlite3.InterfaceError("An unexpected SQLite error")
    
    mock_print = mocker.patch("builtins.print")
    handle_sqlite_error(error)
    mock_print.assert_called_with(f"Unexpected SQLite error: An unexpected SQLite error")


# Test case for an unexpected error type (not an SQLite error)
def test_handle_unexpected_error_type(mocker):
    """Test a non-SQLite error."""
    class CustomError(Exception):
        pass

    error = CustomError("An unexpected error occurred")
    
    mock_print = mocker.patch("builtins.print")
    handle_sqlite_error(error)
    mock_print.assert_called_with(f"Unexpected SQLite error: {error}")
