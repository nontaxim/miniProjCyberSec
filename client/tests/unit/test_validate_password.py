from client import validate_password 

# Test case when the password is too short
def test_password_too_short() -> None:
    result: bool = validate_password("short1")
    assert result is False, "Password must be at least 8 characters long."

# Test case when the password doesn't contain a number
def test_password_no_number() -> None:
    result: bool = validate_password("NoNumber!")
    assert result is False, "Password must contain at least one number."

# Test case when the password doesn't contain an uppercase letter
def test_password_no_uppercase() -> None:
    result: bool = validate_password("lowercase1!")
    assert result is False, "Password must contain at least one uppercase letter."

# Test case when the password doesn't contain a lowercase letter
def test_password_no_lowercase() -> None:
    result: bool = validate_password("UPPERCASE1!")
    assert result is False, "Password must contain at least one lowercase letter."

# Test case when the password doesn't contain a special character
def test_password_no_special_char() -> None:
    result: bool = validate_password("NoSpecial123")
    assert result is False, "Password must contain at least one special character."

# Test case when the password is valid
def test_valid_password() -> None:
    result: bool = validate_password("ValidPass123!")
    assert result is True, "Valid password should return True"

# Test case when the password contains spaces
def test_password_with_space() -> None:
    result: bool = validate_password("Password with space1!")
    assert result is False, "Password must not contain spaces."