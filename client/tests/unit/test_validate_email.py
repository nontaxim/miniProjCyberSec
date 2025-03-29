from client import validate_email

def test_valid_email():
    # Valid email addresses
    valid_emails = [
        "test@example.com",
        "user.name+tag@example.co.uk",
        "user123@example.com",
        "first.last@subdomain.example.com"
    ]
    
    for email in valid_emails:
        assert validate_email(email) is True, f"Failed to validate valid email: {email}"

def test_invalid_email():
    # Invalid email addresses
    invalid_emails = [
        "plainaddress",                  # No @ symbol
        "@missingusername.com",          # Missing username part
        "missingdomain@.com",            # Missing domain name
        "user@com",                      # Incomplete domain part
        "user@domain@domain.com",        # Multiple @ symbols
        "user@domain,com",               # Invalid character (comma instead of dot)
        "user@.com",                     # Invalid domain starting with a dot
        "user@domain#example.com",       # Invalid character (#) in domain
    ]
    
    for email in invalid_emails:
        assert validate_email(email) is False, f"Failed to invalidate email: {email}"
