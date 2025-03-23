from my_server import generate_challenge

def test_generate_challenge() -> None:
    """
    Test that the generate_challenge function creates a valid challenge for a given username.

    :return: None
    """
    username: str = "test_user"  # Define the username as a string
    challenge: str = generate_challenge(username)  # Define challenge as a string
    
    # Ensure the challenge is a string and has a length of 64 (32 bytes in hex format)
    assert isinstance(challenge, str)
    assert len(challenge) == 64  # 32 bytes in hex format
