import pytest
from pytest_mock import MockerFixture
from my_server import recv_all  # Adjust the import path according to your project structure

@pytest.fixture
def mock_socket(mocker: MockerFixture):
    """Fixture to mock the client_socket."""
    # Mock the client socket
    mock_socket = mocker.MagicMock()
    return mock_socket

def test_recv_all_single_chunk(mock_socket):
    """Test the recv_all function when data is received in a single chunk."""
    # Simulate the behavior of recv to return the data in one go
    mock_socket.recv.side_effect = [b"Hello, World!"]

    # Call the function under test
    result = recv_all(mock_socket)

    # Assert that the result is the concatenated string
    assert result == "Hello, World!", f"Expected 'Hello, World!', but got {result}"

def test_recv_all_multiple_chunks(mock_socket):
    """Test the recv_all function when data is received in multiple chunks."""
    # Simulate receiving data in multiple chunks
    mock_socket.recv.side_effect = [b"Hello", b", ", b"World", b"!!", b""]  # Adding an empty byte string for the end

    # Call the function under test with a buffer size of 2
    result = recv_all(mock_socket, buffer_size=2)

    # Assert that the result is the concatenated string
    assert result == "Hello, World!!", f"Expected 'Hello, World!!', but got {result}"


def test_recv_all_end_of_data(mock_socket):
    """Test the recv_all function when no more data is available."""
    # Simulate receiving data in chunks with the last chunk being smaller than buffer size
    mock_socket.recv.side_effect = [b"Hello, ", b"World", b"!"]

    # Call the function under test with a buffer size of 2
    result = recv_all(mock_socket, buffer_size=2)

    # Assert that the result is the concatenated string
    assert result == "Hello, World!", f"Expected 'Hello, World!', but got {result}"

def test_recv_all_empty(mock_socket):
    """Test the recv_all function when no data is received."""
    # Simulate no data being received
    mock_socket.recv.side_effect = [b""]

    # Call the function under test
    result = recv_all(mock_socket)

    # Assert that the result is an empty string
    assert result == "", f"Expected '', but got {result}"
