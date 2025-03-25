# End-to-End (E2E) Testing Examples

This document provides examples of E2E test cases for scenarios involving a server and one or more clients.

---

## Test Cases with Separate Server and Client

### Test Case 1: Single Client - Registration
```python
def test_case_1(start_server, client_socket):
  """Test case 1 with a single client."""
  client_socket.send("register".encode())
  response = client_socket.recv(1024).decode()
  assert response == "Please enter OTP"
```

### Test Case 2: Single Client - Login
```python
def test_case_2(start_server, client_socket):
  """Test case 2 with a single client."""
  client_socket.send("login".encode())
  response = client_socket.recv(1024).decode()
  assert response == "Please enter username"
```

---

## Test Case with Multiple Clients

### Test Case: Multiple Clients Interaction
```python
def test_case_with_multiple_clients(start_server):
  """Test case with multiple clients."""
  client1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  client1.connect(('localhost', 5555))

  client2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  client2.connect(('localhost', 5555))

  # Client 1 sends a message
  client1.send("register".encode())
  response1 = client1.recv(1024).decode()
  assert response1 == "Please enter OTP"

  # Client 2 sends a message
  client2.send("login".encode())
  response2 = client2.recv(1024).decode()
  assert response2 == "Please enter username"

  # Close clients
  client1.send("exit".encode())
  client1.close()
  client2.send("exit".encode())
  client2.close()
```

---

### Notes
- Ensure the server is running before executing the test cases.
- Replace `'localhost'` and `5555` with the appropriate server address and port if different.
- Use proper cleanup mechanisms to avoid resource leaks during testing.
- These examples assume the server responds with specific messages like `"Please enter OTP"` and `"Please enter username"`. Adjust assertions as needed based on your server's implementation.