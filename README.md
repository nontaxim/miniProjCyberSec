# Mini Project Topic: Secure Chat (CLI)

secure messaging system that allows clients to register, log in, send encrypted messages to each other, and verify message authenticity using encryption and digital signatures. The server acts as an intermediary, handling registration, authentication, and message forwarding between clients. It focuses on security, utilizing public key cryptography (RSA), multi-factor authentication (password + signed message), and network communication via sockets.

## Table of Contents

1. [Set up](#set-up)
2. [Tests](#tests)
   - [Running Tests for the Server](#running-tests-for-the-server)
   - [Running Tests for the Client](#running-tests-for-the-client)
3. [Naming Conventions](#naming-conventions)
4. [How it works](#how-its-work)
   - [Server-Side](#server-side)
   - [Client-Side](#client-side)
5. [Testing tools](#testing-tools)
   - [Unit testing](#unit-testing)
   - [E2E testing](#e2e-testing)
   - [Mocking](#mocking)
   - [Security testing](#security-testing)
   - [Load & Stress testing](#load--stress-testing)
6. [Relevant Topics](#relevant-topics)
   - [Encryption (RSA)](#encryption-rsa)
   - [Authentication](#authentication)
   - [Networking](#networking)

## Set up

To run your project in a Python environment, follow these steps to set up the virtual environment and install the required dependencies:

### 1. Activate the Virtual Environment

The virtual environment isolates your project’s dependencies, making sure you don't have conflicts with other Python projects on your machine.

- **On Windows**, run:

```bash
.\venv\Scripts\activate
```

- **On Mac/Linux**, run:

```bash
source venv/bin/activate
```

### 2. Install Dependencies from requirements.txt

Once the virtual environment is activated, you'll need to install the necessary Python packages that your project depends on. These packages are listed in the `requirements.txt` file.
Run this command:

```bash
pip install -r requirements.txt
```

This will install all the packages listed in the requirements.txt file.

### 3. Run Your Project

After setting up the environment and installing the dependencies, you can run your project by following the instructions for running the server or client.

```bash
cd server ; python server.py
```

or

```bash
cd client ; python client.py
```

depending on which part of the project you want to execute.

### 4. Deactivating the Virtual Environment

Once you're done working in the virtual environment, you can deactivate it by running:

```bash
deactivate
```

This will return you to the global Python environment.

## How to run Tests

This project is divided into two main parts: the **client** and the **server**. Each part has its own set of tests and coverage reports.

To run tests and view the coverage reports for both client and server, follow the instructions below.

### Running Tests for the Server

#### 1. Navigate to the server directory:

```bash
cd server
```

#### 2. Run the tests for the server:

```bash
pytest tests
```

This will run all tests in the server/tests folder and generate the coverage report.

#### 3. Viewing the Server Coverage Report:

After running the tests, the coverage report will be generated in the htmlcov directory. To view the report:

**On Windows**:  
 In PowerShell, run:

```powershell
start .\htmlcov\index.html
```

This will open the report in your default web browser.

**On macOS**:  
 In the Terminal, run:

```bash
open htmlcov/index.html
```

This will open the report in your default web browser.

### Running Tests for the Client

#### 1. Navigate to the client directory:

```bash
cd client
```

#### 2. Run the tests for the client:

```bash
pytest tests
```

This will run all tests in the client/tests folder and generate the coverage report.

#### 3. Viewing the Server Coverage Report:

After running the tests, the coverage report will be generated in the htmlcov directory. To view the report:

**On Windows**:  
 In PowerShell, run:

```powershell
start .\htmlcov\index.html
```

This will open the report in your default web browser.

**On macOS**:  
 In the Terminal, run:

```bash
open htmlcov/index.html
```

This will open the report in your default web browser.

### Terminal Output Report

In addition to the HTML report, the coverage report will also be printed in the terminal, giving you an overview of the test coverage directly in your command line

## Naming Conventions

This project follows common Python naming conventions to ensure code readability and consistency. Below are the naming guidelines adopted for this project:

### 1. Variable and Function Names

- Format: snake_case
- All variable names and function names are written in lowercase letters, with words separated by underscores.

### 2. Class Names

- Format: PascalCase (also known as UpperCamelCase)
- Class names begin with a capital letter, and each subsequent word is capitalized.

### 3. Constants

- Format: UPPERCASE_SNAKE_CASE
- Constants are written in all uppercase letters, with words separated by underscores.

### 4. Private Variables/Functions

- Format: \_snake_case
- Private variables or functions (intended for internal use only) begin with a single underscore to indicate they should not be accessed directly outside of the class or module.

## How it's work?

### Server-Side

#### 1. Setup Server (server.py):

- Purpose: Set up the server to handle multiple client connections, use threads to handle simultaneous requests, and manage communication.
- Responsibilities:
  - Set up a socket server with threading.
  - Accept incoming client connections.
  - Manage communication with clients (send and receive messages).

#### 2. Handle Client Registration:

- Purpose: Allow clients to register by providing their username, email, password and public key.
- Responsibilities:
  - Receive the client’s username, email, password, and public_key.
  - Generate and send OTP using Google Authenticator or another OTP method.
  - Verify OTP received from the client.
  - Store the client’s username, email, password, and public_key
  - Send a response back to the client after successful registration.

#### 3. Handle Client Login:

- Purpose: Authenticate clients with a challenge-response system, using RSA encryption and signing.
- Responsibilities:
  - Send a challenge message to the client (a random message that needs to be signed by the client).
  - Receive the signed challenge message from the client (Something you have).
  - Verify the signature using the client’s public key
  - Receive password from the client (Something you know).
  - Return success/failure response to the client.

#### 4. Handle Public Key Requests:

- Purpose: Allow a client to request the public key of another user (needed for encrypting messages).
- Responsibilities:
  - Receive a target username from the requesting client.
  - Retrieve the public key of the requested user from the server's stored data.
  - Send the public key back to the requesting client.

#### 5. Handle Client Send Message:

- Purpose: Receive encrypted messages from one client and forward them to the intended recipient.
- Responsibilities:
  - Receive a message that includes the sender’s username, target username, encrypted message, and the signature of the encrypted message.
  - send everything to target user

### Client-Side

#### 1. Generate RSA Key Pair (generate_RSA_key()):

- Purpose: Generate a public/private key pair for encryption and signing.
- Responsibilities:
  - Generate an RSA key pair for both encryption and signing (private key for signing and private/public for encryption).
  - Store the keys in a local file for use during login and message sending.

#### 2. Encrypt Message (encrypt_message()):

- Purpose: Encrypt a message with the target client’s public key.
- Responsibilities:
  - Use the recipient's public key to encrypt the message.
  - Send the encrypted message to the server.

#### 3. Sign Message (signed_message()):

- Purpose: Sign the encrypted message using the client’s private key.
- Responsibilities:
  - Use the client’s public key to sign the encrypted message, ensuring authenticity and integrity.
  - Send the signed message along with the encrypted message to the server.

#### 4. Register Client (register_client()):

- Purpose: Register the client with the server.
- Responsibilities:
  - Send username, email, and public_key to the server for registration.
  - Generate OTP and send it to the server for verification.
  - Once registration is complete, the client is able to send and receive messages.

#### 5. Login Client (login_client()):

- Purpose: Handle client login using challenge-response authentication.
- Responsibilities:
  - Receive a challenge message from the server.
  - Sign the challenge message using the client’s private key.
  - Send the signed challenge message to the server for verification & send password.

#### 6. Request Public Key (request_public_key()):

- Purpose: Request the public key of a target client.
- Responsibilities:
  - Send the target client’s username to the server.
  - Receive the public key of the target client from the server.

#### 7. Send Message (send_message()):

- Purpose: Encrypt and send a message to a target client.
- Responsibilities:
  - Request the target client’s public key from the server.
  - Encrypt the message using the public key.
  - Sign the encrypted message with the client’s private key.
  - Send the encrypted and signed message to the server for forwarding to the recipient.

#### 8. Receive Message (receive_message()):

- Purpose: Receive a message from another client.
- Responsibilities:
  - Retrieve the target client’s public key from the server.
  - Verify the signature of the received message using the sender’s public key.
  - If the signature is valid, decrypt the message using the client’s private key and display it.

## Testing tools

### Unit testing

- [pytest](https://docs.pytest.org/en/stable/contents.html)

### E2E testing

#### Prerequisites

Before running E2E tests, ensure that you have the following tools installed and configured:
**MailHog**: A mock email server used to capture OTPs during testing.
- **Installation**:

  - **macOS (via Homebrew)**:
    ```bash
    brew install mailhog
    ```
  - **Linux/Windows**:
    Download the binary from [MailHog Releases](https://github.com/mailhog/MailHog/releases) and run it.

- **Usage**:

  - Start MailHog:
    ```bash
    mailhog
    ```
  - MailHog will listen on:
    - SMTP: `localhost:1025`
    - Web UI: `http://localhost:8025`

- **Verify**:

  - Open `http://localhost:8025` in your browser to ensure MailHog is running.

- [pytest-subprocess](https://pytest-subprocess.readthedocs.io/en/latest/)

### Mocking

- [pytest-mock](https://pytest-mock.readthedocs.io/en/latest/)

### Security testing

- [bandit](https://github.com/PyCQA/bandit)

### Load & Stress testing

- [Locust](https://docs.locust.io/en/stable/)

## Relevant Topics

### 1. Encryption (RSA):

- Encryption:
- RSA encryption and decryption (asymmetric encryption).
- Using public/private key pairs for encryption and signing messages.

### 2. Authentication

- Multi-factor authentication (MFA)
  - Challenge-response authentication with RSA signing (Something You Have)
  - password (Something You Know)

### 3. Networking:

- Socket
