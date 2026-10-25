
# Encrypted Chat App

A Python-based TCP chat application built for learning socket programming, multithreading, and AES-256-GCM authenticated encryption.

## Features

- TCP client-server communication
- Multiple client connections
- AES-256-GCM message encryption
- Length-prefixed message framing
- Basic username and chat notifications (in development)

## Technologies

- Python
- TCP Sockets
- Threading
- Cryptography library

## Requirements

- Python 3.13 or compatible Python version
- pip

## Installation

Clone the repository:

```bash
git clone YOUR_REPOSITORY_URL
cd Encrypted-Chat-App
```

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

## Running

Start the server in one terminal:

```bash
python server.py
```

Start a client in another terminal:

```bash
python client.py
```

The current server is configured for local testing using `127.0.0.1`.

## Security Notes

This project is an educational prototype, not production-ready secure messaging software.

The current design uses a shared local encryption key. Secure key distribution, user authentication, and transport security require further work.

Never commit `chat.key` or other secret credentials.
