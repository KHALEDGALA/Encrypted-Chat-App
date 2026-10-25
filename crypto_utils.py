
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_FILE = "chat.key"


def load_or_create_key():
    """Load a 32-byte key, or create one for local testing."""
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as file:
            key = file.read()

        if len(key) != 32:
            raise ValueError("chat.key must contain exactly 32 bytes.")

        return key

    key = AESGCM.generate_key(bit_length=256)

    with open(KEY_FILE, "xb") as file:
        file.write(key)

    return key


def encrypt_message(message, key):
    """Encrypt UTF-8 text and return nonce + ciphertext."""
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)

    ciphertext = aesgcm.encrypt(
        nonce,
        message.encode("utf-8"),
        None
    )

    return nonce + ciphertext


def decrypt_message(data, key):
    """Decrypt nonce + ciphertext and verify its authentication tag."""
    if len(data) < 12 + 16:
        raise ValueError("Encrypted message is too short.")

    nonce = data[:12]
    ciphertext = data[12:]

    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    return plaintext.decode("utf-8")
