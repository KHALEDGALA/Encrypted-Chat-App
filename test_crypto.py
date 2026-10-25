
from crypto_utils import (
    load_or_create_key,
    encrypt_message,
    decrypt_message,
)

key = load_or_create_key()

original = "Hello from the encrypted chat!"
encrypted = encrypt_message(original, key)
decrypted = decrypt_message(encrypted, key)

print("Original:", original)
print("Encrypted bytes:", encrypted.hex())
print("Decrypted:", decrypted)

assert decrypted == original
print("Encryption test passed!")
 