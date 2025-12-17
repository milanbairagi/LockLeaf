import secrets
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes


def encrypt_data(vault_key: bytes, plaintext: bytes) -> str:
    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(vault_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    encrypted_data = base64.urlsafe_b64encode(nonce + ciphertext).decode()
    return encrypted_data

def decrypt_data(vault_key: bytes, encrypted_data: str) -> bytes:
    decoded_data = base64.urlsafe_b64decode(encrypted_data)
    nonce = decoded_data[:12]
    ciphertext = decoded_data[12:]
    aesgcm = AESGCM(vault_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext