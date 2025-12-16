from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets
import base64


def encrypt_vault_key(master_key: str) -> str:    
    # Derive a key from the master key using PBKDF2HMAC    
    salt = secrets.token_bytes(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    # Derive a 32-byte key (no encoding) for AESGCM
    derived_key = kdf.derive(master_key.encode())

    # Encrypt a fresh vault key with the derived key
    nonce = secrets.token_bytes(12)  # 96-bit nonce for AES-GCM
    vault_key = secrets.token_bytes(32)
    aesgcm = AESGCM(derived_key)
    ciphertext = aesgcm.encrypt(nonce, vault_key, None)

    # Persist salt + nonce + ciphertext
    encrypted_vault_key = base64.urlsafe_b64encode(salt + nonce + ciphertext).decode()
    return encrypted_vault_key

def decrypt_vault_key(master_key: str, encrypted_vault_key: str) -> bytes:
    decoded_data = base64.urlsafe_b64decode(encrypted_vault_key)
    salt = decoded_data[:16]
    nonce = decoded_data[16:28]
    ciphertext = decoded_data[28:]

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    raw_key = kdf.derive(master_key.encode())

    aesgcm = AESGCM(raw_key)
    vault_key = aesgcm.decrypt(nonce, ciphertext, None)
    return vault_key
