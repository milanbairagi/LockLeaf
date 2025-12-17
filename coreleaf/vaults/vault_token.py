import time, jwt, base64
from django.conf import settings
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import hashlib


def issue_vault_unlock_token(user_id: int, vault_key: bytes, ttl_second: int = 900) -> str:
    """Issue a short-lived JWT with encrypted vault_key embedded."""
    now = int(time.time())
    
    # Encrypt vault_key with server secret for embedding in JWT
    server_key = hashlib.sha256(settings.VAULT_UNLOCK_SECRET.encode()).digest()
    nonce = b"\x00" * 12  # Fixed nonce OK since each JWT is unique (exp/iat differ)
    aesgcm = AESGCM(server_key)
    encrypted_vault_key = aesgcm.encrypt(nonce, vault_key, None)
    
    payload = {
        "user_id": user_id,
        "vault_key": base64.urlsafe_b64encode(encrypted_vault_key).decode(),
        "exp": now + ttl_second,
        "iat": now,
    }
    token = jwt.encode(payload, settings.VAULT_UNLOCK_SECRET, algorithm="HS256")
    return token


def verify_vault_unlock_token(token: str) -> tuple[int, bytes] | tuple[None, None]:
    """Verify JWT and return (user_id, decrypted_vault_key) or (None, None)."""
    try:
        payload = jwt.decode(token, settings.VAULT_UNLOCK_SECRET, algorithms=["HS256"])
        user_id = payload.get("user_id")
        encrypted_vault_key_b64 = payload.get("vault_key")
        
        if not user_id or not encrypted_vault_key_b64:
            return None, None
        
        # Decrypt vault_key
        server_key = hashlib.sha256(settings.VAULT_UNLOCK_SECRET.encode()).digest()
        nonce = b"\x00" * 12
        aesgcm = AESGCM(server_key)
        encrypted_vault_key = base64.urlsafe_b64decode(encrypted_vault_key_b64)
        vault_key = aesgcm.decrypt(nonce, encrypted_vault_key, None)
        
        return user_id, vault_key
    except jwt.ExpiredSignatureError:
        return None, None
    except jwt.InvalidTokenError:
        return None, None
    except Exception:
        return None, None