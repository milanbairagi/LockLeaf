import time, jwt
from django.conf import settings


def issue_vault_unlock_token(user_id: int, ttl_second: int = 900) -> str:
    now = int(time.time())
    payload = {
        "user_id": user_id,
        "exp": now + ttl_second,
        "iat": now,
    }
    token = jwt.encode(payload, settings.VAULT_UNLOCK_SECRET, algorithm="HS256")
    return token


def verify_vault_unlock_token(token: str) -> int | None:
    try:
        payload = jwt.decode(token, settings.VAULT_UNLOCK_SECRET, algorithms=["HS256"])
        return payload.get("user_id")
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None