import os
import secrets
import base64
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from jose import jwt
from datetime import datetime, timedelta, timezone
from ..config import settings

ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)

LOCKOUT_THRESHOLD = 5
LOCKOUT_BASE_MINUTES = 1
LOCKOUT_MAX_MINUTES = 60


def lockout_duration_minutes(failed_attempts: int) -> int:
    """Progressive backoff: doubles each failure past the threshold, capped."""
    excess = failed_attempts - LOCKOUT_THRESHOLD + 1
    return min(LOCKOUT_BASE_MINUTES * (2 ** (excess - 1)), LOCKOUT_MAX_MINUTES)


def hash_password(password: str) -> str:
    return ph.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return ph.verify(hashed, plain)
    except Exception:
        return False


def generate_salt() -> bytes:
    return secrets.token_bytes(16)


def derive_kek(master_password: str, salt: bytes) -> bytes:
    """Derive a 32-byte key-encryption-key from the master password."""
    from argon2.low_level import hash_secret_raw, Type
    raw = hash_secret_raw(
        secret=master_password.encode(),
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=2,
        hash_len=32,
        type=Type.ID,
    )
    return raw


def encrypt(data: bytes, key: bytes) -> dict:
    nonce = secrets.token_bytes(12)
    ct = AESGCM(key).encrypt(nonce, data, None)
    return {"ciphertext": base64.b64encode(ct).decode(), "nonce": base64.b64encode(nonce).decode()}


def decrypt(ciphertext_b64: str, nonce_b64: str, key: bytes) -> bytes:
    ct = base64.b64decode(ciphertext_b64)
    nonce = base64.b64decode(nonce_b64)
    return AESGCM(key).decrypt(nonce, ct, None)


def create_access_token(subject: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": subject,
        "iat": now,
        "exp": now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
        "type": "access",
        "jti": secrets.token_hex(16),
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def create_refresh_token(subject: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": subject,
        "iat": now,
        "exp": now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
        "type": "refresh",
        "jti": secrets.token_hex(16),
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def verify_token(token: str, expected_type: str = "access") -> str:
    """Returns user id (sub) if valid, else raises."""
    from jose import JWTError
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
        if payload.get("type") != expected_type:
            raise ValueError("wrong token type")
        return payload["sub"]
    except JWTError as e:
        raise ValueError("invalid token") from e
