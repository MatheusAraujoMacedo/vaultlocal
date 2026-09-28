import secrets
from argon2 import PasswordHasher
import jwt
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


def create_mfa_token(subject: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": subject,
        "iat": now,
        "exp": now + timedelta(minutes=5),
        "type": "mfa_pending",
        "jti": secrets.token_hex(16),
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def verify_token(token: str, expected_type: str = "access") -> str:
    """Returns user id (sub) if valid, else raises."""
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
        if payload.get("type") != expected_type:
            raise ValueError("wrong token type")
        return payload["sub"]
    except jwt.InvalidTokenError as e:
        raise ValueError("invalid token") from e
