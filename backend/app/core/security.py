import secrets
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError
import jwt
from datetime import datetime, timedelta, timezone
from ..config import settings

ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)
# Argon2 verification for unknown accounts keeps login cost comparable to a real user.
DUMMY_AUTH_HASH = ph.hash("vaultlocal-dummy-login-value")

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
    except VerificationError:
        return False


def create_access_token(subject: str, session_id: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": subject,
        "sid": session_id,
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


def _subject_from_payload(payload: dict, expected_type: str) -> str:
    if payload.get("type") != expected_type:
        raise ValueError("wrong token type")
    subject = payload.get("sub")
    if not isinstance(subject, str) or not subject:
        raise ValueError("token missing subject")
    return subject


def verify_token(token: str, expected_type: str = "access") -> str:
    """Returns user id (sub) if valid, else raises."""
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
        return _subject_from_payload(payload, expected_type)
    except jwt.InvalidTokenError as e:
        raise ValueError("invalid token") from e


def verify_access_token(token: str) -> tuple[str, str]:
    """Returns (user id, session id) for a live access-token format."""
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
        subject = _subject_from_payload(payload, "access")
        session_id = payload.get("sid")
        if not isinstance(session_id, str) or not session_id:
            raise ValueError("access token missing session id")
        return subject, session_id
    except jwt.InvalidTokenError as e:
        raise ValueError("invalid token") from e
