import os

os.environ.setdefault("JWT_SECRET", "test-secret-not-for-prod-0123456789ab")
os.environ.setdefault("TOTP_ENCRYPTION_KEY", "a" * 64)

from datetime import datetime, timedelta, timezone

import jwt as jose_jwt
import pytest
from app.core.security import (
    create_access_token,
    create_mfa_token,
    settings,
    verify_access_token,
    verify_token,
)


def test_create_mfa_token_verifies_as_mfa_pending():
    token = create_mfa_token("user-123")
    assert verify_token(token, "mfa_pending") == "user-123"


def test_mfa_token_rejected_as_access_token():
    token = create_mfa_token("user-123")
    with pytest.raises(ValueError):
        verify_token(token, "access")


def test_access_token_carries_session_id():
    token = create_access_token("user-123", "session-456")
    assert verify_access_token(token) == ("user-123", "session-456")


def test_legacy_access_token_without_session_id_is_rejected():
    token = jose_jwt.encode(
        {
            "sub": "user-123",
            "iat": datetime.now(timezone.utc),
            "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
            "type": "access",
        },
        settings.JWT_SECRET,
        algorithm=settings.JWT_ALGORITHM,
    )
    with pytest.raises(ValueError):
        verify_access_token(token)


def test_access_token_without_subject_is_rejected():
    token = jose_jwt.encode(
        {
            "iat": datetime.now(timezone.utc),
            "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
            "type": "access",
            "sid": "session-123",
        },
        settings.JWT_SECRET,
        algorithm=settings.JWT_ALGORITHM,
    )
    with pytest.raises(ValueError):
        verify_access_token(token)
