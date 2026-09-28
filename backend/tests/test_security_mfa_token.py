import os

os.environ.setdefault("JWT_SECRET", "test-secret-not-for-prod-0123456789ab")

import pytest

from app.core.security import create_mfa_token, verify_token


def test_create_mfa_token_verifies_as_mfa_pending():
    token = create_mfa_token("user-123")
    assert verify_token(token, "mfa_pending") == "user-123"


def test_mfa_token_rejected_as_access_token():
    token = create_mfa_token("user-123")
    with pytest.raises(ValueError):
        verify_token(token, "access")
