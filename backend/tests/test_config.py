import pytest
from pydantic import ValidationError

from app.config import Settings


def test_jwt_secret_requires_32_characters():
    with pytest.raises(ValidationError):
        Settings(JWT_SECRET="x" * 31)


def test_jwt_secret_rejects_placeholders():
    with pytest.raises(ValidationError):
        Settings(JWT_SECRET="change_me_to_a_long_random_hex_string")


def test_jwt_secret_accepts_strong_value():
    settings = Settings(JWT_SECRET="x" * 64)
    assert settings.JWT_SECRET == "x" * 64


def test_totp_key_requires_32_bytes_hex():
    with pytest.raises(ValidationError):
        Settings(TOTP_ENCRYPTION_KEY="a" * 62)


def test_totp_key_accepts_32_bytes_hex():
    settings = Settings(TOTP_ENCRYPTION_KEY="b" * 64)
    assert settings.TOTP_ENCRYPTION_KEY == "b" * 64
