import pytest
from app.config import Settings
from pydantic import ValidationError


def test_jwt_secret_requires_32_characters():
    with pytest.raises(ValidationError):
        Settings(JWT_SECRET="x" * 31)


def test_jwt_secret_rejects_placeholders():
    with pytest.raises(ValidationError):
        Settings(JWT_SECRET="change_me_to_a_long_random_hex_string")


def test_jwt_secret_accepts_strong_value():
    settings = Settings(JWT_SECRET="x" * 64)
    assert settings.JWT_SECRET == "x" * 64



def test_jwt_algorithm_must_be_hs256():
    with pytest.raises(ValidationError):
        Settings(JWT_SECRET="x" * 64, JWT_ALGORITHM="HS512")


def test_allowed_hosts_rejects_wildcard():
    with pytest.raises(ValidationError):
        Settings(JWT_SECRET="x" * 64, ALLOWED_HOSTS="*")


def test_allowed_hosts_normalizes_values():
    settings = Settings(JWT_SECRET="x" * 64, ALLOWED_HOSTS=" Localhost, 127.0.0.1 ")
    assert settings.ALLOWED_HOSTS == "localhost,127.0.0.1"


def test_allowed_origins_rejects_wildcard():
    with pytest.raises(ValidationError):
        Settings(JWT_SECRET="x" * 64, ALLOWED_ORIGINS="*")


def test_allowed_origins_require_scheme():
    with pytest.raises(ValidationError):
        Settings(JWT_SECRET="x" * 64, ALLOWED_ORIGINS="localhost:8080")


def test_totp_key_requires_32_bytes_hex():
    with pytest.raises(ValidationError):
        Settings(TOTP_ENCRYPTION_KEY="a" * 62)


def test_totp_key_accepts_32_bytes_hex():
    settings = Settings(TOTP_ENCRYPTION_KEY="b" * 64)
    assert settings.TOTP_ENCRYPTION_KEY == "b" * 64
