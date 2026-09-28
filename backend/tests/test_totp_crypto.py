import os

os.environ.setdefault("JWT_SECRET", "test-secret-not-for-prod-0123456789ab")
os.environ.setdefault("TOTP_ENCRYPTION_KEY", "a" * 64)

from app.core.totp import encrypt_totp_secret, decrypt_totp_secret


def test_encrypt_decrypt_roundtrip():
    secret = "JBSWY3DPEHPK3PXP"
    token = encrypt_totp_secret(secret)
    assert isinstance(token, bytes)
    assert decrypt_totp_secret(token) == secret


def test_encrypted_token_is_not_plaintext_secret():
    secret = "JBSWY3DPEHPK3PXP"
    token = encrypt_totp_secret(secret)
    assert secret.encode() not in token


def test_decrypt_rejects_tampered_token():
    secret = "JBSWY3DPEHPK3PXP"
    token = bytearray(encrypt_totp_secret(secret))
    token[-1] ^= 0xFF
    from cryptography.fernet import InvalidToken
    import pytest
    with pytest.raises(InvalidToken):
        decrypt_totp_secret(bytes(token))


def test_totp_encryption_is_independent_of_jwt_secret(monkeypatch):
    from app.config import settings

    token = encrypt_totp_secret("JBSWY3DPEHPK3PXP")
    original = settings.JWT_SECRET
    monkeypatch.setattr(settings, "JWT_SECRET", "d" * 64)
    try:
        assert decrypt_totp_secret(token) == "JBSWY3DPEHPK3PXP"
    finally:
        monkeypatch.setattr(settings, "JWT_SECRET", original)
