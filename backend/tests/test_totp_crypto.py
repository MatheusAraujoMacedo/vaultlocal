import os

os.environ.setdefault("JWT_SECRET", "test-secret-not-for-prod")

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
