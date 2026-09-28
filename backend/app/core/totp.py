import base64

from cryptography.fernet import Fernet

from ..config import settings


def _totp_fernet_key() -> bytes:
    raw = bytes.fromhex(settings.TOTP_ENCRYPTION_KEY)
    return base64.urlsafe_b64encode(raw)


def encrypt_totp_secret(secret: str) -> bytes:
    return Fernet(_totp_fernet_key()).encrypt(secret.encode())


def decrypt_totp_secret(token: bytes) -> str:
    return Fernet(_totp_fernet_key()).decrypt(token).decode()
