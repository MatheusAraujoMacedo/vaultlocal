import base64

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ..config import settings


def _totp_fernet_key() -> bytes:
    kdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"totp")
    raw = kdf.derive(settings.JWT_SECRET.encode())
    return base64.urlsafe_b64encode(raw)


def encrypt_totp_secret(secret: str) -> bytes:
    return Fernet(_totp_fernet_key()).encrypt(secret.encode())


def decrypt_totp_secret(token: bytes) -> str:
    return Fernet(_totp_fernet_key()).decrypt(token).decode()
