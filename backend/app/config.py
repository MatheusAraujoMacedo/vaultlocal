from pathlib import Path

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    ENVIRONMENT: str = "development"
    DATABASE_URL: str = "sqlite+aiosqlite:///./vault.db"
    JWT_SECRET: str = ""
    TOTP_ENCRYPTION_KEY: str = ""
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    RESET_DELIVERY: str = "local"
    RESET_URL_BASE: str = "http://localhost:8080/login"
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USERNAME: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM: str = ""
    SMTP_STARTTLS: bool = True
    GOOGLE_CLIENT_ID: str = ""
    GOOGLE_CLIENT_SECRET: str = ""
    GOOGLE_REDIRECT_URI: str = "http://localhost:8080/api/v1/auth/oidc/google/callback"
    GOOGLE_ISSUER: str = "https://accounts.google.com"
    WEBAUTHN_RP_ID: str = "localhost"
    WEBAUTHN_RP_NAME: str = "VaultLocal"
    WEBAUTHN_ORIGIN: str = "http://localhost:8080"
    HIBP_LOCAL_DIR: str = "/var/lib/vaultlocal/hibp/sha1"

    model_config = SettingsConfigDict(
        env_file=Path(__file__).resolve().parents[2] / ".env",
        extra="ignore",
    )

    @field_validator("JWT_SECRET")
    @classmethod
    def validate_jwt_secret(cls, value: str) -> str:
        if value in {"", "dev-secret-change-me", "change-me", "change_me_to_a_long_random_hex_string"}:
            raise ValueError("JWT_SECRET must be set to a strong random value")
        if len(value) < 32:
            raise ValueError("JWT_SECRET must be at least 32 characters long")
        return value

    @field_validator("RESET_DELIVERY")
    @classmethod
    def validate_reset_delivery(cls, value: str) -> str:
        normalized = value.lower()
        if normalized not in {"local", "smtp"}:
            raise ValueError("RESET_DELIVERY must be local or smtp")
        return normalized

    @field_validator("TOTP_ENCRYPTION_KEY")
    @classmethod
    def validate_totp_encryption_key(cls, value: str) -> str:
        try:
            raw = bytes.fromhex(value)
        except ValueError as exc:
            raise ValueError("TOTP_ENCRYPTION_KEY must be 64 hexadecimal characters") from exc
        if len(raw) != 32:
            raise ValueError("TOTP_ENCRYPTION_KEY must encode exactly 32 bytes")
        return value


settings = Settings()
