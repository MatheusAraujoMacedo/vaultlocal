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
