from pydantic import field_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    ENVIRONMENT: str = "development"
    DATABASE_URL: str = "sqlite+aiosqlite:///./vault.db"
    JWT_SECRET: str = "dev-secret-change-me"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    model_config = {"env_file": ".env", "extra": "ignore"}

    @field_validator("JWT_SECRET")
    @classmethod
    def validate_jwt_secret(cls, value: str, info) -> str:
        environment = info.data.get("ENVIRONMENT", "development").lower()
        if environment == "production":
            if value in {"", "dev-secret-change-me", "change-me"}:
                raise ValueError("JWT_SECRET must be set to a strong random value in production")
            if len(value) < 32:
                raise ValueError("JWT_SECRET must be at least 32 characters long in production")
        return value


settings = Settings()
