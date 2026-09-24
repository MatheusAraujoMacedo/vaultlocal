import base64
from typing import Literal

from pydantic import BaseModel, EmailStr, Field, field_validator, model_validator


def _b64_len(value: str, expected_len: int, field_name: str) -> str:
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception:
        raise ValueError(f"{field_name} must be valid base64")
    if len(raw) != expected_len:
        raise ValueError(f"{field_name} must decode to exactly {expected_len} bytes")
    return value


def _b64_any_len(value: str, field_name: str) -> str:
    try:
        base64.b64decode(value, validate=True)
    except Exception:
        raise ValueError(f"{field_name} must be valid base64")
    return value


class RegisterIn(BaseModel):
    email: EmailStr
    salt_auth: str
    salt_crypto: str
    auth_key: str = Field(min_length=1)


class LoginInitIn(BaseModel):
    email: EmailStr


class LoginInitOut(BaseModel):
    salt_auth: str
    salt_crypto: str


class LoginIn(BaseModel):
    email: EmailStr
    auth_key: str


class TokenOut(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshIn(BaseModel):
    refresh_token: str


class LoginOut(BaseModel):
    status: Literal["mfa_setup_required", "mfa_verify_required"]
    mfa_token: str


class TotpSetupOut(BaseModel):
    secret: str
    otpauth_uri: str


class TotpCodeIn(BaseModel):
    totp_code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


class ChangePasswordEntryRewrap(BaseModel):
    id: str
    wrapped_data_key: str
    wrapped_nonce: str

    @field_validator("wrapped_nonce")
    @classmethod
    def _validate_wrapped_nonce(cls, v: str) -> str:
        return _b64_len(v, 12, "wrapped_nonce")

    @field_validator("wrapped_data_key")
    @classmethod
    def _validate_wrapped_data_key(cls, v: str) -> str:
        return _b64_len(v, 48, "wrapped_data_key")


class ChangePasswordIn(BaseModel):
    old_auth_key: str
    new_auth_key: str
    new_salt_auth: str
    new_salt_crypto: str
    entries: list[ChangePasswordEntryRewrap]


class EntryIn(BaseModel):
    title: str = Field(min_length=1, max_length=255)
    site: str | None = None
    username_enc: str
    nonce_username: str
    password_enc: str
    nonce_password: str
    notes_enc: str | None = None
    nonce_notes: str | None = None
    wrapped_data_key: str
    wrapped_nonce: str
    tags: str = ""

    @field_validator("nonce_username", "nonce_password")
    @classmethod
    def _validate_nonce(cls, v: str) -> str:
        return _b64_len(v, 12, "nonce")

    @field_validator("nonce_notes")
    @classmethod
    def _validate_nonce_notes(cls, v: str | None) -> str | None:
        if v is None:
            return v
        return _b64_len(v, 12, "nonce_notes")

    @field_validator("username_enc", "password_enc")
    @classmethod
    def _validate_ciphertext(cls, v: str) -> str:
        return _b64_any_len(v, "ciphertext")

    @field_validator("notes_enc")
    @classmethod
    def _validate_notes_enc(cls, v: str | None) -> str | None:
        if v is None:
            return v
        return _b64_any_len(v, "notes_enc")

    @field_validator("wrapped_data_key")
    @classmethod
    def _validate_wrapped_data_key(cls, v: str) -> str:
        return _b64_len(v, 48, "wrapped_data_key")

    @field_validator("wrapped_nonce")
    @classmethod
    def _validate_wrapped_nonce(cls, v: str) -> str:
        return _b64_len(v, 12, "wrapped_nonce")

    @model_validator(mode="after")
    def _validate_notes_pair(self) -> "EntryIn":
        if (self.notes_enc is None) != (self.nonce_notes is None):
            raise ValueError("notes_enc and nonce_notes must both be set or both be None")
        return self


class EntryOut(BaseModel):
    id: str
    title: str
    site: str | None
    username_enc: str
    nonce_username: str
    password_enc: str
    nonce_password: str
    notes_enc: str | None
    nonce_notes: str | None
    wrapped_data_key: str
    wrapped_nonce: str
    tags: str
    created_at: str
    updated_at: str


class EntryListItem(BaseModel):
    id: str
    title: str
    site: str | None
    tags: str
    created_at: str
    updated_at: str


class GenerateIn(BaseModel):
    length: int = Field(default=20, ge=8, le=128)
    use_symbols: bool = True


class GenerateOut(BaseModel):
    password: str


class HealthReportIn(BaseModel):
    total_entries: int = Field(ge=0)
    weak_count: int = Field(ge=0)
    reused_count: int = Field(ge=0)
    old_count: int = Field(ge=0)

    @model_validator(mode="after")
    def counts_within_total(self) -> "HealthReportIn":
        for field in ("weak_count", "reused_count", "old_count"):
            if getattr(self, field) > self.total_entries:
                raise ValueError(f"{field} cannot exceed total_entries")
        return self


class HealthReportOut(BaseModel):
    id: str
    user_id: str
    total_entries: int
    weak_count: int
    reused_count: int
    old_count: int
    created_at: str
    updated_at: str
