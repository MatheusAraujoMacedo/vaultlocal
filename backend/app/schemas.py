import base64
import binascii
from datetime import datetime
from typing import Any, Literal

from pydantic import UUID4, BaseModel, EmailStr, Field, field_validator, model_validator


def _b64_len(value: str, expected_len: int, field_name: str) -> str:
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError(f"{field_name} must be valid base64") from None
    if len(raw) != expected_len:
        raise ValueError(f"{field_name} must decode to exactly {expected_len} bytes")
    return value


def _b64_any_len(value: str, field_name: str) -> str:
    try:
        base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError(f"{field_name} must be valid base64") from None
    return value


class RegisterIn(BaseModel):
    email: EmailStr = Field(max_length=320)
    salt_auth: str
    salt_crypto: str
    auth_key: str = Field(min_length=1)

    @field_validator("salt_auth", "salt_crypto")
    @classmethod
    def _validate_registration_salts(cls, v: str, info) -> str:
        return _b64_len(v, 16, info.field_name)

    @field_validator("auth_key")
    @classmethod
    def _validate_auth_key(cls, v: str) -> str:
        return _b64_len(v, 32, "auth_key")


class LoginInitIn(BaseModel):
    email: EmailStr = Field(max_length=320)


class LoginInitOut(BaseModel):
    salt_auth: str
    salt_crypto: str


class LoginIn(BaseModel):
    email: EmailStr = Field(max_length=320)
    auth_key: str

    @field_validator("auth_key")
    @classmethod
    def _validate_login_auth_key(cls, v: str) -> str:
        return _b64_len(v, 32, "auth_key")


class TokenOut(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshIn(BaseModel):
    refresh_token: str = Field(min_length=1, max_length=4096)


class LoginOut(BaseModel):
    status: Literal["mfa_setup_required", "recovery_setup_required", "mfa_verify_required"]
    mfa_token: str
    recovery_upgrade_required: bool = False


class GoogleHandoffOut(BaseModel):
    status: Literal["existing", "setup_required"]
    email: EmailStr = Field(max_length=320)
    salt_auth: str | None = None
    salt_crypto: str | None = None


class GoogleCompleteIn(BaseModel):
    new_salt_auth: str
    new_salt_crypto: str
    auth_key: str

    @field_validator("new_salt_auth", "new_salt_crypto")
    @classmethod
    def _validate_google_salts(cls, v: str, info) -> str:
        return _b64_len(v, 16, info.field_name)

    @field_validator("auth_key")
    @classmethod
    def _validate_google_auth_key(cls, v: str) -> str:
        return _b64_len(v, 32, "auth_key")


class GooglePasswordIn(BaseModel):
    auth_key: str

    @field_validator("auth_key")
    @classmethod
    def _validate_google_password_auth_key(cls, v: str) -> str:
        return _b64_len(v, 32, "auth_key")


class WebAuthnRegisterVerifyIn(BaseModel):
    challenge: str = Field(min_length=40, max_length=100)
    prf_salt: str
    credential: dict[str, Any]

    @field_validator("prf_salt")
    @classmethod
    def _validate_prf_salt(cls, v: str) -> str:
        return _b64_len(v, 32, "prf_salt")

    @field_validator("challenge")
    @classmethod
    def _validate_webauthn_challenge(cls, v: str) -> str:
        return v


class WebAuthnEnvelopeIn(BaseModel):
    credential_id: str = Field(min_length=1, max_length=512)
    encrypted_kek: str
    kek_nonce: str

    @field_validator("encrypted_kek")
    @classmethod
    def _validate_encrypted_kek(cls, v: str) -> str:
        return _b64_len(v, 48, "encrypted_kek")

    @field_validator("kek_nonce")
    @classmethod
    def _validate_kek_nonce(cls, v: str) -> str:
        return _b64_len(v, 12, "kek_nonce")


class WebAuthnLoginVerifyIn(BaseModel):
    challenge: str = Field(min_length=40, max_length=100)
    credential: dict[str, Any]


class WebAuthnLocalOptionsIn(BaseModel):
    email: EmailStr = Field(max_length=320)


class WebAuthnRegisterOptionsOut(BaseModel):
    options: dict[str, Any]
    challenge: str
    prf_salt: str


class WebAuthnLoginOptionsOut(BaseModel):
    options: dict[str, Any]
    challenge: str
    prf_salts: dict[str, str]


class WebAuthnLoginOut(BaseModel):
    access_token: str
    refresh_token: str
    credential_id: str
    encrypted_kek: str
    kek_nonce: str


class WebAuthnDeviceOut(BaseModel):
    credential_id: str
    name: str
    created_at: datetime
    last_used_at: datetime | None
    credential_backed_up: bool


class WebAuthnDevicesOut(BaseModel):
    devices: list[WebAuthnDeviceOut]


class WebAuthnDeviceRenameIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)


class WebAuthnDeviceRevokeIn(BaseModel):
    totp_code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


class RecoverySetupIn(BaseModel):
    recovery_wrapped_kek: str
    recovery_nonce: str
    recovery_public_key: str = Field(min_length=80, max_length=2048)
    recovery_wrapped_signing_key: str
    recovery_signing_nonce: str

    @field_validator("recovery_signing_nonce")
    @classmethod
    def _validate_recovery_signing_nonce(cls, v: str) -> str:
        return _b64_len(v, 12, "recovery_signing_nonce")

    @field_validator("recovery_wrapped_signing_key")
    @classmethod
    def _validate_recovery_signing_key(cls, v: str) -> str:
        return _b64_any_len(v, "recovery_wrapped_signing_key")

    @field_validator("recovery_wrapped_kek")
    @classmethod
    def _validate_recovery_wrap(cls, v: str) -> str:
        return _b64_len(v, 48, "recovery_wrapped_kek")

    @field_validator("recovery_nonce")
    @classmethod
    def _validate_recovery_nonce(cls, v: str) -> str:
        return _b64_len(v, 12, "recovery_nonce")


class RecoveryInitIn(BaseModel):
    email: EmailStr = Field(max_length=320)


class RecoveryInitOut(BaseModel):
    salt_crypto: str
    recovery_wrapped_kek: str
    recovery_nonce: str
    recovery_challenge: str
    recovery_public_key: str
    recovery_wrapped_signing_key: str
    recovery_signing_nonce: str


class RecoveryVerifyIn(BaseModel):
    email: EmailStr = Field(max_length=320)
    recovery_challenge: str
    recovery_proof: str

    @field_validator("recovery_challenge")
    @classmethod
    def _validate_recovery_challenge_b64(cls, v: str) -> str:
        return _b64_len(v, 32, "recovery_challenge")

    @field_validator("recovery_proof")
    @classmethod
    def _validate_recovery_proof_b64(cls, v: str) -> str:
        return _b64_len(v, 64, "recovery_proof")


class RecoveryUpgradeIn(BaseModel):
    recovery_public_key: str = Field(min_length=80, max_length=2048)
    recovery_wrapped_signing_key: str
    recovery_signing_nonce: str

    @field_validator("recovery_signing_nonce")
    @classmethod
    def _validate_upgrade_signing_nonce(cls, v: str) -> str:
        return _b64_len(v, 12, "recovery_signing_nonce")

    @field_validator("recovery_wrapped_signing_key")
    @classmethod
    def _validate_upgrade_signing_key(cls, v: str) -> str:
        return _b64_any_len(v, "recovery_wrapped_signing_key")


class RecoveryEntry(BaseModel):
    id: str
    crypto_version: Literal[1, 2]
    wrapped_data_key: str
    wrapped_nonce: str

    @field_validator("wrapped_data_key")
    @classmethod
    def _validate_recovery_wrapped_key(cls, v: str) -> str:
        return _b64_len(v, 48, "wrapped_data_key")

    @field_validator("wrapped_nonce")
    @classmethod
    def _validate_recovery_wrapped_nonce(cls, v: str) -> str:
        return _b64_len(v, 12, "wrapped_nonce")


class RecoveryVerifyOut(BaseModel):
    recovery_token: str
    entries: list[RecoveryEntry]


class RecoverIn(BaseModel):
    new_auth_key: str
    new_salt_auth: str
    new_salt_crypto: str
    new_recovery_wrapped_kek: str
    new_recovery_nonce: str
    new_recovery_public_key: str = Field(min_length=80, max_length=2048)
    new_recovery_wrapped_signing_key: str
    new_recovery_signing_nonce: str
    entries: list["ChangePasswordEntryRewrap"]

    @field_validator("new_auth_key")
    @classmethod
    def _validate_recover_auth_key(cls, v: str) -> str:
        return _b64_len(v, 32, "new_auth_key")

    @field_validator("new_salt_auth", "new_salt_crypto")
    @classmethod
    def _validate_recover_salt(cls, v: str, info) -> str:
        return _b64_len(v, 16, info.field_name)

    @field_validator("new_recovery_wrapped_kek")
    @classmethod
    def _validate_recover_wrap(cls, v: str) -> str:
        return _b64_len(v, 48, "new_recovery_wrapped_kek")

    @field_validator("new_recovery_nonce")
    @classmethod
    def _validate_recover_nonce(cls, v: str) -> str:
        return _b64_len(v, 12, "new_recovery_nonce")

    @field_validator("new_recovery_signing_nonce")
    @classmethod
    def _validate_new_recovery_signing_nonce(cls, v: str) -> str:
        return _b64_len(v, 12, "new_recovery_signing_nonce")

    @field_validator("new_recovery_wrapped_signing_key")
    @classmethod
    def _validate_new_recovery_signing_key(cls, v: str) -> str:
        return _b64_any_len(v, "new_recovery_wrapped_signing_key")


class PasswordResetRequestIn(BaseModel):
    email: EmailStr = Field(max_length=320)
    totp_code: str | None = Field(default=None, min_length=6, max_length=6, pattern=r"^\d{6}$")


class PasswordResetRequestOut(BaseModel):
    ok: bool = True
    token: str | None = None


class PasswordResetValidateIn(BaseModel):
    token: str = Field(min_length=1, max_length=512)


class PasswordResetConfirmIn(BaseModel):
    token: str = Field(min_length=1, max_length=512)
    new_auth_key: str
    new_salt_auth: str
    new_salt_crypto: str

    @field_validator("new_auth_key")
    @classmethod
    def _validate_reset_auth_key(cls, v: str) -> str:
        return _b64_len(v, 32, "new_auth_key")

    @field_validator("new_salt_auth", "new_salt_crypto")
    @classmethod
    def _validate_reset_salt(cls, v: str, info) -> str:
        return _b64_len(v, 16, info.field_name)


class TotpSetupOut(BaseModel):
    secret: str
    otpauth_uri: str


class TotpCodeIn(BaseModel):
    totp_code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


class ChangePasswordEntryRewrap(BaseModel):
    id: UUID4
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

    @field_validator("old_auth_key", "new_auth_key")
    @classmethod
    def _validate_auth_keys(cls, v: str, info) -> str:
        return _b64_len(v, 32, info.field_name)

    @field_validator("new_salt_auth", "new_salt_crypto")
    @classmethod
    def _validate_password_change_salts(cls, v: str, info) -> str:
        return _b64_len(v, 16, info.field_name)


class EntryIn(BaseModel):
    id: UUID4
    crypto_version: Literal[2] = 2
    title: str = Field(min_length=1, max_length=255)
    site: str | None = Field(default=None, max_length=255)
    expires_at: datetime | None = None
    username_enc: str
    nonce_username: str
    password_enc: str
    nonce_password: str
    notes_enc: str | None = None
    nonce_notes: str | None = None
    wrapped_data_key: str
    wrapped_nonce: str
    tags: str = Field(default="", max_length=512)

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
    crypto_version: Literal[1, 2]
    title: str
    site: str | None
    expires_at: datetime | None
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
    expires_at: str | None
    created_at: str
    updated_at: str


class TrashEntryOut(EntryListItem):
    deleted_at: str
    purge_at: str


class TrashListOut(BaseModel):
    entries: list[TrashEntryOut]


class SecurityEventOut(BaseModel):
    event_type: Literal[
        "entry_created",
        "entry_updated",
        "entry_deleted",
        "entry_restored",
        "entry_permanently_deleted",
        "health_scan",
        "passkey_added",
        "passkey_renamed",
        "passkey_revoked",
        "password_changed",
        "mfa_enabled",
        "recovery_used",
        "login_success",
        "logout",
    ]
    created_at: str


class SecurityTimelineOut(BaseModel):
    events: list[SecurityEventOut]


class HealthReportIn(BaseModel):
    total_entries: int = Field(ge=0)
    weak_count: int = Field(ge=0)
    reused_count: int = Field(ge=0)
    old_count: int = Field(ge=0)
    breached_count: int = Field(ge=0, default=0)

    @model_validator(mode="after")
    def counts_within_total(self) -> "HealthReportIn":
        for field in ("weak_count", "reused_count", "old_count", "breached_count"):
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
    breached_count: int
    score: int
    created_at: str
    updated_at: str
