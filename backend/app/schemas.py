from pydantic import BaseModel, EmailStr, Field


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


class ChangePasswordEntryRewrap(BaseModel):
    id: str
    wrapped_data_key: str
    wrapped_nonce: str


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
