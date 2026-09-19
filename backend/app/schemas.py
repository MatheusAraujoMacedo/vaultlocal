from pydantic import BaseModel, EmailStr, Field


class RegisterIn(BaseModel):
    email: EmailStr
    master_password: str = Field(min_length=12)


class LoginIn(BaseModel):
    email: EmailStr
    master_password: str


class TokenOut(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshIn(BaseModel):
    refresh_token: str


class ChangePasswordIn(BaseModel):
    old_master_password: str
    new_master_password: str = Field(min_length=12)


class EntryIn(BaseModel):
    title: str = Field(min_length=1, max_length=255)
    site: str | None = None
    username: str
    password: str
    notes: str | None = None
    tags: str = ""


class EntryOut(BaseModel):
    id: str
    title: str
    site: str | None
    username: str
    password: str
    notes: str | None
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
