> **Hardening note (2026-09-27):** the server-side password generator described
> in this historical implementation plan was removed. Password generation is now
> performed entirely in the browser with Web Crypto so the backend never sees the
> generated secret. Treat the `/entries/generate/password` references below as
> historical and do not reintroduce that endpoint.

# Zero-knowledge Frontend Crypto Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move all master-password/KEK/entry-secret handling to the browser so the backend never sees plaintext secrets, `master_password`, or the KEK — only opaque derived values and ciphertext blobs.

**Architecture:** Split key derivation into `auth_key` (server-verified login credential) and `KEK` (never leaves the browser) from two different salts. Each vault entry gets its own random `data_key` that encrypts its fields; the `data_key` is wrapped (AES-GCM) by the KEK and only the wrapped blob is stored server-side. Changing the master password only re-wraps each entry's small `data_key`, never the entry ciphertext itself.

**Tech Stack:** FastAPI/SQLAlchemy/Alembic (existing backend), React/Vite (existing frontend), `hash-wasm` (Argon2id in the browser, new dependency), native `window.crypto.subtle` (AES-GCM, already available, no dependency).

**Spec:** `docs/superpowers/specs/2026-09-19-zero-knowledge-frontend-design.md`

## Global Constraints

- Repository has no `.git` yet (confirmed: not a git repository). Skip every "commit" step from the standard task template — end each task by moving to the next one, no `git add`/`git commit`.
- Backend venv has no `pip`/`uv` binary directly; use `/home/matheusaraujosami/Documentos/vaultlocal/.venv/bin/python -m pip` for any install, same as done earlier in this project.
- Existing `users`/`vault_entries`/`sessions` rows are test data only — the migration in Task 1 deletes all of them; this is intentional per the approved spec, not a bug.
- Argon2id parameters MUST match between backend (`time_cost=3, memory_cost=65536, parallelism=2, hash_len=32`, from `backend/app/core/security.py`) and frontend (`hash-wasm`'s `iterations=3, memorySize=65536, parallelism=2, hashLength=32`) — `memory_cost`/`memorySize` are both in KiB, no unit conversion needed.
- All new binary values crossing the HTTP boundary (salts, auth_key, ciphertext, nonces, wrapped keys) are base64 strings in JSON, never raw bytes or hex, to match the existing convention already used by `username_enc`/`nonce_username` etc.
- Run backend tests with: `cd backend && JWT_SECRET=test ../.venv/bin/python -m pytest -q` (matches the pattern already used in this project; `make test` from the repo root does the same).

---

### Task 1: Envelope-per-entry schema migration

**Files:**
- Modify: `backend/app/models.py:42-70` (the `VaultEntry` class)
- Create: `backend/alembic/versions/<generated>_zero_knowledge_entries.py`

**Interfaces:**
- Produces: `VaultEntry.wrapped_data_key: str`, `VaultEntry.wrapped_nonce: str` — consumed by Task 3 (`entries.py`, `EntryIn`/`EntryOut`) and Task 2 (`change_password`'s rewrap loop).

- [ ] **Step 1: Add the two new columns to the model**

Edit `backend/app/models.py`, in the `VaultEntry` class, right after the `tags` column and before `created_at`:

```python
    tags: Mapped[str] = mapped_column(String(512), default="")  # comma separated for sqlite compat

    wrapped_data_key: Mapped[str] = mapped_column(Text)
    wrapped_nonce: Mapped[str] = mapped_column(String(64))

    created_at: Mapped[datetime] = mapped_column(
```

- [ ] **Step 2: Generate the migration skeleton**

Run: `cd backend && ../.venv/bin/alembic revision -m "zero knowledge entries"`
Expected: a new file appears under `backend/alembic/versions/`, with `down_revision = '9ed8100d85dc'` (the current head) and empty `upgrade()`/`downgrade()`.

- [ ] **Step 3: Write the migration body**

Open the generated file and replace `upgrade()`/`downgrade()` with:

```python
def upgrade() -> None:
    # test/dev data only — the auth_hash/salts of every existing user were
    # computed under the old (server-derives-KEK) model and cannot be
    # reconciled with the new client-side derivation, so this migration
    # resets the vault instead of trying to migrate it in place.
    op.execute("DELETE FROM vault_entries")
    op.execute("DELETE FROM sessions")
    op.execute("DELETE FROM users")
    op.add_column("vault_entries", sa.Column("wrapped_data_key", sa.Text(), nullable=False))
    op.add_column("vault_entries", sa.Column("wrapped_nonce", sa.String(length=64), nullable=False))


def downgrade() -> None:
    op.drop_column("vault_entries", "wrapped_nonce")
    op.drop_column("vault_entries", "wrapped_data_key")
```

- [ ] **Step 4: Verify the migration applies cleanly from the current head**

Run:
```bash
cd backend
rm -f /tmp/zk_migration_check.db
DATABASE_URL="sqlite+aiosqlite:////tmp/zk_migration_check.db" JWT_SECRET=dev-tmp ../.venv/bin/alembic upgrade 9ed8100d85dc
DATABASE_URL="sqlite+aiosqlite:////tmp/zk_migration_check.db" JWT_SECRET=dev-tmp ../.venv/bin/alembic upgrade head
DATABASE_URL="sqlite+aiosqlite:////tmp/zk_migration_check.db" JWT_SECRET=dev-tmp ../.venv/bin/alembic current
rm -f /tmp/zk_migration_check.db
```
Expected: no errors; the last command prints the new revision id followed by `(head)`.

---

### Task 2: Auth domain — client-derived `auth_key`, envelope-aware change-password

**Files:**
- Modify: `backend/app/schemas.py` (`RegisterIn`, `LoginIn`, `ChangePasswordIn`; add `LoginInitIn`, `LoginInitOut`, `ChangePasswordEntryRewrap`)
- Modify: `backend/app/core/security.py` (remove `derive_kek` and its `argon2.low_level` import)
- Modify: `backend/app/routers/auth.py` (rewrite `register`, `login`, `change_password`; add `login_init`; drop `kekstore`/`common_passwords` imports and calls)
- Modify: `backend/tests/conftest.py` (`register_and_login` fixture uses the new contract)
- Delete: `backend/app/core/common_passwords.py`
- Delete: `backend/tests/test_common_passwords.py`
- Test: `backend/tests/test_auth.py` (full rewrite)

**Interfaces:**
- Consumes: nothing from Task 1 except `VaultEntry` (already has `wrapped_data_key`/`wrapped_nonce` from Task 1) for the rewrap loop.
- Produces: `POST /auth/login/init {email} -> {salt_auth, salt_crypto}` (both base64); `POST /auth/register {email, salt_auth, salt_crypto, auth_key}`; `POST /auth/login {email, auth_key} -> TokenOut`; `POST /auth/change-password {old_auth_key, new_auth_key, new_salt_auth, new_salt_crypto, entries: [{id, wrapped_data_key, wrapped_nonce}]} -> TokenOut`. Consumed by Task 5 (frontend `api.ts`).

- [ ] **Step 1: Write the failing tests**

Overwrite `backend/tests/conftest.py`'s `register_and_login` fixture (keep the rest of the file — `_isolated_state`, `client` — unchanged):

```python
import base64
import secrets
```
(add these two imports at the top of the file, alongside the existing `os`/`tempfile` imports)

```python
@pytest.fixture
def register_and_login(client):
    async def _do(email: str, auth_key: str = "sim-auth-key-AAAAAAAAAAAAAAAAAAAA") -> dict:
        salt_auth = base64.b64encode(secrets.token_bytes(16)).decode()
        salt_crypto = base64.b64encode(secrets.token_bytes(16)).decode()
        resp = await client.post(
            "/api/v1/auth/register",
            json={"email": email, "salt_auth": salt_auth, "salt_crypto": salt_crypto, "auth_key": auth_key},
        )
        assert resp.status_code == 201, resp.text
        user_id = resp.json()["id"]
        resp = await client.post("/api/v1/auth/login", json={"email": email, "auth_key": auth_key})
        assert resp.status_code == 200, resp.text
        return {**resp.json(), "user_id": user_id}

    return _do
```

Delete `backend/tests/test_common_passwords.py` entirely (`rm backend/tests/test_common_passwords.py`).

Replace `backend/tests/test_auth.py` entirely with:

```python
import base64
import secrets

import pytest
from sqlalchemy import select

from app.core.security import lockout_duration_minutes, LOCKOUT_THRESHOLD
from app.db import SessionLocal
from app.models import User, VaultEntry

AUTH_KEY = "sim-auth-key-AAAAAAAAAAAAAAAAAAAA"
NEW_AUTH_KEY = "sim-auth-key-BBBBBBBBBBBBBBBBBBBB"


def _salt() -> str:
    return base64.b64encode(secrets.token_bytes(16)).decode()


async def _register(client, email: str, auth_key: str = AUTH_KEY) -> dict:
    salt_auth, salt_crypto = _salt(), _salt()
    resp = await client.post(
        "/api/v1/auth/register",
        json={"email": email, "salt_auth": salt_auth, "salt_crypto": salt_crypto, "auth_key": auth_key},
    )
    assert resp.status_code == 201, resp.text
    return {"id": resp.json()["id"], "salt_auth": salt_auth, "salt_crypto": salt_crypto}


async def _login(client, email: str, auth_key: str = AUTH_KEY) -> dict:
    resp = await client.post("/api/v1/auth/login", json={"email": email, "auth_key": auth_key})
    assert resp.status_code == 200, resp.text
    return resp.json()


async def _create_entry_directly(user_id: str, **overrides) -> str:
    defaults = dict(
        title="Bank", site=None,
        username_enc="u", nonce_username="n1",
        password_enc="p", nonce_password="n2",
        notes_enc=None, nonce_notes=None,
        wrapped_data_key="old-wrapped", wrapped_nonce="old-nonce",
        tags="",
    )
    defaults.update(overrides)
    async with SessionLocal() as db:
        entry = VaultEntry(user_id=user_id, **defaults)
        db.add(entry)
        await db.commit()
        await db.refresh(entry)
        return entry.id


async def test_login_init_returns_real_salts_for_known_user(client):
    salts = await _register(client, "alice@test.com")
    resp = await client.post("/api/v1/auth/login/init", json={"email": "alice@test.com"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["salt_auth"] == salts["salt_auth"]
    assert body["salt_crypto"] == salts["salt_crypto"]


async def test_login_init_returns_fake_but_stable_salts_for_unknown_user(client):
    resp1 = await client.post("/api/v1/auth/login/init", json={"email": "ghost@test.com"})
    resp2 = await client.post("/api/v1/auth/login/init", json={"email": "ghost@test.com"})
    assert resp1.status_code == 200 == resp2.status_code
    assert resp1.json() == resp2.json()


async def test_register_success(client):
    await _register(client, "bob@test.com")


async def test_register_duplicate_email_rejected(client):
    await _register(client, "bob@test.com")
    resp = await client.post(
        "/api/v1/auth/register",
        json={"email": "bob@test.com", "salt_auth": _salt(), "salt_crypto": _salt(), "auth_key": AUTH_KEY},
    )
    assert resp.status_code == 409


async def test_login_success_returns_tokens(client):
    await _register(client, "carol@test.com")
    tokens = await _login(client, "carol@test.com")
    assert tokens["access_token"]
    assert tokens["refresh_token"]


async def test_login_wrong_auth_key_rejected(client):
    await _register(client, "dave@test.com")
    resp = await client.post("/api/v1/auth/login", json={"email": "dave@test.com", "auth_key": "wrong-key"})
    assert resp.status_code == 401


async def test_login_unknown_email_rejected(client):
    resp = await client.post("/api/v1/auth/login", json={"email": "ghost2@test.com", "auth_key": AUTH_KEY})
    assert resp.status_code == 401


async def test_login_lockout_engages_after_threshold(client):
    await _register(client, "erin@test.com")
    for _ in range(LOCKOUT_THRESHOLD):
        resp = await client.post("/api/v1/auth/login", json={"email": "erin@test.com", "auth_key": "wrong-key"})
        assert resp.status_code == 401

    async with SessionLocal() as db:
        user = await db.scalar(select(User).where(User.email == "erin@test.com"))
        assert user.failed_login_attempts == LOCKOUT_THRESHOLD
        assert user.locked_until is not None

    resp = await client.post("/api/v1/auth/login", json={"email": "erin@test.com", "auth_key": AUTH_KEY})
    assert resp.status_code in (401, 429)


async def test_refresh_rotates_token(client):
    await _register(client, "frank@test.com")
    tokens = await _login(client, "frank@test.com")
    old_refresh = tokens["refresh_token"]

    resp = await client.post("/api/v1/auth/refresh", json={"refresh_token": old_refresh})
    assert resp.status_code == 200
    new_refresh = resp.json()["refresh_token"]
    assert new_refresh != old_refresh

    resp = await client.post("/api/v1/auth/refresh", json={"refresh_token": old_refresh})
    assert resp.status_code == 401

    resp = await client.post("/api/v1/auth/refresh", json={"refresh_token": new_refresh})
    assert resp.status_code == 200


async def test_logout_invalidates_refresh_token(client):
    await _register(client, "gina@test.com")
    tokens = await _login(client, "gina@test.com")
    refresh = tokens["refresh_token"]

    resp = await client.post("/api/v1/auth/logout", json={"refresh_token": refresh})
    assert resp.status_code == 200

    resp = await client.post("/api/v1/auth/refresh", json={"refresh_token": refresh})
    assert resp.status_code == 401


async def test_change_password_requires_authentication(client):
    resp = await client.post(
        "/api/v1/auth/change-password",
        json={
            "old_auth_key": AUTH_KEY, "new_auth_key": NEW_AUTH_KEY,
            "new_salt_auth": _salt(), "new_salt_crypto": _salt(), "entries": [],
        },
    )
    assert resp.status_code in (401, 403)


async def test_change_password_rejects_wrong_old_auth_key(client):
    reg = await _register(client, "henry@test.com")
    tokens = await _login(client, "henry@test.com")
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}

    resp = await client.post(
        "/api/v1/auth/change-password",
        headers=headers,
        json={
            "old_auth_key": "wrong-key", "new_auth_key": NEW_AUTH_KEY,
            "new_salt_auth": _salt(), "new_salt_crypto": _salt(), "entries": [],
        },
    )
    assert resp.status_code == 401
    assert reg["id"]


async def test_change_password_rejects_incomplete_entries_payload(client):
    reg = await _register(client, "iris@test.com")
    tokens = await _login(client, "iris@test.com")
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    await _create_entry_directly(reg["id"])

    resp = await client.post(
        "/api/v1/auth/change-password",
        headers=headers,
        json={
            "old_auth_key": AUTH_KEY, "new_auth_key": NEW_AUTH_KEY,
            "new_salt_auth": _salt(), "new_salt_crypto": _salt(),
            "entries": [],  # missing the one entry that exists -- must be rejected
        },
    )
    assert resp.status_code == 400


async def test_change_password_rotates_credentials_and_sessions(client):
    await _register(client, "jack@test.com")
    tokens = await _login(client, "jack@test.com")
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    old_refresh = tokens["refresh_token"]

    resp = await client.post(
        "/api/v1/auth/change-password",
        headers=headers,
        json={
            "old_auth_key": AUTH_KEY, "new_auth_key": NEW_AUTH_KEY,
            "new_salt_auth": _salt(), "new_salt_crypto": _salt(), "entries": [],
        },
    )
    assert resp.status_code == 200
    assert resp.json()["access_token"]

    resp = await client.post("/api/v1/auth/refresh", json={"refresh_token": old_refresh})
    assert resp.status_code == 401

    resp = await client.post("/api/v1/auth/login", json={"email": "jack@test.com", "auth_key": AUTH_KEY})
    assert resp.status_code == 401

    resp = await client.post("/api/v1/auth/login", json={"email": "jack@test.com", "auth_key": NEW_AUTH_KEY})
    assert resp.status_code == 200


async def test_change_password_rewraps_entry_keys_without_touching_ciphertext(client):
    reg = await _register(client, "kate@test.com")
    tokens = await _login(client, "kate@test.com")
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    entry_id = await _create_entry_directly(reg["id"])

    resp = await client.post(
        "/api/v1/auth/change-password",
        headers=headers,
        json={
            "old_auth_key": AUTH_KEY, "new_auth_key": NEW_AUTH_KEY,
            "new_salt_auth": _salt(), "new_salt_crypto": _salt(),
            "entries": [{"id": entry_id, "wrapped_data_key": "new-wrapped", "wrapped_nonce": "new-nonce"}],
        },
    )
    assert resp.status_code == 200

    async with SessionLocal() as db:
        entry = await db.get(VaultEntry, entry_id)
        assert entry.wrapped_data_key == "new-wrapped"
        assert entry.wrapped_nonce == "new-nonce"
        assert entry.username_enc == "u"
        assert entry.password_enc == "p"


@pytest.mark.parametrize(
    "attempts,expected_minutes",
    [(5, 1), (6, 2), (7, 4), (8, 8), (13, 60), (100, 60)],
)
def test_lockout_duration_progressive_backoff(attempts, expected_minutes):
    assert lockout_duration_minutes(attempts) == expected_minutes
```

- [ ] **Step 2: Run the tests to confirm they fail against the old contract**

Run: `cd backend && JWT_SECRET=test ../.venv/bin/python -m pytest tests/test_auth.py -q`
Expected: FAIL — old `RegisterIn`/`LoginIn` require `master_password`, so posting `auth_key` trips a 422 instead of the expected 201/200 (or import errors if `test_common_passwords.py` was already removed and nothing replaced `is_common_password` imports elsewhere yet — either failure mode is expected at this point).

- [ ] **Step 3: Update schemas**

In `backend/app/schemas.py`, replace `RegisterIn`, `LoginIn`, `RefreshIn`, `ChangePasswordIn` block with:

```python
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
```

(Leave `EntryIn`/`EntryOut`/`EntryListItem`/`GenerateIn`/`GenerateOut` untouched here — Task 3 handles those.)

- [ ] **Step 4: Remove `derive_kek` from `security.py`**

In `backend/app/core/security.py`, delete the entire `derive_kek` function (the one with the `from argon2.low_level import hash_secret_raw, Type` inline import). Leave `encrypt`/`decrypt` in place for now (Task 3 removes those). `hash_password`, `verify_password`, `generate_salt`, `create_access_token`, `create_refresh_token`, `verify_token`, `LOCKOUT_THRESHOLD`, `lockout_duration_minutes` all stay unchanged.

- [ ] **Step 5: Delete `common_passwords.py` and rewrite `auth.py`**

Run: `rm backend/app/core/common_passwords.py`

Replace `backend/app/routers/auth.py` entirely with:

```python
import base64
import hashlib
import hmac
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ..config import settings
from ..deps import get_db, get_current_user
from ..models import User, Session, VaultEntry
from ..schemas import (
    RegisterIn, LoginInitIn, LoginInitOut, LoginIn, TokenOut, RefreshIn,
    ChangePasswordIn,
)
from ..core.security import (
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token,
    verify_token,
    lockout_duration_minutes,
    LOCKOUT_THRESHOLD,
)
from ..core.limiter import limiter

router = APIRouter(prefix="/auth", tags=["auth"])


def _aware(dt: datetime | None) -> datetime | None:
    """SQLite drops tzinfo on read; Postgres keeps it. Normalize to UTC-aware
    so comparisons against datetime.now(timezone.utc) never crash."""
    if dt is None or dt.tzinfo is not None:
        return dt
    return dt.replace(tzinfo=timezone.utc)


def _fake_salt(email: str, domain: str) -> str:
    digest = hmac.new(settings.JWT_SECRET.encode(), f"{domain}:{email}".encode(), hashlib.sha256).digest()
    return base64.b64encode(digest[:16]).decode()


@router.post("/login/init", response_model=LoginInitOut)
async def login_init(body: LoginInitIn, db: AsyncSession = Depends(get_db)):
    user = await db.scalar(select(User).where(User.email == body.email))
    if not user:
        return LoginInitOut(
            salt_auth=_fake_salt(body.email, "auth"),
            salt_crypto=_fake_salt(body.email, "crypto"),
        )
    return LoginInitOut(
        salt_auth=base64.b64encode(user.salt_auth).decode(),
        salt_crypto=base64.b64encode(user.salt_crypto).decode(),
    )


@router.post("/register", status_code=201)
async def register(body: RegisterIn, db: AsyncSession = Depends(get_db)):
    existing = await db.scalar(select(User).where(User.email == body.email))
    if existing:
        raise HTTPException(409, "email already registered")
    user = User(
        email=body.email,
        auth_hash=hash_password(body.auth_key),
        salt_auth=base64.b64decode(body.salt_auth),
        salt_crypto=base64.b64decode(body.salt_crypto),
    )
    db.add(user)
    await db.commit()
    return {"id": user.id, "email": user.email}


@router.post("/login", response_model=TokenOut)
@limiter.limit("5/minute")
async def login(request: Request, body: LoginIn, db: AsyncSession = Depends(get_db)):
    user = await db.scalar(select(User).where(User.email == body.email))

    now = datetime.now(timezone.utc)
    locked_until = _aware(user.locked_until) if user else None
    if locked_until and locked_until > now:
        retry_after = int((locked_until - now).total_seconds())
        raise HTTPException(429, f"account locked, try again in {retry_after}s")

    if not user or not verify_password(body.auth_key, user.auth_hash):
        if user:
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= LOCKOUT_THRESHOLD:
                minutes = lockout_duration_minutes(user.failed_login_attempts)
                user.locked_until = now + timedelta(minutes=minutes)
            await db.commit()
        raise HTTPException(401, "invalid credentials")

    user.failed_login_attempts = 0
    user.locked_until = None

    access = create_access_token(user.id)
    refresh = create_refresh_token(user.id)
    session = Session(
        user_id=user.id,
        refresh_hash=hash_password(refresh),
        expires_at=datetime.now(timezone.utc) + timedelta(days=7),
    )
    db.add(session)
    await db.commit()
    return TokenOut(access_token=access, refresh_token=refresh)


@router.post("/refresh", response_model=TokenOut)
async def refresh(body: RefreshIn, db: AsyncSession = Depends(get_db)):
    try:
        user_id = verify_token(body.refresh_token, "refresh")
    except ValueError:
        raise HTTPException(401, "invalid refresh token")

    sessions = await db.scalars(select(Session).where(Session.user_id == user_id))
    matched = None
    for s in sessions:
        if verify_password(body.refresh_token, s.refresh_hash):
            matched = s
            break
    if not matched:
        raise HTTPException(401, "refresh token not found")
    if _aware(matched.expires_at) < datetime.now(timezone.utc):
        await db.delete(matched)
        await db.commit()
        raise HTTPException(401, "refresh token expired")

    access = create_access_token(user_id)
    new_refresh = create_refresh_token(user_id)
    matched.refresh_hash = hash_password(new_refresh)
    matched.expires_at = datetime.now(timezone.utc) + timedelta(days=7)
    await db.commit()
    return TokenOut(access_token=access, refresh_token=new_refresh)


@router.post("/change-password", response_model=TokenOut)
async def change_password(
    body: ChangePasswordIn,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if not verify_password(body.old_auth_key, user.auth_hash):
        raise HTTPException(401, "invalid credentials")

    entries = list(await db.scalars(select(VaultEntry).where(VaultEntry.user_id == user.id)))
    entry_by_id = {e.id: e for e in entries}
    incoming_ids = {item.id for item in body.entries}
    if incoming_ids != set(entry_by_id.keys()):
        raise HTTPException(400, "entries payload must cover exactly the user's current entries")

    for item in body.entries:
        entry = entry_by_id[item.id]
        entry.wrapped_data_key = item.wrapped_data_key
        entry.wrapped_nonce = item.wrapped_nonce

    user.auth_hash = hash_password(body.new_auth_key)
    user.salt_auth = base64.b64decode(body.new_salt_auth)
    user.salt_crypto = base64.b64decode(body.new_salt_crypto)

    old_sessions = list(await db.scalars(select(Session).where(Session.user_id == user.id)))
    for s in old_sessions:
        await db.delete(s)

    access = create_access_token(user.id)
    refresh = create_refresh_token(user.id)
    session = Session(
        user_id=user.id,
        refresh_hash=hash_password(refresh),
        expires_at=datetime.now(timezone.utc) + timedelta(days=7),
    )
    db.add(session)
    await db.commit()
    return TokenOut(access_token=access, refresh_token=refresh)


@router.post("/logout")
async def logout(body: RefreshIn, db: AsyncSession = Depends(get_db)):
    try:
        user_id = verify_token(body.refresh_token, "refresh")
    except ValueError:
        return {"ok": True}
    sessions = await db.scalars(select(Session).where(Session.user_id == user_id))
    for s in sessions:
        if verify_password(body.refresh_token, s.refresh_hash):
            await db.delete(s)
    await db.commit()
    return {"ok": True}
```

- [ ] **Step 6: Run the tests again to confirm they pass**

Run: `cd backend && JWT_SECRET=test ../.venv/bin/python -m pytest tests/test_auth.py -q`
Expected: all PASS. (`tests/test_entries.py` is expected to fail at this point — Task 3 fixes it — do not chase that failure here.)

---

### Task 3: Entries domain — opaque blob passthrough, drop server-side crypto

**Files:**
- Modify: `backend/app/schemas.py` (`EntryIn`, `EntryOut`)
- Modify: `backend/app/routers/entries.py` (full rewrite)
- Modify: `backend/app/deps.py` (remove `get_current_user_with_kek`)
- Modify: `backend/app/core/security.py` (remove `encrypt`/`decrypt`, the now-unused `AESGCM` import, and the unused `os` import)
- Delete: `backend/app/core/kekstore.py`
- Test: `backend/tests/test_entries.py` (full rewrite)

**Interfaces:**
- Consumes: `VaultEntry.wrapped_data_key`/`wrapped_nonce` (Task 1); `get_current_user` (unchanged, from `deps.py`).
- Produces: `EntryIn`/`EntryOut` blob shape — consumed by Task 6 (frontend `EntryForm.tsx`, `EntryDetail.tsx`) via Task 5's `api.ts`.

- [ ] **Step 1: Write the failing test**

Replace `backend/tests/test_entries.py` entirely with:

```python
def _entry_payload(**overrides):
    payload = dict(
        title="GitHub", site="github.com",
        username_enc="enc-username", nonce_username="nonce-u",
        password_enc="enc-password", nonce_password="nonce-p",
        notes_enc="enc-notes", nonce_notes="nonce-n",
        wrapped_data_key="wrapped-dk", wrapped_nonce="wrapped-n",
        tags="dev,work",
    )
    payload.update(overrides)
    return payload


async def _auth_headers(register_and_login, email):
    tokens = await register_and_login(email)
    return {"Authorization": f"Bearer {tokens['access_token']}"}


async def test_create_and_get_entry_roundtrips_blobs(client, register_and_login):
    headers = await _auth_headers(register_and_login, "alice@test.com")
    resp = await client.post("/api/v1/entries", headers=headers, json=_entry_payload())
    assert resp.status_code == 201
    entry = resp.json()
    assert entry["username_enc"] == "enc-username"
    assert entry["password_enc"] == "enc-password"
    assert entry["wrapped_data_key"] == "wrapped-dk"

    resp = await client.get(f"/api/v1/entries/{entry['id']}", headers=headers)
    assert resp.status_code == 200
    fetched = resp.json()
    assert fetched["username_enc"] == "enc-username"
    assert fetched["wrapped_nonce"] == "wrapped-n"


async def test_create_entry_without_notes(client, register_and_login):
    headers = await _auth_headers(register_and_login, "noNotes@test.com")
    resp = await client.post(
        "/api/v1/entries", headers=headers,
        json=_entry_payload(notes_enc=None, nonce_notes=None),
    )
    assert resp.status_code == 201
    assert resp.json()["notes_enc"] is None


async def test_list_entries_scoped_to_user(client, register_and_login):
    headers = await _auth_headers(register_and_login, "bob@test.com")
    for title in ["First", "Second"]:
        await client.post("/api/v1/entries", headers=headers, json=_entry_payload(title=title))
    resp = await client.get("/api/v1/entries", headers=headers)
    assert resp.status_code == 200
    titles = [e["title"] for e in resp.json()]
    assert set(titles) == {"First", "Second"}


async def test_search_entries_matches_title(client, register_and_login):
    headers = await _auth_headers(register_and_login, "carol@test.com")
    await client.post("/api/v1/entries", headers=headers, json=_entry_payload(title="Netflix Account"))
    await client.post("/api/v1/entries", headers=headers, json=_entry_payload(title="Work Email"))
    resp = await client.get("/api/v1/entries/search", headers=headers, params={"q": "netflix"})
    assert resp.status_code == 200
    results = resp.json()
    assert len(results) == 1
    assert results[0]["title"] == "Netflix Account"


async def test_update_entry_changes_blobs(client, register_and_login):
    headers = await _auth_headers(register_and_login, "dave@test.com")
    resp = await client.post("/api/v1/entries", headers=headers, json=_entry_payload(title="Old"))
    entry_id = resp.json()["id"]

    resp = await client.put(
        f"/api/v1/entries/{entry_id}", headers=headers,
        json=_entry_payload(title="New", username_enc="enc-username-2", tags="updated"),
    )
    assert resp.status_code == 200
    updated = resp.json()
    assert updated["title"] == "New"
    assert updated["username_enc"] == "enc-username-2"
    assert updated["tags"] == "updated"


async def test_delete_entry_removes_it(client, register_and_login):
    headers = await _auth_headers(register_and_login, "erin@test.com")
    resp = await client.post("/api/v1/entries", headers=headers, json=_entry_payload(title="Temp"))
    entry_id = resp.json()["id"]

    resp = await client.delete(f"/api/v1/entries/{entry_id}", headers=headers)
    assert resp.status_code == 204

    resp = await client.get(f"/api/v1/entries/{entry_id}", headers=headers)
    assert resp.status_code == 404


async def test_entries_require_authentication(client):
    resp = await client.get("/api/v1/entries")
    assert resp.status_code in (401, 403)


async def test_entries_isolated_between_users(client, register_and_login):
    headers_a = await _auth_headers(register_and_login, "userA@test.com")
    headers_b = await _auth_headers(register_and_login, "userB@test.com")

    resp = await client.post("/api/v1/entries", headers=headers_a, json=_entry_payload(title="A's secret"))
    entry_id = resp.json()["id"]

    resp = await client.get(f"/api/v1/entries/{entry_id}", headers=headers_b)
    assert resp.status_code == 404

    resp = await client.get("/api/v1/entries", headers=headers_b)
    assert resp.json() == []


async def test_generate_password_respects_length_and_symbols(client, register_and_login):
    headers = await _auth_headers(register_and_login, "frank@test.com")
    resp = await client.post(
        "/api/v1/entries/generate/password", headers=headers,
        json={"length": 24, "use_symbols": False},
    )
    assert resp.status_code == 200
    pwd = resp.json()["password"]
    assert len(pwd) == 24
    assert all(c.isalnum() for c in pwd)
```

- [ ] **Step 2: Run to confirm it fails**

Run: `cd backend && JWT_SECRET=test ../.venv/bin/python -m pytest tests/test_entries.py -q`
Expected: FAIL — current `EntryIn` still requires `username`/`password` plaintext fields, so posting `username_enc` trips a 422.

- [ ] **Step 3: Update `EntryIn`/`EntryOut` in `schemas.py`**

Replace the `EntryIn`/`EntryOut` block in `backend/app/schemas.py` with:

```python
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
```

(`EntryListItem`, `GenerateIn`, `GenerateOut` stay exactly as they are.)

- [ ] **Step 4: Rewrite `entries.py`, `deps.py`, `security.py`; delete `kekstore.py`**

Replace `backend/app/routers/entries.py` entirely with:

```python
import secrets
import string
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, or_
from sqlalchemy.ext.asyncio import AsyncSession
from ..deps import get_db, get_current_user
from ..models import VaultEntry, User
from ..schemas import EntryIn, EntryOut, EntryListItem, GenerateIn, GenerateOut

router = APIRouter(prefix="/entries", tags=["entries"])


def _to_out(e: VaultEntry) -> EntryOut:
    return EntryOut(
        id=e.id,
        title=e.title,
        site=e.site,
        username_enc=e.username_enc,
        nonce_username=e.nonce_username,
        password_enc=e.password_enc,
        nonce_password=e.nonce_password,
        notes_enc=e.notes_enc,
        nonce_notes=e.nonce_notes,
        wrapped_data_key=e.wrapped_data_key,
        wrapped_nonce=e.wrapped_nonce,
        tags=e.tags or "",
        created_at=e.created_at.isoformat(),
        updated_at=e.updated_at.isoformat(),
    )


@router.get("", response_model=list[EntryListItem])
async def list_entries(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    rows = await db.scalars(
        select(VaultEntry).where(VaultEntry.user_id == user.id).order_by(VaultEntry.updated_at.desc())
    )
    return [
        EntryListItem(
            id=e.id, title=e.title, site=e.site, tags=e.tags or "",
            created_at=e.created_at.isoformat(), updated_at=e.updated_at.isoformat(),
        )
        for e in rows
    ]


@router.get("/search", response_model=list[EntryListItem])
async def search_entries(
    q: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    like = f"%{q}%"
    rows = await db.scalars(
        select(VaultEntry).where(
            VaultEntry.user_id == user.id,
            or_(VaultEntry.title.ilike(like), VaultEntry.site.ilike(like)),
        )
    )
    return [
        EntryListItem(
            id=e.id, title=e.title, site=e.site, tags=e.tags or "",
            created_at=e.created_at.isoformat(), updated_at=e.updated_at.isoformat(),
        )
        for e in rows
    ]


@router.post("", response_model=EntryOut, status_code=201)
async def create_entry(
    body: EntryIn,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    entry = VaultEntry(
        user_id=user.id,
        title=body.title,
        site=body.site,
        username_enc=body.username_enc,
        nonce_username=body.nonce_username,
        password_enc=body.password_enc,
        nonce_password=body.nonce_password,
        notes_enc=body.notes_enc,
        nonce_notes=body.nonce_notes,
        wrapped_data_key=body.wrapped_data_key,
        wrapped_nonce=body.wrapped_nonce,
        tags=body.tags,
    )
    db.add(entry)
    await db.commit()
    await db.refresh(entry)
    return _to_out(entry)


@router.get("/{entry_id}", response_model=EntryOut)
async def get_entry(
    entry_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    e = await db.get(VaultEntry, entry_id)
    if not e or e.user_id != user.id:
        raise HTTPException(404, "not found")
    return _to_out(e)


@router.put("/{entry_id}", response_model=EntryOut)
async def update_entry(
    entry_id: str,
    body: EntryIn,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    e = await db.get(VaultEntry, entry_id)
    if not e or e.user_id != user.id:
        raise HTTPException(404, "not found")
    e.title = body.title
    e.site = body.site
    e.username_enc = body.username_enc
    e.nonce_username = body.nonce_username
    e.password_enc = body.password_enc
    e.nonce_password = body.nonce_password
    e.notes_enc = body.notes_enc
    e.nonce_notes = body.nonce_notes
    e.wrapped_data_key = body.wrapped_data_key
    e.wrapped_nonce = body.wrapped_nonce
    e.tags = body.tags
    await db.commit()
    await db.refresh(e)
    return _to_out(e)


@router.delete("/{entry_id}", status_code=204)
async def delete_entry(
    entry_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    e = await db.get(VaultEntry, entry_id)
    if not e or e.user_id != user.id:
        raise HTTPException(404, "not found")
    await db.delete(e)
    await db.commit()


@router.post("/generate/password", response_model=GenerateOut)
async def generate_password(
    body: GenerateIn,
    user: User = Depends(get_current_user),
):
    chars = string.ascii_letters + string.digits
    if body.use_symbols:
        chars += "!@#$%^&*()-_=+[]{};:,.<>?"
    pwd = "".join(secrets.choice(chars) for _ in range(body.length))
    return GenerateOut(password=pwd)
```

In `backend/app/deps.py`, delete the `get_current_user_with_kek` function and the `from .core.kekstore import get_kek` import. `get_db`, `get_current_user` stay as they are.

In `backend/app/core/security.py`, delete the `encrypt`/`decrypt` functions, the `from cryptography.hazmat.primitives.ciphers.aead import AESGCM` import, and the unused `import os` line at the top.

Run: `rm backend/app/core/kekstore.py`

- [ ] **Step 5: Run the tests to confirm they pass, then run the full suite**

Run: `cd backend && JWT_SECRET=test ../.venv/bin/python -m pytest -q`
Expected: all PASS (both `test_auth.py` and `test_entries.py`, plus the untouched lockout/security tests).

---

### Task 4: Frontend crypto module

**Files:**
- Modify: `frontend/package.json` (add `hash-wasm` dependency)
- Create: `frontend/src/crypto.ts`

**Interfaces:**
- Produces: `randomSaltB64(): string`, `deriveAuthKey(password: string, saltAuthB64: string): Promise<string>`, `deriveKek(password: string, saltCryptoB64: string): Promise<CryptoKey>`, `setSessionKek(kek: CryptoKey): void`, `clearSessionKek(): void`, `getSessionKek(): CryptoKey`, `generateDataKey(): Promise<CryptoKey>`, `wrapDataKey(dataKey: CryptoKey, kek: CryptoKey): Promise<{wrapped_data_key: string; wrapped_nonce: string}>`, `unwrapDataKey(wrapped: {wrapped_data_key: string; wrapped_nonce: string}, kek: CryptoKey): Promise<CryptoKey>`, `encryptField(plaintext: string, dataKey: CryptoKey): Promise<{ciphertext: string; nonce: string}>`, `decryptField(field: {ciphertext: string; nonce: string}, dataKey: CryptoKey): Promise<string>`, `isCommonPassword(password: string): boolean`. Consumed by Task 5 (`api.ts`, `Login.tsx`, `Register.tsx`) and Task 6 (`EntryForm.tsx`, `EntryDetail.tsx`).

- [ ] **Step 1: Add the dependency**

Edit `frontend/package.json`, add to `"dependencies"`:
```json
    "hash-wasm": "^4.11.0",
```

Run: `cd frontend && npm install`
Expected: `hash-wasm` appears in `node_modules` and `package-lock.json`.

- [ ] **Step 2: Write `crypto.ts`**

Create `frontend/src/crypto.ts`:

```typescript
import { argon2id } from 'hash-wasm'

function b64encode(bytes: Uint8Array): string {
  let binary = ''
  for (const b of bytes) binary += String.fromCharCode(b)
  return btoa(binary)
}

function b64decode(b64: string): Uint8Array {
  const binary = atob(b64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return bytes
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16)
  }
  return bytes
}

async function deriveRawKey(password: string, saltB64: string): Promise<Uint8Array> {
  const salt = b64decode(saltB64)
  const hex = await argon2id({
    password,
    salt,
    parallelism: 2,
    iterations: 3,
    memorySize: 65536,
    hashLength: 32,
    outputType: 'hex',
  })
  return hexToBytes(hex)
}

export function randomSaltB64(): string {
  const bytes = new Uint8Array(16)
  crypto.getRandomValues(bytes)
  return b64encode(bytes)
}

export async function deriveAuthKey(password: string, saltAuthB64: string): Promise<string> {
  const raw = await deriveRawKey(password, saltAuthB64)
  return b64encode(raw)
}

async function importAesKey(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt'])
}

export async function deriveKek(password: string, saltCryptoB64: string): Promise<CryptoKey> {
  const raw = await deriveRawKey(password, saltCryptoB64)
  return importAesKey(raw)
}

let sessionKek: CryptoKey | null = null

export function setSessionKek(kek: CryptoKey): void {
  sessionKek = kek
}

export function clearSessionKek(): void {
  sessionKek = null
}

export function getSessionKek(): CryptoKey {
  if (!sessionKek) throw new Error('vault locked, login again')
  return sessionKek
}

export interface WrappedKey {
  wrapped_data_key: string
  wrapped_nonce: string
}

export async function generateDataKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt'])
}

export async function wrapDataKey(dataKey: CryptoKey, kek: CryptoKey): Promise<WrappedKey> {
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', dataKey))
  const nonce = new Uint8Array(12)
  crypto.getRandomValues(nonce)
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, kek, raw),
  )
  return { wrapped_data_key: b64encode(ciphertext), wrapped_nonce: b64encode(nonce) }
}

export async function unwrapDataKey(wrapped: WrappedKey, kek: CryptoKey): Promise<CryptoKey> {
  const ciphertext = b64decode(wrapped.wrapped_data_key)
  const nonce = b64decode(wrapped.wrapped_nonce)
  const raw = new Uint8Array(
    await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, kek, ciphertext),
  )
  return importAesKey(raw)
}

export interface EncField {
  ciphertext: string
  nonce: string
}

export async function encryptField(plaintext: string, dataKey: CryptoKey): Promise<EncField> {
  const nonce = new Uint8Array(12)
  crypto.getRandomValues(nonce)
  const encoded = new TextEncoder().encode(plaintext)
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, dataKey, encoded),
  )
  return { ciphertext: b64encode(ciphertext), nonce: b64encode(nonce) }
}

export async function decryptField(field: EncField, dataKey: CryptoKey): Promise<string> {
  const ciphertext = b64decode(field.ciphertext)
  const nonce = b64decode(field.nonce)
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, dataKey, ciphertext)
  return new TextDecoder().decode(plaintext)
}

const COMMON_PASSWORDS = new Set([
  '123456', '123456789', '12345678', '1234567', '12345', '1234567890',
  '1234', '123123', '123321', '111111', '000000', '666666', '121212',
  '112233', '654321', '222222', '777777', '888888', '999999',
  'password', 'password1', 'password123', 'passw0rd', 'p@ssw0rd',
  'iloveyou', 'princess', 'sunshine', 'shadow', 'monkey', 'monkey1',
  'dragon', 'master', 'master1', 'letmein', 'login', 'admin',
  'administrator', 'welcome', 'welcome1', 'qwerty', 'qwerty123',
  'qwertyuiop', 'asdfghjkl', 'zxcvbnm', 'abc123', 'abcd1234',
  'trustno1', 'starwars', 'superman', 'batman', 'spiderman',
  'football', 'baseball', 'basketball', 'soccer', 'hockey',
  'whatever', 'freedom', 'ninja', 'mustang', 'michael', 'jennifer',
  'jordan23', 'hunter2', 'access', 'flower', 'hottie', 'loveme',
  'charlie', 'donald', 'andrew', 'daniel', 'matthew', 'joshua',
  'george', 'thomas', 'robert', 'buster', 'harley', 'ranger',
  'tigger', 'soccer1', 'cheese', 'summer', 'winter', 'autumn',
  '1q2w3e4r', '1qaz2wsx', 'qazwsx', 'zaq12wsx', 'q1w2e3r4',
  'rockyou', 'changeme', 'letmein1', 'iloveyou1', 'senha',
  'senha123', 'brasil', 'brasil123', 'vasco', 'flamengo', 'corinthians',
  'palmeiras', 'internacional', 'gremio', '12345678910',
  'aaaaaa', 'bbbbbb', '111222', 'asdf1234', 'test1234', 'temp1234',
])

const KEYBOARD_ROWS = ['1234567890', 'qwertyuiop', 'asdfghjkl', 'zxcvbnm']

function isSequential(lowered: string): boolean {
  if (lowered.length < 6) return false
  let ascending = true
  let descending = true
  for (let i = 0; i < lowered.length - 1; i++) {
    const diff = lowered.charCodeAt(i + 1) - lowered.charCodeAt(i)
    if (diff !== 1) ascending = false
    if (diff !== -1) descending = false
  }
  return ascending || descending
}

function isSingleCharacter(lowered: string): boolean {
  return new Set(lowered).size === 1
}

function isKeyboardWalk(lowered: string): boolean {
  if (lowered.length < 6) return false
  return KEYBOARD_ROWS.some(
    (row) => row.includes(lowered) || row.split('').reverse().join('').includes(lowered),
  )
}

export function isCommonPassword(password: string): boolean {
  const lowered = password.trim().toLowerCase()
  return (
    COMMON_PASSWORDS.has(lowered) ||
    isSingleCharacter(lowered) ||
    isSequential(lowered) ||
    isKeyboardWalk(lowered)
  )
}
```

- [ ] **Step 3: Type-check**

Run: `cd frontend && npx tsc --noEmit`
Expected: no errors. (Full runtime verification of this module happens in Task 7, in a real browser — `hash-wasm`'s WASM loading and `window.crypto.subtle` both need a real browser context, not Node.)

---

### Task 5: Frontend — `api.ts`, `Login.tsx`, `Register.tsx`

**Files:**
- Modify: `frontend/src/api.ts`
- Modify: `frontend/src/pages/Login.tsx`
- Modify: `frontend/src/pages/Register.tsx`

**Interfaces:**
- Consumes: everything from Task 4 (`crypto.ts`); backend contracts from Task 2 (`/auth/login/init`, `/auth/register`, `/auth/login`) — matches exactly, no new backend calls needed here since Task 2 is already done.
- Produces: `api.loginInit`, `api.register` (new signature), `api.login` (new signature), `EntryBlob` type — consumed by Task 6.

- [ ] **Step 1: Rewrite `api.ts`**

Replace `frontend/src/api.ts` entirely with:

```typescript
import { clearSessionKek } from './crypto'

const API_BASE = '/api/v1'

function getToken(): string | null {
  return localStorage.getItem('access_token')
}

export function setTokens(access: string, refresh: string) {
  localStorage.setItem('access_token', access)
  localStorage.setItem('refresh_token', refresh)
}

export function clearTokens() {
  localStorage.removeItem('access_token')
  localStorage.removeItem('refresh_token')
}

async function request<T>(
  path: string,
  opts: RequestInit = {},
  auth = true,
): Promise<T> {
  const headers: HeadersInit = {
    'Content-Type': 'application/json',
    ...(opts.headers || {}),
  }
  if (auth) {
    const token = getToken()
    if (token) headers['Authorization'] = `Bearer ${token}`
  }
  const res = await fetch(`${API_BASE}${path}`, { ...opts, headers })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(err.detail || `HTTP ${res.status}`)
  }
  if (res.status === 204) return undefined as T
  return res.json()
}

export interface EntryListItem {
  id: string
  title: string
  site: string | null
  tags: string
  created_at: string
  updated_at: string
}

export interface EntryBlob extends EntryListItem {
  username_enc: string
  nonce_username: string
  password_enc: string
  nonce_password: string
  notes_enc: string | null
  nonce_notes: string | null
  wrapped_data_key: string
  wrapped_nonce: string
}

export const api = {
  loginInit: (email: string) =>
    request<{ salt_auth: string; salt_crypto: string }>('/auth/login/init', {
      method: 'POST',
      body: JSON.stringify({ email }),
    }, false),

  register: (email: string, salt_auth: string, salt_crypto: string, auth_key: string) =>
    request<{ id: string; email: string }>('/auth/register', {
      method: 'POST',
      body: JSON.stringify({ email, salt_auth, salt_crypto, auth_key }),
    }, false),

  login: (email: string, auth_key: string) =>
    request<{ access_token: string; refresh_token: string }>('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, auth_key }),
    }, false),

  logout: () => {
    const refresh = localStorage.getItem('refresh_token')
    if (refresh) {
      request('/auth/logout', {
        method: 'POST',
        body: JSON.stringify({ refresh_token: refresh }),
      }, false).catch(() => {})
    }
    clearTokens()
    clearSessionKek()
  },

  listEntries: () => request<EntryListItem[]>('/entries'),

  getEntry: (id: string) => request<EntryBlob>(`/entries/${id}`),

  createEntry: (data: Omit<EntryBlob, 'id' | 'created_at' | 'updated_at'>) =>
    request<EntryBlob>('/entries', { method: 'POST', body: JSON.stringify(data) }),

  updateEntry: (id: string, data: Omit<EntryBlob, 'id' | 'created_at' | 'updated_at'>) =>
    request<EntryBlob>(`/entries/${id}`, { method: 'PUT', body: JSON.stringify(data) }),

  deleteEntry: (id: string) =>
    request<void>(`/entries/${id}`, { method: 'DELETE' }),

  search: (q: string) =>
    request<EntryListItem[]>(`/entries/search?q=${encodeURIComponent(q)}`),

  generatePassword: (length = 20, use_symbols = true) =>
    request<{ password: string }>('/entries/generate/password', {
      method: 'POST',
      body: JSON.stringify({ length, use_symbols }),
    }),
}
```

- [ ] **Step 2: Rewrite `Login.tsx`**

In `frontend/src/pages/Login.tsx`, replace the imports and `submit` function:

```tsx
import { useState, FormEvent } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { api, setTokens } from '../api'
import { deriveAuthKey, deriveKek, setSessionKek } from '../crypto'

export default function Login({ onLogin }: { onLogin: () => void }) {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const nav = useNavigate()

  async function submit(e: FormEvent) {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const salts = await api.loginInit(email)
      const authKey = await deriveAuthKey(password, salts.salt_auth)
      const kek = await deriveKek(password, salts.salt_crypto)
      const res = await api.login(email, authKey)
      setTokens(res.access_token, res.refresh_token)
      setSessionKek(kek)
      onLogin()
      nav('/')
    } catch (err: any) {
      setError(err.message || 'Erro ao entrar')
    } finally {
      setLoading(false)
    }
  }
```

(The rest of the file — the JSX form — is unchanged.)

- [ ] **Step 3: Rewrite `Register.tsx`**

In `frontend/src/pages/Register.tsx`, replace the imports and `submit` function:

```tsx
import { useState, FormEvent } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { api, setTokens } from '../api'
import { deriveAuthKey, deriveKek, randomSaltB64, isCommonPassword, setSessionKek } from '../crypto'

export default function Register() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  async function submit(e: FormEvent) {
    e.preventDefault()
    setError('')
    if (password.length < 12) {
      setError('Senha-mestra precisa ter no mínimo 12 caracteres')
      return
    }
    if (isCommonPassword(password)) {
      setError('Senha-mestra é muito comum, escolha uma mais forte')
      return
    }
    if (password !== confirm) {
      setError('As senhas não coincidem')
      return
    }
    setLoading(true)
    try {
      const saltAuth = randomSaltB64()
      const saltCrypto = randomSaltB64()
      const authKey = await deriveAuthKey(password, saltAuth)
      await api.register(email, saltAuth, saltCrypto, authKey)
      const res = await api.login(email, authKey)
      setTokens(res.access_token, res.refresh_token)
      const kek = await deriveKek(password, saltCrypto)
      setSessionKek(kek)
      window.location.href = '/'
    } catch (err: any) {
      setError(err.message || 'Erro ao criar conta')
    } finally {
      setLoading(false)
    }
  }
```

(The `nav` variable and its `useNavigate()` call are no longer used in `Register.tsx` since navigation now happens via `window.location.href` as before — leave that line exactly as it already is in the current file; only `submit` and the import line change.)

(The rest of the file — the JSX form — is unchanged.)

- [ ] **Step 4: Type-check**

Run: `cd frontend && npx tsc --noEmit`
Expected: no errors.

---

### Task 6: Frontend — `EntryForm.tsx`, `EntryDetail.tsx`

**Files:**
- Modify: `frontend/src/pages/EntryForm.tsx`
- Modify: `frontend/src/pages/EntryDetail.tsx`

**Interfaces:**
- Consumes: `crypto.ts` (Task 4), `api.ts`'s `EntryBlob`/`getEntry`/`createEntry`/`updateEntry` (Task 5).
- Produces: nothing further downstream — this is the last code task before end-to-end verification (Task 7).

- [ ] **Step 1: Rewrite `EntryForm.tsx`**

Replace the imports, state, `useEffect`, and `submit` function in `frontend/src/pages/EntryForm.tsx`:

```tsx
import { useEffect, useState, FormEvent } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { api } from '../api'
import {
  generateDataKey, wrapDataKey, unwrapDataKey, encryptField, decryptField, getSessionKek,
} from '../crypto'

export default function EntryForm() {
  const { id } = useParams<{ id: string }>()
  const isEdit = !!id
  const nav = useNavigate()

  const [title, setTitle] = useState('')
  const [site, setSite] = useState('')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [notes, setNotes] = useState('')
  const [tags, setTags] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [generating, setGenerating] = useState(false)
  const [dataKey, setDataKey] = useState<CryptoKey | null>(null)

  useEffect(() => {
    if (!id) return
    api.getEntry(id).then(async (e) => {
      const kek = getSessionKek()
      const key = await unwrapDataKey(
        { wrapped_data_key: e.wrapped_data_key, wrapped_nonce: e.wrapped_nonce },
        kek,
      )
      setDataKey(key)
      setTitle(e.title)
      setSite(e.site || '')
      setUsername(await decryptField({ ciphertext: e.username_enc, nonce: e.nonce_username }, key))
      setPassword(await decryptField({ ciphertext: e.password_enc, nonce: e.nonce_password }, key))
      setNotes(
        e.notes_enc
          ? await decryptField({ ciphertext: e.notes_enc, nonce: e.nonce_notes! }, key)
          : '',
      )
      setTags(e.tags)
    })
  }, [id])

  async function submit(ev: FormEvent) {
    ev.preventDefault()
    setError('')
    setLoading(true)
    try {
      const kek = getSessionKek()
      const key = dataKey || (await generateDataKey())
      const wrapped = await wrapDataKey(key, kek)
      const u = await encryptField(username, key)
      const p = await encryptField(password, key)
      const n = notes ? await encryptField(notes, key) : null

      const data = {
        title,
        site: site || null,
        username_enc: u.ciphertext,
        nonce_username: u.nonce,
        password_enc: p.ciphertext,
        nonce_password: p.nonce,
        notes_enc: n ? n.ciphertext : null,
        nonce_notes: n ? n.nonce : null,
        wrapped_data_key: wrapped.wrapped_data_key,
        wrapped_nonce: wrapped.wrapped_nonce,
        tags,
      }
      if (isEdit) {
        await api.updateEntry(id!, data)
      } else {
        await api.createEntry(data)
      }
      nav('/')
    } catch (e: any) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  async function generate() {
    setGenerating(true)
    try {
      const res = await api.generatePassword(24, true)
      setPassword(res.password)
    } catch (e: any) {
      setError(e.message)
    } finally {
      setGenerating(false)
    }
  }
```

(The rest of the file — the JSX form starting at `return (`  — is unchanged.)

- [ ] **Step 2: Rewrite `EntryDetail.tsx`**

Replace the imports and the top of the component in `frontend/src/pages/EntryDetail.tsx`:

```tsx
import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api } from '../api'
import { unwrapDataKey, decryptField, getSessionKek } from '../crypto'

interface DecryptedEntry {
  id: string
  title: string
  site: string | null
  username: string
  password: string
  notes: string | null
  tags: string
}

export default function EntryDetail() {
  const { id } = useParams<{ id: string }>()
  const [entry, setEntry] = useState<DecryptedEntry | null>(null)
  const [showPassword, setShowPassword] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    if (!id) return
    ;(async () => {
      try {
        const e = await api.getEntry(id)
        const kek = getSessionKek()
        const key = await unwrapDataKey(
          { wrapped_data_key: e.wrapped_data_key, wrapped_nonce: e.wrapped_nonce },
          kek,
        )
        const username = await decryptField({ ciphertext: e.username_enc, nonce: e.nonce_username }, key)
        const password = await decryptField({ ciphertext: e.password_enc, nonce: e.nonce_password }, key)
        const notes = e.notes_enc
          ? await decryptField({ ciphertext: e.notes_enc, nonce: e.nonce_notes! }, key)
          : null
        setEntry({ id: e.id, title: e.title, site: e.site, username, password, notes, tags: e.tags })
      } catch (err: any) {
        setError(err.message)
      }
    })()
  }, [id])
```

(`useNavigate`/`nav` was already used further down for the `remove()` function — keep that import and usage exactly as in the current file; only the top block shown above changes. The rest of the file, from the `copy`/`remove` functions through the JSX, is unchanged — it already reads `entry.username`/`entry.password`/`entry.notes`/`entry.tags`, which still exist on `DecryptedEntry`.)

- [ ] **Step 3: Type-check**

Run: `cd frontend && npx tsc --noEmit`
Expected: no errors.

---

### Task 7: End-to-end verification (real Docker, real browser)

**Files:** none (verification only).

**Interfaces:** none — this task only exercises everything built in Tasks 1-6 together.

- [ ] **Step 1: Run the full backend test suite**

Run: `cd /home/matheusaraujosami/Documentos/vaultlocal && make test`
Expected: all tests PASS (this now includes the rewritten `test_auth.py`/`test_entries.py` from Tasks 2-3).

- [ ] **Step 2: Rebuild and restart the real stack**

Run:
```bash
cd /home/matheusaraujosami/Documentos/vaultlocal
sudo docker compose build api web
sudo docker compose up -d
sudo docker compose exec api alembic current
```
Expected: `alembic current` prints the Task 1 migration's revision id followed by `(head)`. `sudo docker compose ps` shows all three containers `Up`.

- [ ] **Step 3: Browser walkthrough — register, create entry, view it decrypted**

Using the Playwright browser tools:
1. Navigate to `http://127.0.0.1:8080/register`.
2. Fill email `e2e@test.com`, password `Xk9#mQ2vLp7$WzE2E` (12+ chars, not in the common list) in both password fields, submit.
3. Confirm the page lands on the empty vault (`/`) with no console errors (check via the browser console-messages tool).
4. Click "Nova entrada"; fill title `Test Site`, username `e2euser`, password `s3cr3t-e2e-pass`, notes `e2e note`; submit.
5. Confirm redirect to `/` and the new entry titled "Test Site" appears in the list.
6. Click the entry, click "Mostrar" to reveal the password.
7. Take an accessibility snapshot or screenshot; confirm the visible username is `e2euser`, the revealed password is `s3cr3t-e2e-pass`, and the notes read `e2e note` — i.e., the round trip through Argon2id + AES-GCM in the real browser reproduces the original plaintext.

Expected: every value matches what was typed in step 4; no console errors at any point.

- [ ] **Step 4: Confirm the KEK really doesn't survive a reload**

Reload the entry detail page (full page reload, not client-side navigation).
Expected: the page errors out (surfaces the `vault locked, login again` message from `getSessionKek()`) instead of showing the entry, because `sessionKek` is an in-memory module variable that a reload resets to `null`. This confirms the KEK is not being persisted anywhere (`localStorage`, cookies, etc.).
