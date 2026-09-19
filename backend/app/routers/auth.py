from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ..deps import get_db, get_current_user
from ..models import User, Session, VaultEntry
from ..schemas import RegisterIn, LoginIn, TokenOut, RefreshIn, ChangePasswordIn
from ..core.security import (
    hash_password,
    verify_password,
    generate_salt,
    derive_kek,
    encrypt,
    decrypt,
    create_access_token,
    create_refresh_token,
    verify_token,
    lockout_duration_minutes,
    LOCKOUT_THRESHOLD,
)
from ..core.kekstore import set_kek, clear_kek
from ..core.common_passwords import is_common_password
from ..core.limiter import limiter

router = APIRouter(prefix="/auth", tags=["auth"])


def _aware(dt: datetime | None) -> datetime | None:
    """SQLite drops tzinfo on read; Postgres keeps it. Normalize to UTC-aware
    so comparisons against datetime.now(timezone.utc) never crash."""
    if dt is None or dt.tzinfo is not None:
        return dt
    return dt.replace(tzinfo=timezone.utc)


@router.post("/register", status_code=201)
async def register(body: RegisterIn, db: AsyncSession = Depends(get_db)):
    existing = await db.scalar(select(User).where(User.email == body.email))
    if existing:
        raise HTTPException(409, "email already registered")
    if is_common_password(body.master_password):
        raise HTTPException(400, "master password is too common, choose a stronger one")
    salt_auth = generate_salt()
    salt_crypto = generate_salt()
    auth_hash = hash_password(body.master_password)
    user = User(
        email=body.email,
        auth_hash=auth_hash,
        salt_auth=salt_auth,
        salt_crypto=salt_crypto,
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

    if not user or not verify_password(body.master_password, user.auth_hash):
        if user:
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= LOCKOUT_THRESHOLD:
                minutes = lockout_duration_minutes(user.failed_login_attempts)
                user.locked_until = now + timedelta(minutes=minutes)
            await db.commit()
        raise HTTPException(401, "invalid credentials")

    user.failed_login_attempts = 0
    user.locked_until = None

    # derive KEK and tuck it in session
    kek = derive_kek(body.master_password, user.salt_crypto)
    set_kek(user.id, kek)

    access = create_access_token(user.id)
    refresh = create_refresh_token(user.id)
    refresh_hash = hash_password(refresh)
    session = Session(
        user_id=user.id,
        refresh_hash=refresh_hash,
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

    # verify against stored session
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
    if not verify_password(body.old_master_password, user.auth_hash):
        raise HTTPException(401, "invalid credentials")
    if is_common_password(body.new_master_password):
        raise HTTPException(400, "master password is too common, choose a stronger one")

    old_kek = derive_kek(body.old_master_password, user.salt_crypto)
    new_salt_crypto = generate_salt()
    new_kek = derive_kek(body.new_master_password, new_salt_crypto)

    # decrypt everything under the old KEK before mutating anything, so a
    # corrupt row aborts cleanly instead of leaving entries half-migrated
    entries = list(await db.scalars(select(VaultEntry).where(VaultEntry.user_id == user.id)))
    plaintexts = [
        (
            decrypt(e.username_enc, e.nonce_username, old_kek),
            decrypt(e.password_enc, e.nonce_password, old_kek),
            decrypt(e.notes_enc, e.nonce_notes, old_kek) if e.notes_enc else None,
        )
        for e in entries
    ]

    for entry, (username, password, notes) in zip(entries, plaintexts):
        u = encrypt(username, new_kek)
        p = encrypt(password, new_kek)
        entry.username_enc, entry.nonce_username = u["ciphertext"], u["nonce"]
        entry.password_enc, entry.nonce_password = p["ciphertext"], p["nonce"]
        if notes is not None:
            n = encrypt(notes, new_kek)
            entry.notes_enc, entry.nonce_notes = n["ciphertext"], n["nonce"]
        else:
            entry.notes_enc, entry.nonce_notes = None, None

    user.auth_hash = hash_password(body.new_master_password)
    user.salt_crypto = new_salt_crypto

    # password change invalidates every existing session; issue a fresh one
    # for the device making this request
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

    set_kek(user.id, new_kek)
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
    clear_kek(user_id)
    await db.commit()
    return {"ok": True}
