import base64
import hashlib
import hmac
from datetime import datetime, timedelta, timezone

import pyotp
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ..config import settings
from ..deps import get_db, get_current_user, get_mfa_pending_user
from ..models import User, Session, VaultEntry
from ..schemas import (
    RegisterIn, LoginInitIn, LoginInitOut, LoginIn, LoginOut, TokenOut, RefreshIn,
    ChangePasswordIn, TotpSetupOut, TotpCodeIn,
)
from ..core.security import (
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token,
    create_mfa_token,
    verify_token,
    lockout_duration_minutes,
    LOCKOUT_THRESHOLD,
)
from ..core.totp import encrypt_totp_secret, decrypt_totp_secret
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


def _b64decode(value: str, field_name: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except Exception:
        raise HTTPException(400, f"invalid base64 in {field_name}")


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
@limiter.limit("5/minute")
async def register(request: Request, body: RegisterIn, db: AsyncSession = Depends(get_db)):
    existing = await db.scalar(select(User).where(User.email == body.email))
    if existing:
        raise HTTPException(409, "email already registered")
    salt_auth = _b64decode(body.salt_auth, "salt_auth")
    salt_crypto = _b64decode(body.salt_crypto, "salt_crypto")
    if len(salt_auth) != 16:
        raise HTTPException(400, "invalid base64 in salt_auth")
    if len(salt_crypto) != 16:
        raise HTTPException(400, "invalid base64 in salt_crypto")
    user = User(
        email=body.email,
        auth_hash=hash_password(body.auth_key),
        salt_auth=salt_auth,
        salt_crypto=salt_crypto,
    )
    db.add(user)
    await db.commit()
    return {"id": user.id, "email": user.email}


@router.post("/login", response_model=LoginOut)
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
    await db.commit()

    mfa_token = create_mfa_token(user.id)
    status_value = "mfa_setup_required" if not user.mfa_configured else "mfa_verify_required"
    return LoginOut(status=status_value, mfa_token=mfa_token)


async def _issue_session_tokens(db: AsyncSession, user_id: str) -> TokenOut:
    # Cleanup expired sessions for this user
    expired_sessions = list(await db.scalars(
        select(Session).where(Session.user_id == user_id, Session.expires_at < datetime.now(timezone.utc))
    ))
    for s in expired_sessions:
        await db.delete(s)

    access = create_access_token(user_id)
    refresh = create_refresh_token(user_id)
    session = Session(
        user_id=user_id,
        refresh_hash=hash_password(refresh),
        expires_at=datetime.now(timezone.utc) + timedelta(days=7),
    )
    db.add(session)
    await db.commit()
    return TokenOut(access_token=access, refresh_token=refresh)


@router.post("/totp/setup", response_model=TotpSetupOut)
async def totp_setup(
    user: User = Depends(get_mfa_pending_user), db: AsyncSession = Depends(get_db)
):
    if user.mfa_configured:
        raise HTTPException(409, "TOTP already configured")
    secret = pyotp.random_base32()
    user.totp_secret_enc = encrypt_totp_secret(secret)
    await db.commit()
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=user.email, issuer_name="VaultLocal")
    return TotpSetupOut(secret=secret, otpauth_uri=uri)


@router.post("/totp/confirm", response_model=TokenOut)
@limiter.limit("5/minute")
async def totp_confirm(
    request: Request,
    body: TotpCodeIn,
    user: User = Depends(get_mfa_pending_user),
    db: AsyncSession = Depends(get_db),
):
    if user.mfa_configured:
        raise HTTPException(409, "TOTP already configured")
    if not user.totp_secret_enc:
        raise HTTPException(400, "call /auth/totp/setup first")

    now = datetime.now(timezone.utc)
    locked_until = _aware(user.totp_locked_until)
    if locked_until and locked_until > now:
        retry_after = max(1, int((locked_until - now).total_seconds()))
        raise HTTPException(429, f"totp locked, try again in {retry_after}s")

    secret = decrypt_totp_secret(user.totp_secret_enc)
    if not pyotp.TOTP(secret).verify(body.totp_code, valid_window=1):
        user.totp_failed_attempts += 1
        if user.totp_failed_attempts >= LOCKOUT_THRESHOLD:
            minutes = lockout_duration_minutes(user.totp_failed_attempts)
            user.totp_locked_until = now + timedelta(minutes=minutes)
        await db.commit()
        raise HTTPException(401, "invalid totp code")
    user.totp_failed_attempts = 0
    user.totp_locked_until = None
    user.mfa_configured = True
    await db.commit()
    return await _issue_session_tokens(db, user.id)


@router.post("/mfa/verify", response_model=TokenOut)
@limiter.limit("5/minute")
async def mfa_verify(
    request: Request,
    body: TotpCodeIn,
    user: User = Depends(get_mfa_pending_user),
    db: AsyncSession = Depends(get_db),
):
    now = datetime.now(timezone.utc)
    locked_until = _aware(user.totp_locked_until)
    if locked_until and locked_until > now:
        retry_after = max(1, int((locked_until - now).total_seconds()))
        raise HTTPException(429, f"totp locked, try again in {retry_after}s")

    if not user.mfa_configured or not user.totp_secret_enc:
        raise HTTPException(400, "totp not configured")

    secret = decrypt_totp_secret(user.totp_secret_enc)
    if not pyotp.TOTP(secret).verify(body.totp_code, valid_window=1):
        user.totp_failed_attempts += 1
        if user.totp_failed_attempts >= LOCKOUT_THRESHOLD:
            minutes = lockout_duration_minutes(user.totp_failed_attempts)
            user.totp_locked_until = now + timedelta(minutes=minutes)
        await db.commit()
        raise HTTPException(401, "invalid totp code")

    user.totp_failed_attempts = 0
    user.totp_locked_until = None
    return await _issue_session_tokens(db, user.id)


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

    new_salt_auth = _b64decode(body.new_salt_auth, "new_salt_auth")
    new_salt_crypto = _b64decode(body.new_salt_crypto, "new_salt_crypto")

    entries = list(await db.scalars(select(VaultEntry).where(VaultEntry.user_id == user.id)))
    entry_by_id = {e.id: e for e in entries}
    incoming_ids = {item.id for item in body.entries}
    if incoming_ids != set(entry_by_id.keys()) or len(body.entries) != len(incoming_ids):
        raise HTTPException(400, "entries payload must cover exactly the user's current entries")

    for item in body.entries:
        entry = entry_by_id[item.id]
        entry.wrapped_data_key = item.wrapped_data_key
        entry.wrapped_nonce = item.wrapped_nonce

    user.auth_hash = hash_password(body.new_auth_key)
    user.salt_auth = new_salt_auth
    user.salt_crypto = new_salt_crypto

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
