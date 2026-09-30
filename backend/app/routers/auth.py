import asyncio
import base64
import binascii
import hashlib
import hmac
import json
import logging
import secrets
import smtplib
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

import pyotp
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from webauthn import verify_authentication_response, verify_registration_response

from ..config import settings
from ..core.audit import record_security_event
from ..core.limiter import limiter
from ..core.security import (
    DUMMY_AUTH_HASH,
    LOCKOUT_THRESHOLD,
    create_access_token,
    create_google_handoff_token,
    create_mfa_token,
    create_oidc_state_token,
    create_recovery_token,
    create_refresh_token,
    hash_password,
    hash_reset_token,
    lockout_duration_minutes,
    verify_google_handoff_token,
    verify_oidc_state_token,
    verify_password,
    verify_token,
)
from ..core.totp import decrypt_totp_secret, encrypt_totp_secret
from ..deps import (
    get_current_session_context,
    get_current_user,
    get_db,
    get_mfa_pending_user,
    get_recovery_pending_user,
)
from ..models import (
    HealthReport,
    PasswordResetToken,
    Session,
    User,
    VaultEntry,
    WebAuthnChallenge,
    WebAuthnCredential,
)
from ..oidc import google_authorization_url, google_id_token_claims
from ..schemas import (
    ChangePasswordIn,
    GoogleCompleteIn,
    GoogleHandoffOut,
    GooglePasswordIn,
    LoginIn,
    LoginInitIn,
    LoginInitOut,
    LoginOut,
    PasswordResetConfirmIn,
    PasswordResetRequestIn,
    PasswordResetRequestOut,
    PasswordResetValidateIn,
    RecoverIn,
    RecoveryEntry,
    RecoveryInitIn,
    RecoveryInitOut,
    RecoverySetupIn,
    RecoveryUpgradeIn,
    RecoveryVerifyIn,
    RecoveryVerifyOut,
    RefreshIn,
    RegisterIn,
    SessionOut,
    SessionsOut,
    TokenOut,
    TotpCodeIn,
    TotpSetupOut,
    WebAuthnDeviceOut,
    WebAuthnDeviceRenameIn,
    WebAuthnDeviceRevokeIn,
    WebAuthnDevicesOut,
    WebAuthnEnvelopeIn,
    WebAuthnLocalOptionsIn,
    WebAuthnLoginOptionsOut,
    WebAuthnLoginOut,
    WebAuthnLoginVerifyIn,
    WebAuthnRegisterOptionsOut,
    WebAuthnRegisterVerifyIn,
)
from ..webauthn_support import (
    authentication_options,
    b64url_decode,
    b64url_encode,
    registration_options,
)

router = APIRouter(prefix="/auth", tags=["auth"])
logger = logging.getLogger(__name__)


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
    except (binascii.Error, ValueError):
        raise HTTPException(400, f"invalid base64 in {field_name}") from None


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _verify_recovery_signature(public_key_json: str, challenge: bytes, signature: bytes) -> bool:
    try:
        jwk = json.loads(public_key_json)
        if (
            jwk.get("kty") != "EC"
            or jwk.get("crv") != "P-256"
            or jwk.get("alg") not in {None, "ES256"}
            or not isinstance(jwk.get("x"), str)
            or not isinstance(jwk.get("y"), str)
            or len(signature) != 64
        ):
            return False
        x = int.from_bytes(_b64url_decode(jwk["x"]), "big")
        y = int.from_bytes(_b64url_decode(jwk["y"]), "big")
        public_key = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
        r = int.from_bytes(signature[:32], "big")
        s = int.from_bytes(signature[32:], "big")
        public_key.verify(encode_dss_signature(r, s), challenge, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, AttributeError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        return False


@router.post("/login/init", response_model=LoginInitOut)
@limiter.limit("10/minute")
async def login_init(request: Request, body: LoginInitIn, db: AsyncSession = Depends(get_db)):
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

    auth_hash = user.auth_hash if user else DUMMY_AUTH_HASH
    credentials_valid = verify_password(body.auth_key, auth_hash)
    if not user or not credentials_valid:
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
    if not user.mfa_configured:
        status_value = "mfa_setup_required"
    elif not user.recovery_wrapped_kek:
        status_value = "recovery_setup_required"
    else:
        status_value = "mfa_verify_required"
    return LoginOut(
        status=status_value,
        mfa_token=mfa_token,
        recovery_upgrade_required=bool(user.recovery_wrapped_kek and not user.recovery_public_key),
    )


async def _issue_session_tokens(
    db: AsyncSession, user_id: str, event_type: str | None = 'login_success'
) -> TokenOut:
    # Cleanup expired sessions for this user
    expired_sessions = list(await db.scalars(
        select(Session).where(Session.user_id == user_id, Session.expires_at < datetime.now(timezone.utc))
    ))
    for s in expired_sessions:
        await db.delete(s)

    refresh = create_refresh_token(user_id)
    session_id = str(uuid.uuid4())
    session = Session(
        id=session_id,
        user_id=user_id,
        refresh_hash=hash_password(refresh),
        expires_at=datetime.now(timezone.utc) + timedelta(days=7),
    )
    db.add(session)
    if event_type:
        await record_security_event(db, user_id, event_type)
    access = create_access_token(user_id, session_id)
    await db.commit()
    return TokenOut(access_token=access, refresh_token=refresh)


def _fake_recovery_blob(email: str, name: str, length: int) -> str:
    digest = hmac.new(settings.JWT_SECRET.encode(), f"recovery:{name}:{email}".encode(), hashlib.sha256).digest()
    return base64.b64encode((digest * ((length + 31) // 32))[:length]).decode()


def _client_ip(request: Request) -> str:
    return request.headers.get("x-real-ip") or (request.client.host if request.client else "")


def _oidc_cookie_secure(request: Request) -> bool:
    return request.url.scheme == "https"


def _frontend_login_url() -> str:
    parsed = urlsplit(settings.GOOGLE_REDIRECT_URI)
    if not parsed.scheme or not parsed.netloc:
        raise HTTPException(500, "Google redirect URI is invalid")
    return f"{parsed.scheme}://{parsed.netloc}/login"


def _set_oidc_state_cookie(response: Response, value: str, request: Request) -> None:
    response.set_cookie(
        "vaultlocal_oidc_state",
        value,
        max_age=600,
        httponly=True,
        secure=_oidc_cookie_secure(request),
        samesite="lax",
        path="/api/v1/auth/oidc/google",
    )


def _set_google_handoff_cookie(response: Response, value: str, request: Request) -> None:
    response.set_cookie(
        "vaultlocal_google_handoff",
        value,
        max_age=300,
        httponly=True,
        secure=_oidc_cookie_secure(request),
        samesite="lax",
        path="/api/v1/auth",
    )


def _clear_oidc_cookie(response: Response, name: str) -> None:
    if name == "vaultlocal_google_handoff":
        response.delete_cookie(name, path="/api/v1/auth")
        return
    response.delete_cookie(name, path="/api/v1/auth/oidc/google")


@router.get("/oidc/google/start")
@limiter.limit("5/minute")
async def google_start(request: Request):
    authorization_url, state, nonce, code_verifier = await google_authorization_url()
    state_token = create_oidc_state_token(state, nonce, code_verifier)
    response = RedirectResponse(authorization_url, status_code=302)
    _set_oidc_state_cookie(response, state_token, request)
    return response


@router.get("/oidc/google/callback")
@limiter.limit("10/minute")
async def google_callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    response = RedirectResponse(_frontend_login_url(), status_code=302)
    state_token = request.cookies.get("vaultlocal_oidc_state")
    _clear_oidc_cookie(response, "vaultlocal_oidc_state")

    if error or not code or not state or not state_token:
        response.headers["Location"] = f"{_frontend_login_url()}?oauth_error=google_failed"
        return response

    try:
        state_data = verify_oidc_state_token(state_token)
        if not hmac.compare_digest(state, state_data["state"]):
            raise ValueError("OIDC state mismatch")
        identity = await google_id_token_claims(
            code,
            state,
            state_data["nonce"],
            state_data["code_verifier"],
        )
    except (HTTPException, ValueError):
        response.headers["Location"] = f"{_frontend_login_url()}?oauth_error=google_failed"
        return response

    email = identity["email"].lower()
    google_sub = identity["sub"]
    user = await db.scalar(select(User).where(User.google_sub == google_sub))
    if user is None:
        user = await db.scalar(select(User).where(User.email == email))
        if user is not None:
            if user.google_sub and user.google_sub != google_sub:
                response.headers["Location"] = f"{_frontend_login_url()}?oauth_error=google_failed"
                return response
            user.google_sub = google_sub
            user.auth_method = "google"
            await db.commit()

    handoff = create_google_handoff_token(email, google_sub, user.id if user else None)
    _set_google_handoff_cookie(response, handoff, request)
    response.headers["Location"] = f"{_frontend_login_url()}?google=1"
    return response


@router.get("/oidc/google/exchange", response_model=GoogleHandoffOut)
async def google_exchange(request: Request, db: AsyncSession = Depends(get_db)):
    handoff_token = request.cookies.get("vaultlocal_google_handoff")
    if not handoff_token:
        raise HTTPException(401, "Google sign-in session expired")
    try:
        data = verify_google_handoff_token(handoff_token)
    except ValueError:
        raise HTTPException(401, "Google sign-in session expired") from None

    if data["sub"] == "new":
        return GoogleHandoffOut(status="setup_required", email=data["email"])

    user = await db.get(User, data["sub"])
    if user is None or user.google_sub != data["google_sub"]:
        raise HTTPException(401, "Google sign-in session expired")
    return GoogleHandoffOut(
        status="existing",
        email=user.email,
        salt_auth=base64.b64encode(user.salt_auth).decode(),
        salt_crypto=base64.b64encode(user.salt_crypto).decode(),
    )


@router.post("/oidc/google/password", response_model=LoginOut)
@limiter.limit("5/minute")
async def google_password(
    request: Request,
    response: Response,
    body: GooglePasswordIn,
    db: AsyncSession = Depends(get_db),
):
    handoff_token = request.cookies.get("vaultlocal_google_handoff")
    if not handoff_token:
        raise HTTPException(401, "Google sign-in session expired")
    try:
        data = verify_google_handoff_token(handoff_token)
    except ValueError:
        raise HTTPException(401, "Google sign-in session expired") from None

    if data["sub"] == "new":
        raise HTTPException(409, "Google account setup is required")

    user = await db.get(User, data["sub"])
    if user is None or user.google_sub != data["google_sub"]:
        raise HTTPException(401, "Google sign-in session expired")

    now = datetime.now(timezone.utc)
    locked_until = _aware(user.locked_until)
    if locked_until and locked_until > now:
        retry_after = int((locked_until - now).total_seconds())
        raise HTTPException(429, f"account locked, try again in {retry_after}s")

    if not verify_password(body.auth_key, user.auth_hash):
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= LOCKOUT_THRESHOLD:
            minutes = lockout_duration_minutes(user.failed_login_attempts)
            user.locked_until = now + timedelta(minutes=minutes)
        await db.commit()
        raise HTTPException(401, "invalid credentials")

    user.failed_login_attempts = 0
    user.locked_until = None
    await db.commit()
    _clear_oidc_cookie(response, "vaultlocal_google_handoff")

    return LoginOut(
        status=(
            "mfa_setup_required"
            if not user.mfa_configured
            else "recovery_setup_required"
            if not user.recovery_wrapped_kek
            else "mfa_verify_required"
        ),
        mfa_token=create_mfa_token(user.id),
        recovery_upgrade_required=bool(user.recovery_wrapped_kek and not user.recovery_public_key),
    )


@router.post("/oidc/google/complete", response_model=LoginOut)
@limiter.limit("5/minute")
async def google_complete(
    request: Request,
    response: Response,
    body: GoogleCompleteIn,
    db: AsyncSession = Depends(get_db),
):
    handoff_token = request.cookies.get("vaultlocal_google_handoff")
    if not handoff_token:
        raise HTTPException(401, "Google sign-in session expired")
    try:
        data = verify_google_handoff_token(handoff_token)
    except ValueError:
        raise HTTPException(401, "Google sign-in session expired") from None

    if data["sub"] != "new":
        raise HTTPException(409, "Google account is already linked")

    existing_google = await db.scalar(select(User).where(User.google_sub == data["google_sub"]))
    if existing_google:
        raise HTTPException(409, "Google account is already linked")

    existing_email = await db.scalar(select(User).where(User.email == data["email"]))
    if existing_email:
        if existing_email.google_sub and existing_email.google_sub != data["google_sub"]:
            raise HTTPException(409, "email is already linked to another Google account")
        existing_email.google_sub = data["google_sub"]
        existing_email.auth_method = "google"
        await db.commit()
        _clear_oidc_cookie(response, "vaultlocal_google_handoff")
        return LoginOut(
            status=(
                "mfa_setup_required"
                if not existing_email.mfa_configured
                else "recovery_setup_required"
                if not existing_email.recovery_wrapped_kek
                else "mfa_verify_required"
            ),
            mfa_token=create_mfa_token(existing_email.id),
            recovery_upgrade_required=bool(
                existing_email.recovery_wrapped_kek and not existing_email.recovery_public_key
            ),
        )

    user = User(
        email=data["email"],
        auth_hash=hash_password(body.auth_key),
        salt_auth=_b64decode(body.new_salt_auth, "new_salt_auth"),
        salt_crypto=_b64decode(body.new_salt_crypto, "new_salt_crypto"),
        auth_method="google",
        google_sub=data["google_sub"],
    )
    db.add(user)
    await db.commit()
    _clear_oidc_cookie(response, "vaultlocal_google_handoff")
    return LoginOut(
        status="mfa_setup_required",
        mfa_token=create_mfa_token(user.id),
        recovery_upgrade_required=False,
    )


async def _verify_totp_code(user: User, code: str, db: AsyncSession) -> bool:
    now = datetime.now(timezone.utc)
    locked_until = _aware(user.totp_locked_until)
    if locked_until and locked_until > now:
        return False
    if not user.mfa_configured or not user.totp_secret_enc:
        return False
    secret = decrypt_totp_secret(user.totp_secret_enc)
    if not pyotp.TOTP(secret).verify(code, valid_window=1):
        user.totp_failed_attempts += 1
        if user.totp_failed_attempts >= LOCKOUT_THRESHOLD:
            minutes = lockout_duration_minutes(user.totp_failed_attempts)
            user.totp_locked_until = now + timedelta(minutes=minutes)
        await db.commit()
        return False
    user.totp_failed_attempts = 0
    user.totp_locked_until = None
    return True


@router.post("/recovery/setup", status_code=204)
async def recovery_setup(
    body: RecoverySetupIn,
    user: User = Depends(get_mfa_pending_user),
    db: AsyncSession = Depends(get_db),
):
    if user.recovery_wrapped_kek:
        raise HTTPException(409, "recovery key already configured")
    user.recovery_wrapped_kek = body.recovery_wrapped_kek
    user.recovery_nonce = body.recovery_nonce
    user.recovery_public_key = body.recovery_public_key
    user.recovery_wrapped_signing_key = body.recovery_wrapped_signing_key
    user.recovery_signing_nonce = body.recovery_signing_nonce
    user.recovery_verifier = None
    user.recovery_challenge_hash = None
    user.recovery_challenge_expires_at = None
    await db.commit()


@router.post("/recovery/upgrade", status_code=204)
@limiter.limit("5/minute")
async def recovery_upgrade(
    request: Request,
    body: RecoveryUpgradeIn,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if not user.recovery_wrapped_kek or not user.recovery_nonce:
        raise HTTPException(400, "recovery key is not configured")
    if user.recovery_public_key:
        raise HTTPException(409, "recovery key verifier already configured")
    user.recovery_public_key = body.recovery_public_key
    user.recovery_wrapped_signing_key = body.recovery_wrapped_signing_key
    user.recovery_signing_nonce = body.recovery_signing_nonce
    user.recovery_verifier = None
    await db.commit()


@router.post("/recovery/init", response_model=RecoveryInitOut)
@limiter.limit("5/minute")
async def recovery_init(
    request: Request, body: RecoveryInitIn, db: AsyncSession = Depends(get_db)
):
    user = await db.scalar(select(User).where(User.email == body.email))
    if not user or not user.recovery_wrapped_kek or not user.recovery_nonce:
        return RecoveryInitOut(
            salt_crypto=_fake_salt(body.email, "recovery-crypto"),
            recovery_wrapped_kek=_fake_recovery_blob(body.email, "wrap", 48),
            recovery_nonce=_fake_recovery_blob(body.email, "nonce", 12),
            recovery_challenge=base64.b64encode(secrets.token_bytes(32)).decode(),
            recovery_public_key="{}",
            recovery_wrapped_signing_key=_fake_recovery_blob(body.email, "signing", 256),
            recovery_signing_nonce=_fake_recovery_blob(body.email, "signing-nonce", 12),
        )

    challenge = secrets.token_bytes(32)
    user.recovery_challenge_hash = hashlib.sha256(challenge).hexdigest()
    user.recovery_challenge_expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
    await db.commit()
    return RecoveryInitOut(
        salt_crypto=base64.b64encode(user.salt_crypto).decode(),
        recovery_wrapped_kek=user.recovery_wrapped_kek,
        recovery_nonce=user.recovery_nonce,
        recovery_challenge=base64.b64encode(challenge).decode(),
        recovery_public_key=user.recovery_public_key or "{}",
        recovery_wrapped_signing_key=user.recovery_wrapped_signing_key or "",
        recovery_signing_nonce=user.recovery_signing_nonce or "",
    )


@router.post("/recovery/verify", response_model=RecoveryVerifyOut)
@limiter.limit("5/minute")
async def recovery_verify(
    request: Request,
    body: RecoveryVerifyIn,
    db: AsyncSession = Depends(get_db),
):
    user = await db.scalar(select(User).where(User.email == body.email))
    if not user or not user.recovery_wrapped_kek:
        raise HTTPException(401, "invalid recovery credentials")

    challenge = _b64decode(body.recovery_challenge, "recovery_challenge")
    challenge_valid = (
        user.recovery_challenge_hash is not None
        and user.recovery_challenge_expires_at is not None
        and _aware(user.recovery_challenge_expires_at) > datetime.now(timezone.utc)
        and hmac.compare_digest(
            user.recovery_challenge_hash,
            hashlib.sha256(challenge).hexdigest(),
        )
    )
    if not challenge_valid:
        raise HTTPException(401, "invalid recovery credentials")

    if not user.recovery_public_key:
        raise HTTPException(401, "invalid recovery credentials")
    signature = _b64decode(body.recovery_proof, "recovery_proof")
    if not _verify_recovery_signature(user.recovery_public_key, challenge, signature):
        raise HTTPException(401, "invalid recovery credentials")

    user.recovery_challenge_hash = None
    user.recovery_challenge_expires_at = None
    await db.commit()

    entries = await db.scalars(select(VaultEntry).where(VaultEntry.user_id == user.id))
    return RecoveryVerifyOut(
        recovery_token=create_recovery_token(user.id),
        entries=[
            RecoveryEntry(
                id=e.id,
                crypto_version=e.crypto_version,
                wrapped_data_key=e.wrapped_data_key,
                wrapped_nonce=e.wrapped_nonce,
            )
            for e in entries
        ],
    )


@router.post("/recovery/recover", response_model=TokenOut)
async def recovery_recover(
    body: RecoverIn,
    user: User = Depends(get_recovery_pending_user),
    db: AsyncSession = Depends(get_db),
):
    entries = list(await db.scalars(select(VaultEntry).where(VaultEntry.user_id == user.id)))
    entry_by_id = {e.id: e for e in entries}
    incoming_ids = {str(item.id) for item in body.entries}
    if incoming_ids != set(entry_by_id.keys()) or len(body.entries) != len(incoming_ids):
        raise HTTPException(400, "entries payload must cover exactly the user's current entries")

    for item in body.entries:
        entry = entry_by_id[str(item.id)]
        entry.wrapped_data_key = item.wrapped_data_key
        entry.wrapped_nonce = item.wrapped_nonce

    user.auth_hash = hash_password(body.new_auth_key)
    user.salt_auth = _b64decode(body.new_salt_auth, "new_salt_auth")
    user.salt_crypto = _b64decode(body.new_salt_crypto, "new_salt_crypto")
    user.recovery_wrapped_kek = body.new_recovery_wrapped_kek
    user.recovery_nonce = body.new_recovery_nonce
    user.recovery_public_key = body.new_recovery_public_key
    user.recovery_wrapped_signing_key = body.new_recovery_wrapped_signing_key
    user.recovery_signing_nonce = body.new_recovery_signing_nonce
    user.recovery_verifier = None
    user.recovery_challenge_hash = None
    user.recovery_challenge_expires_at = None

    sessions = list(await db.scalars(select(Session).where(Session.user_id == user.id)))
    for session in sessions:
        await db.delete(session)
    await record_security_event(db, user.id, "recovery_used")
    await db.commit()
    return await _issue_session_tokens(db, user.id, event_type=None)


def _reset_token_valid(row: PasswordResetToken | None) -> bool:
    return bool(row and row.used_at is None and _aware(row.expires_at) > datetime.now(timezone.utc))


def _send_reset_email(recipient: str, token: str) -> None:
    from email.message import EmailMessage

    if not settings.SMTP_HOST or not settings.SMTP_FROM:
        raise RuntimeError("SMTP reset delivery is not configured")
    message = EmailMessage()
    message["Subject"] = "VaultLocal — redefinição destrutiva da senha"
    message["From"] = settings.SMTP_FROM
    message["To"] = recipient
    message.set_content(
        "Foi solicitada uma redefinição destrutiva do VaultLocal. "
        f"Este link expira em 30 minutos e apagará o cofre atual: "
        f"{settings.RESET_URL_BASE}?reset={token}"
    )
    with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=10) as smtp:
        if settings.SMTP_STARTTLS:
            smtp.starttls()
        if settings.SMTP_USERNAME:
            smtp.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
        smtp.send_message(message)


@router.post(
    "/password-reset/request",
    response_model=PasswordResetRequestOut,
    response_model_exclude_none=True,
    status_code=status.HTTP_202_ACCEPTED,
)
@limiter.limit("3/minute")
async def password_reset_request(
    request: Request,
    body: PasswordResetRequestIn,
    db: AsyncSession = Depends(get_db),
):
    user = await db.scalar(select(User).where(User.email == body.email))
    if not user:
        return PasswordResetRequestOut()

    now = datetime.now(timezone.utc)
    old_tokens = list(
        await db.scalars(
            select(PasswordResetToken).where(
                PasswordResetToken.user_id == user.id,
                PasswordResetToken.used_at.is_(None),
            )
        )
    )
    for row in old_tokens:
        row.used_at = now

    allowed_local = (
        settings.RESET_DELIVERY.lower() == "local"
        and _client_ip(request) in {"127.0.0.1", "::1"}
        and body.totp_code is not None
    )
    if settings.RESET_DELIVERY.lower() == "local" and (
        not allowed_local or not await _verify_totp_code(user, body.totp_code, db)
    ):
        await db.commit()
        return PasswordResetRequestOut()

    token = secrets.token_urlsafe(32)
    row = PasswordResetToken(
        user_id=user.id,
        token_hash=hash_reset_token(token),
        expires_at=now + timedelta(minutes=30),
        request_ip_hash=hmac.new(
            settings.JWT_SECRET.encode(), _client_ip(request).encode(), hashlib.sha256
        ).hexdigest(),
    )
    db.add(row)
    await db.commit()

    if settings.RESET_DELIVERY.lower() == "smtp":
        try:
            await asyncio.to_thread(_send_reset_email, user.email, token)
        except Exception:
            logger.exception("password reset email delivery failed")
        return PasswordResetRequestOut()

    return PasswordResetRequestOut(token=token)


@router.post("/password-reset/validate")
async def password_reset_validate(
    body: PasswordResetValidateIn,
    db: AsyncSession = Depends(get_db),
):
    row = await db.scalar(
        select(PasswordResetToken).where(PasswordResetToken.token_hash == hash_reset_token(body.token))
    )
    if not _reset_token_valid(row):
        raise HTTPException(400, "invalid or expired reset token")
    return {"ok": True}


@router.post("/password-reset/confirm", status_code=204)
@limiter.limit("5/minute")
async def password_reset_confirm(
    request: Request,
    body: PasswordResetConfirmIn,
    db: AsyncSession = Depends(get_db),
):
    row = await db.scalar(
        select(PasswordResetToken).where(PasswordResetToken.token_hash == hash_reset_token(body.token))
    )
    if not _reset_token_valid(row):
        raise HTTPException(400, "invalid or expired reset token")

    user = await db.get(User, row.user_id)
    if not user:
        row.used_at = datetime.now(timezone.utc)
        await db.commit()
        raise HTTPException(400, "invalid or expired reset token")

    entries = list(await db.scalars(select(VaultEntry).where(VaultEntry.user_id == user.id)))
    for entry in entries:
        await db.delete(entry)

    sessions = list(await db.scalars(select(Session).where(Session.user_id == user.id)))
    for session in sessions:
        await db.delete(session)
    report = await db.scalar(select(HealthReport).where(HealthReport.user_id == user.id))
    if report:
        await db.delete(report)

    user.auth_hash = hash_password(body.new_auth_key)
    user.salt_auth = _b64decode(body.new_salt_auth, "new_salt_auth")
    user.salt_crypto = _b64decode(body.new_salt_crypto, "new_salt_crypto")
    user.mfa_configured = False
    user.totp_secret_enc = None
    user.totp_failed_attempts = 0
    user.totp_locked_until = None
    user.recovery_wrapped_kek = None
    user.recovery_nonce = None
    user.recovery_verifier = None
    user.recovery_public_key = None
    user.recovery_wrapped_signing_key = None
    user.recovery_signing_nonce = None
    user.recovery_challenge_hash = None
    user.recovery_challenge_expires_at = None
    row.used_at = datetime.now(timezone.utc)
    await db.commit()


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
    await record_security_event(db, user.id, "mfa_enabled")
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
@limiter.limit("10/minute")
async def refresh(request: Request, body: RefreshIn, db: AsyncSession = Depends(get_db)):
    try:
        user_id = verify_token(body.refresh_token, "refresh")
    except ValueError:
        raise HTTPException(401, "invalid refresh token") from None

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

    new_refresh = create_refresh_token(user_id)
    access = create_access_token(user_id, matched.id)
    matched.refresh_hash = hash_password(new_refresh)
    matched.expires_at = datetime.now(timezone.utc) + timedelta(days=7)
    await db.commit()
    return TokenOut(access_token=access, refresh_token=new_refresh)


@router.post("/change-password", response_model=TokenOut)
@limiter.limit("5/minute")
async def change_password(
    request: Request,
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
    incoming_ids = {str(item.id) for item in body.entries}
    if incoming_ids != set(entry_by_id.keys()) or len(body.entries) != len(incoming_ids):
        raise HTTPException(400, "entries payload must cover exactly the user's current entries")

    for item in body.entries:
        entry = entry_by_id[str(item.id)]
        entry.wrapped_data_key = item.wrapped_data_key
        entry.wrapped_nonce = item.wrapped_nonce

    user.auth_hash = hash_password(body.new_auth_key)
    user.salt_auth = new_salt_auth
    user.salt_crypto = new_salt_crypto
    await record_security_event(db, user.id, "password_changed")

    old_sessions = list(await db.scalars(select(Session).where(Session.user_id == user.id)))
    for s in old_sessions:
        await db.delete(s)

    refresh = create_refresh_token(user.id)
    session_id = str(uuid.uuid4())
    session = Session(
        id=session_id,
        user_id=user.id,
        refresh_hash=hash_password(refresh),
        expires_at=datetime.now(timezone.utc) + timedelta(days=7),
    )
    db.add(session)
    access = create_access_token(user.id, session_id)
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
            await record_security_event(db, user_id, 'logout')
    await db.commit()
    return {"ok": True}


@router.get("/sessions", response_model=SessionsOut)
async def list_sessions(
    context=Depends(get_current_session_context),
    db: AsyncSession = Depends(get_db),
):
    user, current = context
    now = datetime.now(timezone.utc)
    sessions = list(
        await db.scalars(
            select(Session)
            .where(Session.user_id == user.id)
            .order_by(Session.created_at.desc())
        )
    )
    result: list[SessionOut] = []
    for session in sessions:
        if (_aware(session.expires_at) or now) < now:
            await db.delete(session)
            continue
        result.append(
            SessionOut(
                id=session.id,
                created_at=session.created_at,
                expires_at=session.expires_at,
                current=session.id == current.id,
            )
        )
    await db.commit()
    return SessionsOut(sessions=result)


@router.post("/sessions/revoke-others", status_code=204)
async def revoke_other_sessions(
    context=Depends(get_current_session_context),
    db: AsyncSession = Depends(get_db),
):
    user, current = context
    sessions = list(
        await db.scalars(
            select(Session).where(
                Session.user_id == user.id,
                Session.id != current.id,
            )
        )
    )
    for session in sessions:
        await db.delete(session)
    if sessions:
        await record_security_event(db, user.id, "sessions_revoked")
    await db.commit()


@router.post("/sessions/{session_id}/revoke", status_code=204)
async def revoke_session(
    session_id: str,
    context=Depends(get_current_session_context),
    db: AsyncSession = Depends(get_db),
):
    user, _current = context
    session = await db.scalar(
        select(Session).where(
            Session.id == session_id,
            Session.user_id == user.id,
        )
    )
    if not session:
        raise HTTPException(404, "session not found")
    await db.delete(session)
    await record_security_event(db, user.id, "session_revoked")
    await db.commit()


def _require_webauthn_origin(request: Request) -> None:
    origin = request.headers.get("origin")
    if origin and origin != settings.WEBAUTHN_ORIGIN:
        raise HTTPException(403, "invalid WebAuthn origin")


async def _create_webauthn_challenge(
    db: AsyncSession, user_id: str, purpose: str
) -> bytes:
    challenge = secrets.token_bytes(32)
    row = WebAuthnChallenge(
        user_id=user_id,
        challenge_hash=hashlib.sha256(challenge).hexdigest(),
        purpose=purpose,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
    )
    db.add(row)
    await db.commit()
    return challenge


async def _find_webauthn_challenge(
    db: AsyncSession, user_id: str, purpose: str, challenge: bytes
) -> WebAuthnChallenge:
    row = await db.scalar(
        select(WebAuthnChallenge).where(
            WebAuthnChallenge.user_id == user_id,
            WebAuthnChallenge.purpose == purpose,
            WebAuthnChallenge.challenge_hash == hashlib.sha256(challenge).hexdigest(),
        )
    )
    if not row or row.used_at is not None:
        raise HTTPException(400, "invalid or already used WebAuthn challenge")
    if _aware(row.expires_at) < datetime.now(timezone.utc):
        raise HTTPException(400, "WebAuthn challenge expired")
    return row


async def _consume_webauthn_challenge(db: AsyncSession, row: WebAuthnChallenge) -> None:
    row.used_at = datetime.now(timezone.utc)
    await db.commit()


def _credential_id_from_payload(payload: dict) -> bytes:
    raw_id = payload.get("rawId")
    credential_id = raw_id if isinstance(raw_id, str) and raw_id else payload.get("id")
    if not isinstance(credential_id, str) or not credential_id:
        raise HTTPException(400, "WebAuthn credential id missing")
    try:
        value = b64url_decode(credential_id)
    except (ValueError, binascii.Error):
        raise HTTPException(400, "invalid WebAuthn credential id") from None
    if not value or len(value) > 1024:
        raise HTTPException(400, "invalid WebAuthn credential id")
    return value


@router.post("/webauthn/register/options", response_model=WebAuthnRegisterOptionsOut)
@limiter.limit("5/minute")
async def webauthn_register_options(
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    _require_webauthn_origin(request)
    if not user.mfa_configured or not user.recovery_wrapped_kek:
        raise HTTPException(403, "complete MFA and recovery setup first")

    credentials = list(
        await db.scalars(
            select(WebAuthnCredential).where(WebAuthnCredential.user_id == user.id)
        )
    )
    challenge = await _create_webauthn_challenge(db, user.id, "registration")
    prf_salt = secrets.token_bytes(32)
    try:
        options = registration_options(
            user.email,
            user.id,
            [b64url_decode(item.credential_id) for item in credentials],
            challenge,
        )
    except Exception:
        logger.exception("WebAuthn registration option generation failed")
        raise HTTPException(500, "could not create WebAuthn options") from None

    return WebAuthnRegisterOptionsOut(
        options=options,
        challenge=b64url_encode(challenge),
        prf_salt=base64.b64encode(prf_salt).decode(),
    )


@router.post("/webauthn/register/verify")
@limiter.limit("5/minute")
async def webauthn_register_verify(
    request: Request,
    body: WebAuthnRegisterVerifyIn,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    _require_webauthn_origin(request)
    try:
        challenge = b64url_decode(body.challenge)
    except (ValueError, binascii.Error):
        raise HTTPException(400, "invalid WebAuthn challenge") from None
    if len(challenge) != 32:
        raise HTTPException(400, "invalid WebAuthn challenge")

    row = await _find_webauthn_challenge(db, user.id, "registration", challenge)
    try:
        verified = verify_registration_response(
            credential=body.credential,
            expected_challenge=challenge,
            expected_rp_id=settings.WEBAUTHN_RP_ID,
            expected_origin=settings.WEBAUTHN_ORIGIN,
            require_user_presence=True,
            require_user_verification=True,
        )
    except Exception:
        logger.warning("WebAuthn registration verification failed", exc_info=True)
        raise HTTPException(400, "invalid WebAuthn registration") from None

    credential_id = b64url_encode(verified.credential_id)
    existing = await db.scalar(
        select(WebAuthnCredential).where(
            WebAuthnCredential.credential_id == credential_id
        )
    )
    if existing:
        raise HTTPException(409, "WebAuthn credential already registered")

    db.add(
        WebAuthnCredential(
            user_id=user.id,
            credential_id=credential_id,
            public_key=verified.credential_public_key,
            sign_count=verified.sign_count,
            prf_salt=_b64decode(body.prf_salt, "prf_salt"),
            encrypted_kek=None,
            kek_nonce=None,
            credential_backed_up=verified.credential_backed_up,
        )
    )
    await _consume_webauthn_challenge(db, row)
    return {"credential_id": credential_id, "ready_for_envelope": True}


@router.post("/webauthn/register/envelope", status_code=204)
@limiter.limit("5/minute")
async def webauthn_register_envelope(
    request: Request,
    body: WebAuthnEnvelopeIn,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    _require_webauthn_origin(request)
    credential = await db.scalar(
        select(WebAuthnCredential).where(
            WebAuthnCredential.user_id == user.id,
            WebAuthnCredential.credential_id == body.credential_id,
        )
    )
    if not credential:
        raise HTTPException(404, "WebAuthn credential not found")
    credential.encrypted_kek = body.encrypted_kek
    credential.kek_nonce = body.kek_nonce
    await record_security_event(db, user.id, "passkey_added")
    await db.commit()


@router.get("/webauthn/devices", response_model=WebAuthnDevicesOut)
async def webauthn_devices(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    credentials = list(
        await db.scalars(
            select(WebAuthnCredential)
            .where(
                WebAuthnCredential.user_id == user.id,
                WebAuthnCredential.encrypted_kek.is_not(None),
                WebAuthnCredential.kek_nonce.is_not(None),
            )
            .order_by(WebAuthnCredential.last_used_at.desc().nullslast(), WebAuthnCredential.created_at.desc())
        )
    )
    return WebAuthnDevicesOut(
        devices=[
            WebAuthnDeviceOut(
                credential_id=item.credential_id,
                name=item.name,
                created_at=item.created_at,
                last_used_at=item.last_used_at,
                credential_backed_up=item.credential_backed_up,
            )
            for item in credentials
        ]
    )


@router.patch("/webauthn/devices/{credential_id}", response_model=WebAuthnDeviceOut)
@limiter.limit("10/minute")
async def webauthn_device_rename(
    credential_id: str,
    body: WebAuthnDeviceRenameIn,
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    _require_webauthn_origin(request)
    credential = await db.scalar(
        select(WebAuthnCredential).where(
            WebAuthnCredential.user_id == user.id,
            WebAuthnCredential.credential_id == credential_id,
        )
    )
    if not credential:
        raise HTTPException(404, "trusted device not found")
    credential.name = body.name.strip()
    if not credential.name:
        raise HTTPException(400, "device name cannot be empty")
    await record_security_event(db, user.id, "passkey_renamed")
    await db.commit()
    return WebAuthnDeviceOut(
        credential_id=credential.credential_id,
        name=credential.name,
        created_at=credential.created_at,
        last_used_at=credential.last_used_at,
        credential_backed_up=credential.credential_backed_up,
    )


@router.post("/webauthn/devices/{credential_id}/revoke", status_code=204)
@limiter.limit("5/minute")
async def webauthn_device_revoke(
    credential_id: str,
    body: WebAuthnDeviceRevokeIn,
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    _require_webauthn_origin(request)
    if not user.mfa_configured or not user.totp_secret_enc:
        raise HTTPException(403, "TOTP step-up is required")
    if not await _verify_totp_code(user, body.totp_code, db):
        locked_until = _aware(user.totp_locked_until)
        if locked_until and locked_until > datetime.now(timezone.utc):
            raise HTTPException(429, "TOTP temporarily locked")
        raise HTTPException(401, "invalid TOTP code")

    credential = await db.scalar(
        select(WebAuthnCredential).where(
            WebAuthnCredential.user_id == user.id,
            WebAuthnCredential.credential_id == credential_id,
        )
    )
    if not credential:
        raise HTTPException(404, "trusted device not found")
    await db.delete(credential)
    await record_security_event(db, user.id, "passkey_revoked")
    await db.commit()


@router.post("/webauthn/local/options", response_model=WebAuthnLoginOptionsOut)
@limiter.limit("10/minute")
async def webauthn_local_options(
    request: Request,
    body: WebAuthnLocalOptionsIn,
    db: AsyncSession = Depends(get_db),
):
    _require_webauthn_origin(request)
    user = await db.scalar(
        select(User).where(func.lower(User.email) == body.email.lower())
    )
    if not user or not user.mfa_configured or not user.recovery_wrapped_kek:
        raise HTTPException(404, "no trusted device configured")

    credentials = list(
        await db.scalars(
            select(WebAuthnCredential).where(
                WebAuthnCredential.user_id == user.id,
                WebAuthnCredential.encrypted_kek.is_not(None),
                WebAuthnCredential.kek_nonce.is_not(None),
            )
        )
    )
    if not credentials:
        raise HTTPException(404, "no trusted device configured")

    challenge = await _create_webauthn_challenge(
        db, user.id, "local-authentication"
    )
    try:
        options = authentication_options(
            [b64url_decode(item.credential_id) for item in credentials],
            challenge,
        )
    except Exception:
        logger.exception("WebAuthn local authentication option generation failed")
        raise HTTPException(500, "could not create WebAuthn options") from None

    return WebAuthnLoginOptionsOut(
        options=options,
        challenge=b64url_encode(challenge),
        prf_salts={
            item.credential_id: base64.b64encode(item.prf_salt).decode()
            for item in credentials
        },
    )


@router.post("/webauthn/local/verify", response_model=WebAuthnLoginOut)
@limiter.limit("5/minute")
async def webauthn_local_verify(
    request: Request,
    body: WebAuthnLoginVerifyIn,
    db: AsyncSession = Depends(get_db),
):
    _require_webauthn_origin(request)
    try:
        challenge = b64url_decode(body.challenge)
        credential_id = b64url_encode(_credential_id_from_payload(body.credential))
    except (ValueError, binascii.Error):
        raise HTTPException(400, "invalid WebAuthn response") from None
    if len(challenge) != 32:
        raise HTTPException(400, "invalid WebAuthn challenge")

    row = await db.scalar(
        select(WebAuthnChallenge).where(
            WebAuthnChallenge.challenge_hash == hashlib.sha256(challenge).hexdigest(),
            WebAuthnChallenge.purpose == "local-authentication",
        )
    )
    if not row or row.used_at is not None:
        raise HTTPException(400, "invalid or already used WebAuthn challenge")
    if _aware(row.expires_at) < datetime.now(timezone.utc):
        raise HTTPException(400, "WebAuthn challenge expired")

    credential = await db.scalar(
        select(WebAuthnCredential).where(
            WebAuthnCredential.user_id == row.user_id,
            WebAuthnCredential.credential_id == credential_id,
            WebAuthnCredential.encrypted_kek.is_not(None),
            WebAuthnCredential.kek_nonce.is_not(None),
        )
    )
    if not credential:
        raise HTTPException(401, "trusted device not found")
    user = await db.get(User, row.user_id)
    if not user:
        raise HTTPException(401, "trusted device not found")

    try:
        verified = verify_authentication_response(
            credential=body.credential,
            expected_challenge=challenge,
            expected_rp_id=settings.WEBAUTHN_RP_ID,
            expected_origin=settings.WEBAUTHN_ORIGIN,
            credential_public_key=credential.public_key,
            credential_current_sign_count=credential.sign_count,
            require_user_verification=True,
        )
    except Exception:
        logger.warning("WebAuthn local authentication verification failed", exc_info=True)
        raise HTTPException(401, "invalid WebAuthn assertion") from None

    if (
        credential.sign_count > 0
        and verified.new_sign_count > 0
        and verified.new_sign_count <= credential.sign_count
    ):
        raise HTTPException(401, "WebAuthn signature counter did not advance")

    credential.sign_count = verified.new_sign_count
    credential.last_used_at = datetime.now(timezone.utc)
    row.used_at = datetime.now(timezone.utc)
    tokens = await _issue_session_tokens(db, user.id)
    await db.commit()

    return WebAuthnLoginOut(
        access_token=tokens.access_token,
        refresh_token=tokens.refresh_token,
        credential_id=credential.credential_id,
        encrypted_kek=credential.encrypted_kek,
        kek_nonce=credential.kek_nonce,
    )


async def _google_handoff_user(
    request: Request, db: AsyncSession
) -> User:
    token = request.cookies.get("vaultlocal_google_handoff")
    if not token:
        raise HTTPException(401, "Google login session expired")
    try:
        payload = verify_google_handoff_token(token)
    except ValueError:
        raise HTTPException(401, "Google login session expired") from None
    user = await db.get(User, payload["sub"])
    if not user or user.google_sub != payload["google_sub"] or user.email.lower() != payload["email"].lower():
        raise HTTPException(401, "invalid Google login session")
    return user


@router.get("/webauthn/google/options", response_model=WebAuthnLoginOptionsOut)
@limiter.limit("10/minute")
async def webauthn_google_options(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    _require_webauthn_origin(request)
    user = await _google_handoff_user(request, db)
    if not user.mfa_configured or not user.recovery_wrapped_kek:
        raise HTTPException(403, "trusted-device login is not available yet")

    credentials = list(
        await db.scalars(
            select(WebAuthnCredential).where(
                WebAuthnCredential.user_id == user.id,
                WebAuthnCredential.encrypted_kek.is_not(None),
                WebAuthnCredential.kek_nonce.is_not(None),
            )
        )
    )
    if not credentials:
        raise HTTPException(404, "no trusted device configured")

    challenge = await _create_webauthn_challenge(db, user.id, "authentication")
    try:
        options = authentication_options(
            [b64url_decode(item.credential_id) for item in credentials],
            challenge,
        )
    except Exception:
        logger.exception("WebAuthn authentication option generation failed")
        raise HTTPException(500, "could not create WebAuthn options") from None

    return WebAuthnLoginOptionsOut(
        options=options,
        challenge=b64url_encode(challenge),
        prf_salts={
            item.credential_id: base64.b64encode(item.prf_salt).decode()
            for item in credentials
        },
    )


@router.post("/webauthn/google/verify", response_model=WebAuthnLoginOut)
@limiter.limit("5/minute")
async def webauthn_google_verify(
    request: Request,
    body: WebAuthnLoginVerifyIn,
    db: AsyncSession = Depends(get_db),
):
    _require_webauthn_origin(request)
    user = await _google_handoff_user(request, db)
    if not user.mfa_configured or not user.recovery_wrapped_kek:
        raise HTTPException(403, "trusted-device login is not available yet")

    try:
        challenge = b64url_decode(body.challenge)
        credential_id = b64url_encode(_credential_id_from_payload(body.credential))
    except (ValueError, binascii.Error):
        raise HTTPException(400, "invalid WebAuthn response") from None
    if len(challenge) != 32:
        raise HTTPException(400, "invalid WebAuthn challenge")

    row = await _find_webauthn_challenge(db, user.id, "authentication", challenge)
    credential = await db.scalar(
        select(WebAuthnCredential).where(
            WebAuthnCredential.user_id == user.id,
            WebAuthnCredential.credential_id == credential_id,
        )
    )
    if not credential or not credential.encrypted_kek or not credential.kek_nonce:
        raise HTTPException(401, "trusted device not found")

    try:
        verified = verify_authentication_response(
            credential=body.credential,
            expected_challenge=challenge,
            expected_rp_id=settings.WEBAUTHN_RP_ID,
            expected_origin=settings.WEBAUTHN_ORIGIN,
            credential_public_key=credential.public_key,
            credential_current_sign_count=credential.sign_count,
            require_user_verification=True,
        )
    except Exception:
        logger.warning("WebAuthn authentication verification failed", exc_info=True)
        raise HTTPException(401, "invalid WebAuthn assertion") from None

    if credential.sign_count > 0 and verified.new_sign_count > 0 and verified.new_sign_count <= credential.sign_count:
        raise HTTPException(401, "WebAuthn signature counter did not advance")

    credential.sign_count = verified.new_sign_count
    credential.last_used_at = datetime.now(timezone.utc)
    await _consume_webauthn_challenge(db, row)

    tokens = await _issue_session_tokens(db, user.id)
    response = WebAuthnLoginOut(
        access_token=tokens.access_token,
        refresh_token=tokens.refresh_token,
        credential_id=credential.credential_id,
        encrypted_kek=credential.encrypted_kek,
        kek_nonce=credential.kek_nonce,
    )
    output = Response(
        content=response.model_dump_json(),
        media_type="application/json",
    )
    output.delete_cookie("vaultlocal_google_handoff", path="/api/v1/auth")
    return output
