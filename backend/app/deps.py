from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from .core.security import verify_access_token, verify_token
from .db import SessionLocal
from .models import Session, User

security = HTTPBearer()


def _is_session_expired(session: Session) -> bool:
    from datetime import datetime, timezone
    expires_at = session.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return expires_at < datetime.now(timezone.utc)


async def get_db():
    async with SessionLocal() as session:
        yield session


async def get_current_session_context(
    creds: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db),
) -> tuple[User, Session]:
    token = creds.credentials
    try:
        user_id, session_id = verify_access_token(token)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid token") from None
    user = await db.get(User, user_id)
    session = await db.get(Session, session_id)
    if not user or not session or session.user_id != user.id:
        raise HTTPException(status_code=401, detail="invalid session")
    if _is_session_expired(session):
        raise HTTPException(status_code=401, detail="session expired")
    return user, session


async def get_current_user(
    creds: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db),
) -> User:
    user, _session = await get_current_session_context(creds, db)
    return user


async def get_recovery_pending_user(
    creds: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db),
) -> User:
    token = creds.credentials
    try:
        user_id = verify_token(token, "recovery_pending")
    except ValueError:
        raise HTTPException(status_code=401, detail="invalid or expired recovery token") from None
    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=401, detail="user not found")
    return user


async def get_mfa_pending_user(
    creds: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db),
) -> User:
    token = creds.credentials
    try:
        user_id = verify_token(token, "mfa_pending")
    except ValueError:
        raise HTTPException(status_code=401, detail="invalid or expired mfa token") from None
    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=401, detail="user not found")
    return user
