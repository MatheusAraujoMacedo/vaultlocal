from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from .db import SessionLocal
from .models import User
from .core.security import verify_token
from .core.kekstore import get_kek

security = HTTPBearer()


async def get_db():
    async with SessionLocal() as session:
        yield session


async def get_current_user(
    creds: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db),
) -> User:
    token = creds.credentials
    try:
        user_id = verify_token(token, "access")
    except ValueError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid token")
    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=401, detail="user not found")
    return user


async def get_current_user_with_kek(
    user: User = Depends(get_current_user),
) -> tuple[User, bytes]:
    kek = get_kek(user.id)
    if not kek:
        raise HTTPException(status_code=401, detail="session expired, login again")
    return user, kek
