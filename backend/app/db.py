from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from .config import settings

# allow sqlite for local dev
connect_args = {"check_same_thread": False} if "sqlite" in settings.DATABASE_URL else {}

# normalize URL
url = settings.DATABASE_URL
if url.startswith("sqlite://") and not url.startswith("sqlite+aiosqlite"):
    url = url.replace("sqlite://", "sqlite+aiosqlite://")
if url.startswith("postgres://"):
    url = url.replace("postgres://", "postgresql+asyncpg://")
if url.startswith("postgresql://"):
    url = url.replace("postgresql://", "postgresql+asyncpg://")

engine = create_async_engine(url, echo=False, connect_args=connect_args)
SessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
