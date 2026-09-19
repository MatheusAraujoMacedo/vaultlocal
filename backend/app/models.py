import uuid
from datetime import datetime, timezone
from sqlalchemy import String, ForeignKey, DateTime, LargeBinary, ARRAY, Text
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
import sqlalchemy as sa


class Base(DeclarativeBase):
    pass


# Use Portable UUID for SQLite compatibility in dev
def _uuid_pk():
    return mapped_column(
        sa.String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = _uuid_pk()
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    auth_hash: Mapped[str] = mapped_column(String(512))
    salt_auth: Mapped[bytes] = mapped_column(LargeBinary)
    salt_crypto: Mapped[bytes] = mapped_column(LargeBinary)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    failed_login_attempts: Mapped[int] = mapped_column(
        sa.Integer, default=0, server_default="0"
    )
    locked_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    entries: Mapped[list["VaultEntry"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    sessions: Mapped[list["Session"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )


class VaultEntry(Base):
    __tablename__ = "vault_entries"

    id: Mapped[str] = _uuid_pk()
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="CASCADE"))

    title: Mapped[str] = mapped_column(String(255))
    site: Mapped[str | None] = mapped_column(String(255), nullable=True)

    username_enc: Mapped[str] = mapped_column(Text)
    password_enc: Mapped[str] = mapped_column(Text)
    notes_enc: Mapped[str | None] = mapped_column(Text, nullable=True)

    nonce_username: Mapped[str] = mapped_column(String(64))
    nonce_password: Mapped[str] = mapped_column(String(64))
    nonce_notes: Mapped[str | None] = mapped_column(String(64), nullable=True)

    tags: Mapped[str] = mapped_column(String(512), default="")  # comma separated for sqlite compat

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    user: Mapped[User] = relationship(back_populates="entries")


class Session(Base):
    __tablename__ = "sessions"

    id: Mapped[str] = _uuid_pk()
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="CASCADE"))
    refresh_hash: Mapped[str] = mapped_column(String(512))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    user: Mapped[User] = relationship(back_populates="sessions")
