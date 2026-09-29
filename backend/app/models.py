import uuid
from datetime import datetime, timezone

import sqlalchemy as sa
from sqlalchemy import DateTime, ForeignKey, LargeBinary, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


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
    auth_method: Mapped[str] = mapped_column(
        Text, default="local", server_default="local"
    )
    google_sub: Mapped[str | None] = mapped_column(String(255), unique=True, nullable=True, index=True)
    totp_secret_enc: Mapped[bytes | None] = mapped_column(
        sa.LargeBinary, nullable=True
    )
    mfa_configured: Mapped[bool] = mapped_column(
        sa.Boolean, default=False, server_default=sa.false()
    )
    totp_failed_attempts: Mapped[int] = mapped_column(
        sa.Integer, default=0, server_default="0"
    )
    totp_locked_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    recovery_wrapped_kek: Mapped[str | None] = mapped_column(Text, nullable=True)
    recovery_nonce: Mapped[str | None] = mapped_column(String(64), nullable=True)
    recovery_verifier: Mapped[str | None] = mapped_column(Text, nullable=True)
    recovery_public_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    recovery_wrapped_signing_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    recovery_signing_nonce: Mapped[str | None] = mapped_column(String(64), nullable=True)
    recovery_challenge_hash: Mapped[str | None] = mapped_column(Text, nullable=True)
    recovery_challenge_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    entries: Mapped[list["VaultEntry"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    health_report: Mapped["HealthReport | None"] = relationship(
        back_populates="user", cascade="all, delete-orphan", uselist=False
    )
    security_events: Mapped[list["SecurityEvent"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )

    sessions: Mapped[list["Session"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )

    webauthn_credentials: Mapped[list["WebAuthnCredential"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )

    webauthn_challenges: Mapped[list["WebAuthnChallenge"]] = relationship(
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
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    favorite: Mapped[bool] = mapped_column(
        sa.Boolean, nullable=False, default=False, server_default=sa.false(), index=True
    )

    wrapped_data_key: Mapped[str] = mapped_column(Text)
    wrapped_nonce: Mapped[str] = mapped_column(String(64))
    crypto_version: Mapped[int] = mapped_column(
        sa.SmallInteger, nullable=False, default=2, server_default="1"
    )

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


class WebAuthnCredential(Base):
    __tablename__ = "webauthn_credentials"

    id: Mapped[str] = _uuid_pk()
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    credential_id: Mapped[str] = mapped_column(Text, unique=True, index=True)
    public_key: Mapped[bytes] = mapped_column(LargeBinary)
    sign_count: Mapped[int] = mapped_column(sa.BigInteger, default=0, server_default="0")
    prf_salt: Mapped[bytes] = mapped_column(LargeBinary)
    encrypted_kek: Mapped[str | None] = mapped_column(Text, nullable=True)
    kek_nonce: Mapped[str | None] = mapped_column(String(64), nullable=True)
    name: Mapped[str] = mapped_column(String(100), default="Dispositivo", server_default="Dispositivo")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    credential_backed_up: Mapped[bool] = mapped_column(sa.Boolean, default=False, server_default=sa.false())

    user: Mapped[User] = relationship(back_populates="webauthn_credentials")


class WebAuthnChallenge(Base):
    __tablename__ = "webauthn_challenges"

    id: Mapped[str] = _uuid_pk()
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    challenge_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    purpose: Mapped[str] = mapped_column(String(30))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    user: Mapped[User] = relationship(back_populates="webauthn_challenges")


class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"

    id: Mapped[str] = _uuid_pk()
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    token_hash: Mapped[str] = mapped_column(Text, unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    request_ip_hash: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    user: Mapped[User] = relationship()


class HealthReport(Base):
    __tablename__ = "health_reports"

    id: Mapped[str] = _uuid_pk()
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), unique=True, nullable=False
    )
    total_entries: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    weak_count: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    reused_count: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    old_count: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    breached_count: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    user: Mapped[User] = relationship(back_populates="health_report")

class SecurityEvent(Base):
    __tablename__ = "security_events"

    id: Mapped[str] = _uuid_pk()
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    event_type: Mapped[str] = mapped_column(String(40), index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )

    user: Mapped[User] = relationship(back_populates="security_events")
