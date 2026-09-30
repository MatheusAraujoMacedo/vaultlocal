from sqlalchemy.ext.asyncio import AsyncSession

from ..models import SecurityEvent

SECURITY_EVENT_TYPES = {
    "entry_created",
    "entry_updated",
    "entry_deleted",
    "entry_restored",
    "entry_permanently_deleted",
    "entry_favorited",
    "entry_unfavorited",
    "health_scan",
    "passkey_added",
    "passkey_renamed",
    "passkey_revoked",
    "password_changed",
    "mfa_enabled",
    "recovery_used",
    "login_success",
    "logout",
    "session_revoked",
    "sessions_revoked",
}

async def record_security_event(
    db: AsyncSession,
    user_id: str,
    event_type: str,
) -> None:
    if event_type not in SECURITY_EVENT_TYPES:
        raise ValueError("invalid security event type")
    db.add(SecurityEvent(user_id=user_id, event_type=event_type))
