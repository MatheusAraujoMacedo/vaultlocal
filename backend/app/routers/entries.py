from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.audit import record_security_event
from ..deps import get_current_user, get_db
from ..models import User, VaultEntry
from ..schemas import EntryFavoriteIn, EntryIn, EntryListItem, EntryOut, TrashEntryOut

router = APIRouter(prefix="/entries", tags=["entries"])
TRASH_RETENTION_DAYS = 30

def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _to_out(e: VaultEntry) -> EntryOut:
    return EntryOut(
        id=e.id,
        crypto_version=e.crypto_version,
        title=e.title,
        favorite=e.favorite,
        site=e.site,
        expires_at=e.expires_at,
        username_enc=e.username_enc,
        nonce_username=e.nonce_username,
        password_enc=e.password_enc,
        nonce_password=e.nonce_password,
        password_history_enc=e.password_history_enc,
        nonce_password_history=e.nonce_password_history,
        custom_fields_enc=e.custom_fields_enc,
        nonce_custom_fields=e.nonce_custom_fields,
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
        select(VaultEntry).where(VaultEntry.user_id == user.id, VaultEntry.deleted_at.is_(None)).order_by(VaultEntry.updated_at.desc())
    )
    return [
        EntryListItem(
            id=e.id,
            title=e.title,
            favorite=e.favorite,
            site=e.site,
            tags=e.tags or "",
            expires_at=e.expires_at.isoformat() if e.expires_at else None,
            created_at=e.created_at.isoformat(),
            updated_at=e.updated_at.isoformat(),
        )
        for e in rows
    ]


@router.get("/search", response_model=list[EntryListItem])
async def search_entries(
    q: str = Query(min_length=1, max_length=128),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    like = f"%{q}%"
    rows = await db.scalars(
        select(VaultEntry).where(
            VaultEntry.user_id == user.id,
            VaultEntry.deleted_at.is_(None),
            or_(VaultEntry.title.ilike(like), VaultEntry.site.ilike(like)),
        )
    )
    return [
        EntryListItem(
            id=e.id,
            title=e.title,
            favorite=e.favorite,
            site=e.site,
            tags=e.tags or "",
            expires_at=e.expires_at.isoformat() if e.expires_at else None,
            created_at=e.created_at.isoformat(),
            updated_at=e.updated_at.isoformat(),
        )
        for e in rows
    ]


@router.post("", response_model=EntryOut, status_code=201)
async def create_entry(
    body: EntryIn,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    entry_id = str(body.id)
    if await db.get(VaultEntry, entry_id):
        raise HTTPException(409, "entry id already exists")
    entry = VaultEntry(
        id=entry_id,
        user_id=user.id,
        crypto_version=2,
        title=body.title,
        favorite=body.favorite,
        site=body.site,
        expires_at=body.expires_at,
        username_enc=body.username_enc,
        nonce_username=body.nonce_username,
        password_enc=body.password_enc,
        nonce_password=body.nonce_password,
        password_history_enc=body.password_history_enc,
        nonce_password_history=body.nonce_password_history,
        custom_fields_enc=body.custom_fields_enc,
        nonce_custom_fields=body.nonce_custom_fields,
        notes_enc=body.notes_enc,
        nonce_notes=body.nonce_notes,
        wrapped_data_key=body.wrapped_data_key,
        wrapped_nonce=body.wrapped_nonce,
        tags=body.tags,
    )
    db.add(entry)
    await record_security_event(db, user.id, "entry_created")
    await db.commit()
    await db.refresh(entry)
    return _to_out(entry)


@router.get("/trash", response_model=list[TrashEntryOut])
async def list_trash(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=TRASH_RETENTION_DAYS)
    expired = await db.scalars(
        select(VaultEntry).where(
            VaultEntry.user_id == user.id,
            VaultEntry.deleted_at.is_not(None),
            VaultEntry.deleted_at < cutoff,
        )
    )
    for entry in expired:
        await db.delete(entry)
    await db.commit()

    rows = await db.scalars(
        select(VaultEntry).where(
            VaultEntry.user_id == user.id,
            VaultEntry.deleted_at.is_not(None),
        ).order_by(VaultEntry.deleted_at.desc())
    )
    return [
        {
            "id": e.id,
            "title": e.title,
            "favorite": e.favorite,
            "site": e.site,
            "tags": e.tags or "",
            "expires_at": e.expires_at.isoformat() if e.expires_at else None,
            "created_at": e.created_at.isoformat(),
            "updated_at": e.updated_at.isoformat(),
            "deleted_at": e.deleted_at.isoformat(),
            "purge_at": (e.deleted_at + timedelta(days=TRASH_RETENTION_DAYS)).isoformat(),
        }
        for e in rows
    ]


@router.post("/{entry_id}/restore", response_model=EntryOut)
async def restore_entry(
    entry_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    e = await db.get(VaultEntry, entry_id)
    if not e or e.user_id != user.id or e.deleted_at is None:
        raise HTTPException(404, "not found")
    if _as_utc(e.deleted_at) < datetime.now(timezone.utc) - timedelta(days=TRASH_RETENTION_DAYS):
        await db.delete(e)
        await db.commit()
        raise HTTPException(410, "entry retention period expired")
    e.deleted_at = None
    e.updated_at = datetime.now(timezone.utc)
    await record_security_event(db, user.id, "entry_restored")
    await db.commit()
    await db.refresh(e)
    return _to_out(e)


@router.delete("/{entry_id}/permanent", status_code=204)
async def permanently_delete_entry(
    entry_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    e = await db.get(VaultEntry, entry_id)
    if not e or e.user_id != user.id or e.deleted_at is None:
        raise HTTPException(404, "not found")
    await db.delete(e)
    await record_security_event(db, user.id, "entry_permanently_deleted")
    await db.commit()


@router.get("/{entry_id}", response_model=EntryOut)
async def get_entry(
    entry_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    e = await db.get(VaultEntry, entry_id)
    if not e or e.user_id != user.id or e.deleted_at is not None:
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
    if not e or e.user_id != user.id or e.deleted_at is not None:
        raise HTTPException(404, "not found")
    if str(body.id) != entry_id:
        raise HTTPException(400, "entry id does not match path")
    e.crypto_version = 2
    e.title = body.title
    e.favorite = body.favorite
    e.site = body.site
    e.expires_at = body.expires_at
    e.username_enc = body.username_enc
    e.nonce_username = body.nonce_username
    e.password_enc = body.password_enc
    e.nonce_password = body.nonce_password
    e.password_history_enc = body.password_history_enc
    e.nonce_password_history = body.nonce_password_history
    e.custom_fields_enc = body.custom_fields_enc
    e.nonce_custom_fields = body.nonce_custom_fields
    e.notes_enc = body.notes_enc
    e.nonce_notes = body.nonce_notes
    e.wrapped_data_key = body.wrapped_data_key
    e.wrapped_nonce = body.wrapped_nonce
    e.tags = body.tags
    e.updated_at = datetime.now(timezone.utc)
    await record_security_event(db, user.id, "entry_updated")
    await db.commit()
    await db.refresh(e)
    return _to_out(e)


@router.patch("/{entry_id}/favorite", response_model=EntryOut)
async def set_favorite(
    entry_id: str,
    body: EntryFavoriteIn,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    e = await db.get(VaultEntry, entry_id)
    if not e or e.user_id != user.id or e.deleted_at is not None:
        raise HTTPException(404, "not found")
    e.favorite = body.favorite
    e.updated_at = datetime.now(timezone.utc)
    await record_security_event(db, user.id, "entry_favorited" if body.favorite else "entry_unfavorited")
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
    if not e or e.user_id != user.id or e.deleted_at is not None:
        raise HTTPException(404, "not found")
    e.deleted_at = datetime.now(timezone.utc)
    e.updated_at = datetime.now(timezone.utc)
    await record_security_event(db, user.id, "entry_deleted")
    await db.commit()
