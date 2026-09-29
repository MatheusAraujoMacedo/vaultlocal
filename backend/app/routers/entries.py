from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.audit import record_security_event
from ..deps import get_current_user, get_db
from ..models import User, VaultEntry
from ..schemas import EntryIn, EntryListItem, EntryOut

router = APIRouter(prefix="/entries", tags=["entries"])


def _to_out(e: VaultEntry) -> EntryOut:
    return EntryOut(
        id=e.id,
        crypto_version=e.crypto_version,
        title=e.title,
        site=e.site,
        expires_at=e.expires_at,
        username_enc=e.username_enc,
        nonce_username=e.nonce_username,
        password_enc=e.password_enc,
        nonce_password=e.nonce_password,
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
        select(VaultEntry).where(VaultEntry.user_id == user.id).order_by(VaultEntry.updated_at.desc())
    )
    return [
        EntryListItem(
            id=e.id,
            title=e.title,
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
            or_(VaultEntry.title.ilike(like), VaultEntry.site.ilike(like)),
        )
    )
    return [
        EntryListItem(
            id=e.id,
            title=e.title,
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
        site=body.site,
        expires_at=body.expires_at,
        username_enc=body.username_enc,
        nonce_username=body.nonce_username,
        password_enc=body.password_enc,
        nonce_password=body.nonce_password,
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


@router.get("/{entry_id}", response_model=EntryOut)
async def get_entry(
    entry_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    e = await db.get(VaultEntry, entry_id)
    if not e or e.user_id != user.id:
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
    if not e or e.user_id != user.id:
        raise HTTPException(404, "not found")
    if str(body.id) != entry_id:
        raise HTTPException(400, "entry id does not match path")
    e.crypto_version = 2
    e.title = body.title
    e.site = body.site
    e.expires_at = body.expires_at
    e.username_enc = body.username_enc
    e.nonce_username = body.nonce_username
    e.password_enc = body.password_enc
    e.nonce_password = body.nonce_password
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


@router.delete("/{entry_id}", status_code=204)
async def delete_entry(
    entry_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    e = await db.get(VaultEntry, entry_id)
    if not e or e.user_id != user.id:
        raise HTTPException(404, "not found")
    await db.delete(e)
    await record_security_event(db, user.id, "entry_deleted")
    await db.commit()
