import secrets
import string
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, or_
from sqlalchemy.ext.asyncio import AsyncSession
from ..deps import get_db, get_current_user_with_kek
from ..models import VaultEntry, User
from ..schemas import EntryIn, EntryOut, EntryListItem, GenerateIn, GenerateOut
from ..core.security import encrypt, decrypt

router = APIRouter(prefix="/entries", tags=["entries"])


def _to_out(e: VaultEntry, kek: bytes) -> EntryOut:
    username = decrypt(e.username_enc, e.nonce_username, kek).decode()
    password = decrypt(e.password_enc, e.nonce_password, kek).decode()
    notes = decrypt(e.notes_enc, e.nonce_notes, kek).decode() if e.notes_enc else None
    return EntryOut(
        id=e.id,
        title=e.title,
        site=e.site,
        username=username,
        password=password,
        notes=notes,
        tags=e.tags or "",
        created_at=e.created_at.isoformat(),
        updated_at=e.updated_at.isoformat(),
    )


@router.get("", response_model=list[EntryListItem])
async def list_entries(
    dep: tuple[User, bytes] = Depends(get_current_user_with_kek),
    db: AsyncSession = Depends(get_db),
):
    user, _ = dep
    rows = await db.scalars(
        select(VaultEntry).where(VaultEntry.user_id == user.id).order_by(VaultEntry.updated_at.desc())
    )
    return [
        EntryListItem(
            id=e.id,
            title=e.title,
            site=e.site,
            tags=e.tags or "",
            created_at=e.created_at.isoformat(),
            updated_at=e.updated_at.isoformat(),
        )
        for e in rows
    ]


@router.get("/search", response_model=list[EntryListItem])
async def search_entries(
    q: str,
    dep: tuple[User, bytes] = Depends(get_current_user_with_kek),
    db: AsyncSession = Depends(get_db),
):
    user, _ = dep
    like = f"%{q}%"
    rows = await db.scalars(
        select(VaultEntry).where(
            VaultEntry.user_id == user.id,
            or_(VaultEntry.title.ilike(like), VaultEntry.site.ilike(like)),
        )
    )
    return [
        EntryListItem(
            id=e.id, title=e.title, site=e.site, tags=e.tags or "",
            created_at=e.created_at.isoformat(), updated_at=e.updated_at.isoformat(),
        )
        for e in rows
    ]


@router.post("", response_model=EntryOut, status_code=201)
async def create_entry(
    body: EntryIn,
    dep: tuple[User, bytes] = Depends(get_current_user_with_kek),
    db: AsyncSession = Depends(get_db),
):
    user, kek = dep
    u = encrypt(body.username.encode(), kek)
    p = encrypt(body.password.encode(), kek)
    n = encrypt(body.notes.encode(), kek) if body.notes else None
    entry = VaultEntry(
        user_id=user.id,
        title=body.title,
        site=body.site,
        username_enc=u["ciphertext"],
        nonce_username=u["nonce"],
        password_enc=p["ciphertext"],
        nonce_password=p["nonce"],
        notes_enc=n["ciphertext"] if n else None,
        nonce_notes=n["nonce"] if n else None,
        tags=body.tags,
    )
    db.add(entry)
    await db.commit()
    await db.refresh(entry)
    return _to_out(entry, kek)


@router.get("/{entry_id}", response_model=EntryOut)
async def get_entry(
    entry_id: str,
    dep: tuple[User, bytes] = Depends(get_current_user_with_kek),
    db: AsyncSession = Depends(get_db),
):
    user, kek = dep
    e = await db.get(VaultEntry, entry_id)
    if not e or e.user_id != user.id:
        raise HTTPException(404, "not found")
    return _to_out(e, kek)


@router.put("/{entry_id}", response_model=EntryOut)
async def update_entry(
    entry_id: str,
    body: EntryIn,
    dep: tuple[User, bytes] = Depends(get_current_user_with_kek),
    db: AsyncSession = Depends(get_db),
):
    user, kek = dep
    e = await db.get(VaultEntry, entry_id)
    if not e or e.user_id != user.id:
        raise HTTPException(404, "not found")
    u = encrypt(body.username.encode(), kek)
    p = encrypt(body.password.encode(), kek)
    n = encrypt(body.notes.encode(), kek) if body.notes else None
    e.title = body.title
    e.site = body.site
    e.username_enc = u["ciphertext"]
    e.nonce_username = u["nonce"]
    e.password_enc = p["ciphertext"]
    e.nonce_password = p["nonce"]
    e.notes_enc = n["ciphertext"] if n else None
    e.nonce_notes = n["nonce"] if n else None
    e.tags = body.tags
    await db.commit()
    await db.refresh(e)
    return _to_out(e, kek)


@router.delete("/{entry_id}", status_code=204)
async def delete_entry(
    entry_id: str,
    dep: tuple[User, bytes] = Depends(get_current_user_with_kek),
    db: AsyncSession = Depends(get_db),
):
    user, _ = dep
    e = await db.get(VaultEntry, entry_id)
    if not e or e.user_id != user.id:
        raise HTTPException(404, "not found")
    await db.delete(e)
    await db.commit()


@router.post("/generate/password", response_model=GenerateOut)
async def generate_password(
    body: GenerateIn,
    dep: tuple[User, bytes] = Depends(get_current_user_with_kek),
):
    chars = string.ascii_letters + string.digits
    if body.use_symbols:
        chars += "!@#$%^&*()-_=+[]{};:,.<>?"
    pwd = "".join(secrets.choice(chars) for _ in range(body.length))
    return GenerateOut(password=pwd)
