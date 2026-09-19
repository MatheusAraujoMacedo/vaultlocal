"""In-memory KEK store: user_id -> (kek_bytes, expires_at). Never persisted."""
import time

_kek_store: dict[str, tuple[bytes, float]] = {}
TTL_SECONDS = 60 * 60 * 8  # 8h


def set_kek(user_id: str, kek: bytes):
    _kek_store[user_id] = (kek, time.time() + TTL_SECONDS)


def get_kek(user_id: str) -> bytes | None:
    entry = _kek_store.get(user_id)
    if not entry:
        return None
    kek, exp = entry
    if time.time() > exp:
        _kek_store.pop(user_id, None)
        return None
    return kek


def clear_kek(user_id: str):
    _kek_store.pop(user_id, None)
