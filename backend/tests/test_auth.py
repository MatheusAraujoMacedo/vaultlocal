import base64
import secrets

import pytest
from sqlalchemy import select

from app.core.security import lockout_duration_minutes, LOCKOUT_THRESHOLD
from app.db import SessionLocal
from app.models import User, VaultEntry

AUTH_KEY = "sim-auth-key-AAAAAAAAAAAAAAAAAAAA"
NEW_AUTH_KEY = "sim-auth-key-BBBBBBBBBBBBBBBBBBBB"


def _salt() -> str:
    return base64.b64encode(secrets.token_bytes(16)).decode()


async def _register(client, email: str, auth_key: str = AUTH_KEY) -> dict:
    salt_auth, salt_crypto = _salt(), _salt()
    resp = await client.post(
        "/api/v1/auth/register",
        json={"email": email, "salt_auth": salt_auth, "salt_crypto": salt_crypto, "auth_key": auth_key},
    )
    assert resp.status_code == 201, resp.text
    return {"id": resp.json()["id"], "salt_auth": salt_auth, "salt_crypto": salt_crypto}


async def _login(client, email: str, auth_key: str = AUTH_KEY) -> dict:
    resp = await client.post("/api/v1/auth/login", json={"email": email, "auth_key": auth_key})
    assert resp.status_code == 200, resp.text
    return resp.json()


async def _create_entry_directly(user_id: str, **overrides) -> str:
    defaults = dict(
        title="Bank", site=None,
        username_enc="u", nonce_username="n1",
        password_enc="p", nonce_password="n2",
        notes_enc=None, nonce_notes=None,
        wrapped_data_key="old-wrapped", wrapped_nonce="old-nonce",
        tags="",
    )
    defaults.update(overrides)
    async with SessionLocal() as db:
        entry = VaultEntry(user_id=user_id, **defaults)
        db.add(entry)
        await db.commit()
        await db.refresh(entry)
        return entry.id


async def test_new_user_has_mfa_defaults(client):
    await _register(client, "mfa-defaults@test.com")
    async with SessionLocal() as db:
        user = await db.scalar(select(User).where(User.email == "mfa-defaults@test.com"))
        assert user.auth_method == "local"
        assert user.totp_secret_enc is None
        assert user.mfa_configured is False
        assert user.totp_failed_attempts == 0
        assert user.totp_locked_until is None


async def test_login_init_returns_real_salts_for_known_user(client):
    salts = await _register(client, "alice@test.com")
    resp = await client.post("/api/v1/auth/login/init", json={"email": "alice@test.com"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["salt_auth"] == salts["salt_auth"]
    assert body["salt_crypto"] == salts["salt_crypto"]


async def test_login_init_returns_fake_but_stable_salts_for_unknown_user(client):
    resp1 = await client.post("/api/v1/auth/login/init", json={"email": "ghost@test.com"})
    resp2 = await client.post("/api/v1/auth/login/init", json={"email": "ghost@test.com"})
    assert resp1.status_code == 200 == resp2.status_code
    assert resp1.json() == resp2.json()


async def test_register_success(client):
    await _register(client, "bob@test.com")


async def test_register_duplicate_email_rejected(client):
    await _register(client, "bob@test.com")
    resp = await client.post(
        "/api/v1/auth/register",
        json={"email": "bob@test.com", "salt_auth": _salt(), "salt_crypto": _salt(), "auth_key": AUTH_KEY},
    )
    assert resp.status_code == 409


async def test_register_rejects_malformed_base64_salt(client):
    resp = await client.post(
        "/api/v1/auth/register",
        json={
            "email": "malformed@test.com",
            "salt_auth": "not-valid-base64!!",
            "salt_crypto": _salt(),
            "auth_key": AUTH_KEY,
        },
    )
    assert resp.status_code == 400


async def test_login_success_returns_tokens(client):
    await _register(client, "carol@test.com")
    tokens = await _login(client, "carol@test.com")
    assert tokens["access_token"]
    assert tokens["refresh_token"]


async def test_login_wrong_auth_key_rejected(client):
    await _register(client, "dave@test.com")
    resp = await client.post("/api/v1/auth/login", json={"email": "dave@test.com", "auth_key": "wrong-key"})
    assert resp.status_code == 401


async def test_login_unknown_email_rejected(client):
    resp = await client.post("/api/v1/auth/login", json={"email": "ghost2@test.com", "auth_key": AUTH_KEY})
    assert resp.status_code == 401


async def test_login_lockout_engages_after_threshold(client):
    await _register(client, "erin@test.com")
    for _ in range(LOCKOUT_THRESHOLD):
        resp = await client.post("/api/v1/auth/login", json={"email": "erin@test.com", "auth_key": "wrong-key"})
        assert resp.status_code == 401

    async with SessionLocal() as db:
        user = await db.scalar(select(User).where(User.email == "erin@test.com"))
        assert user.failed_login_attempts == LOCKOUT_THRESHOLD
        assert user.locked_until is not None

    resp = await client.post("/api/v1/auth/login", json={"email": "erin@test.com", "auth_key": AUTH_KEY})
    assert resp.status_code in (401, 429)


async def test_login_resets_failed_attempts_on_success(client):
    await _register(client, "molly@test.com")
    for _ in range(LOCKOUT_THRESHOLD - 1):
        resp = await client.post(
            "/api/v1/auth/login", json={"email": "molly@test.com", "auth_key": "wrong-key"}
        )
        assert resp.status_code == 401

    resp = await client.post(
        "/api/v1/auth/login", json={"email": "molly@test.com", "auth_key": AUTH_KEY}
    )
    assert resp.status_code == 200

    async with SessionLocal() as db:
        user = await db.scalar(select(User).where(User.email == "molly@test.com"))
        assert user.failed_login_attempts == 0
        assert user.locked_until is None


async def test_refresh_rotates_token(client):
    await _register(client, "frank@test.com")
    tokens = await _login(client, "frank@test.com")
    old_refresh = tokens["refresh_token"]

    resp = await client.post("/api/v1/auth/refresh", json={"refresh_token": old_refresh})
    assert resp.status_code == 200
    new_refresh = resp.json()["refresh_token"]
    assert new_refresh != old_refresh

    resp = await client.post("/api/v1/auth/refresh", json={"refresh_token": old_refresh})
    assert resp.status_code == 401

    resp = await client.post("/api/v1/auth/refresh", json={"refresh_token": new_refresh})
    assert resp.status_code == 200


async def test_logout_invalidates_refresh_token(client):
    await _register(client, "gina@test.com")
    tokens = await _login(client, "gina@test.com")
    refresh = tokens["refresh_token"]

    resp = await client.post("/api/v1/auth/logout", json={"refresh_token": refresh})
    assert resp.status_code == 200

    resp = await client.post("/api/v1/auth/refresh", json={"refresh_token": refresh})
    assert resp.status_code == 401


async def test_change_password_requires_authentication(client):
    resp = await client.post(
        "/api/v1/auth/change-password",
        json={
            "old_auth_key": AUTH_KEY, "new_auth_key": NEW_AUTH_KEY,
            "new_salt_auth": _salt(), "new_salt_crypto": _salt(), "entries": [],
        },
    )
    assert resp.status_code in (401, 403)


async def test_change_password_rejects_wrong_old_auth_key(client):
    reg = await _register(client, "henry@test.com")
    tokens = await _login(client, "henry@test.com")
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}

    resp = await client.post(
        "/api/v1/auth/change-password",
        headers=headers,
        json={
            "old_auth_key": "wrong-key", "new_auth_key": NEW_AUTH_KEY,
            "new_salt_auth": _salt(), "new_salt_crypto": _salt(), "entries": [],
        },
    )
    assert resp.status_code == 401
    assert reg["id"]


async def test_change_password_rejects_malformed_base64_salt(client):
    await _register(client, "liam@test.com")
    tokens = await _login(client, "liam@test.com")
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}

    resp = await client.post(
        "/api/v1/auth/change-password",
        headers=headers,
        json={
            "old_auth_key": AUTH_KEY, "new_auth_key": NEW_AUTH_KEY,
            "new_salt_auth": "not-valid-base64!!", "new_salt_crypto": _salt(),
            "entries": [],
        },
    )
    assert resp.status_code == 400


async def test_change_password_rejects_incomplete_entries_payload(client):
    reg = await _register(client, "iris@test.com")
    tokens = await _login(client, "iris@test.com")
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    await _create_entry_directly(reg["id"])

    resp = await client.post(
        "/api/v1/auth/change-password",
        headers=headers,
        json={
            "old_auth_key": AUTH_KEY, "new_auth_key": NEW_AUTH_KEY,
            "new_salt_auth": _salt(), "new_salt_crypto": _salt(),
            "entries": [],  # missing the one entry that exists -- must be rejected
        },
    )
    assert resp.status_code == 400


async def test_change_password_rotates_credentials_and_sessions(client):
    await _register(client, "jack@test.com")
    tokens = await _login(client, "jack@test.com")
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    old_refresh = tokens["refresh_token"]

    resp = await client.post(
        "/api/v1/auth/change-password",
        headers=headers,
        json={
            "old_auth_key": AUTH_KEY, "new_auth_key": NEW_AUTH_KEY,
            "new_salt_auth": _salt(), "new_salt_crypto": _salt(), "entries": [],
        },
    )
    assert resp.status_code == 200
    assert resp.json()["access_token"]

    resp = await client.post("/api/v1/auth/refresh", json={"refresh_token": old_refresh})
    assert resp.status_code == 401

    resp = await client.post("/api/v1/auth/login", json={"email": "jack@test.com", "auth_key": AUTH_KEY})
    assert resp.status_code == 401

    resp = await client.post("/api/v1/auth/login", json={"email": "jack@test.com", "auth_key": NEW_AUTH_KEY})
    assert resp.status_code == 200


async def test_change_password_rewraps_entry_keys_without_touching_ciphertext(client):
    reg = await _register(client, "kate@test.com")
    tokens = await _login(client, "kate@test.com")
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    entry_id = await _create_entry_directly(reg["id"])

    new_wrapped_data_key = base64.b64encode(b"x" * 48).decode()
    new_wrapped_nonce = base64.b64encode(b"y" * 12).decode()
    resp = await client.post(
        "/api/v1/auth/change-password",
        headers=headers,
        json={
            "old_auth_key": AUTH_KEY, "new_auth_key": NEW_AUTH_KEY,
            "new_salt_auth": _salt(), "new_salt_crypto": _salt(),
            "entries": [{"id": entry_id, "wrapped_data_key": new_wrapped_data_key, "wrapped_nonce": new_wrapped_nonce}],
        },
    )
    assert resp.status_code == 200

    async with SessionLocal() as db:
        entry = await db.get(VaultEntry, entry_id)
        assert entry.wrapped_data_key == new_wrapped_data_key
        assert entry.wrapped_nonce == new_wrapped_nonce
        assert entry.username_enc == "u"
        assert entry.password_enc == "p"


@pytest.mark.parametrize(
    "attempts,expected_minutes",
    [(5, 1), (6, 2), (7, 4), (8, 8), (13, 60), (100, 60)],
)
def test_lockout_duration_progressive_backoff(attempts, expected_minutes):
    assert lockout_duration_minutes(attempts) == expected_minutes
