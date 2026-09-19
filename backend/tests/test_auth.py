import pytest
from sqlalchemy import select

from app.core.security import lockout_duration_minutes, LOCKOUT_THRESHOLD
from app.db import SessionLocal
from app.models import User

STRONG_PASSWORD = "Xk9#mQ2vLp7$Wz"


async def test_register_success(client):
    resp = await client.post(
        "/api/v1/auth/register",
        json={"email": "alice@test.com", "master_password": STRONG_PASSWORD},
    )
    assert resp.status_code == 201
    assert resp.json()["email"] == "alice@test.com"


async def test_register_duplicate_email_rejected(client):
    await client.post(
        "/api/v1/auth/register",
        json={"email": "alice@test.com", "master_password": STRONG_PASSWORD},
    )
    resp = await client.post(
        "/api/v1/auth/register",
        json={"email": "alice@test.com", "master_password": STRONG_PASSWORD},
    )
    assert resp.status_code == 409


async def test_register_common_password_rejected(client):
    resp = await client.post(
        "/api/v1/auth/register",
        json={"email": "weak@test.com", "master_password": "aaaaaaaaaaaa"},
    )
    assert resp.status_code == 400


async def test_register_too_short_password_rejected(client):
    resp = await client.post(
        "/api/v1/auth/register",
        json={"email": "short@test.com", "master_password": "short1"},
    )
    assert resp.status_code == 422


async def test_login_success_returns_tokens(client, register_and_login):
    tokens = await register_and_login("bob@test.com", STRONG_PASSWORD)
    assert tokens["access_token"]
    assert tokens["refresh_token"]
    assert tokens["token_type"] == "bearer"


async def test_login_wrong_password_rejected(client):
    await client.post(
        "/api/v1/auth/register",
        json={"email": "carol@test.com", "master_password": STRONG_PASSWORD},
    )
    resp = await client.post(
        "/api/v1/auth/login",
        json={"email": "carol@test.com", "master_password": "wrong-password"},
    )
    assert resp.status_code == 401


async def test_login_unknown_email_rejected(client):
    resp = await client.post(
        "/api/v1/auth/login",
        json={"email": "ghost@test.com", "master_password": STRONG_PASSWORD},
    )
    assert resp.status_code == 401


async def test_login_lockout_engages_after_threshold(client):
    await client.post(
        "/api/v1/auth/register",
        json={"email": "dave@test.com", "master_password": STRONG_PASSWORD},
    )
    for _ in range(LOCKOUT_THRESHOLD):
        resp = await client.post(
            "/api/v1/auth/login",
            json={"email": "dave@test.com", "master_password": "wrong-password"},
        )
        assert resp.status_code == 401

    async with SessionLocal() as db:
        user = await db.scalar(select(User).where(User.email == "dave@test.com"))
        assert user.failed_login_attempts == LOCKOUT_THRESHOLD
        assert user.locked_until is not None

    # 6th attempt is denied either by the account lock or the IP rate limit --
    # both are valid outcomes, the account must not be reachable.
    resp = await client.post(
        "/api/v1/auth/login",
        json={"email": "dave@test.com", "master_password": STRONG_PASSWORD},
    )
    assert resp.status_code in (401, 403, 429)


async def test_login_resets_failed_attempts_on_success(client):
    await client.post(
        "/api/v1/auth/register",
        json={"email": "erin@test.com", "master_password": STRONG_PASSWORD},
    )
    for _ in range(LOCKOUT_THRESHOLD - 1):
        await client.post(
            "/api/v1/auth/login",
            json={"email": "erin@test.com", "master_password": "wrong-password"},
        )

    resp = await client.post(
        "/api/v1/auth/login",
        json={"email": "erin@test.com", "master_password": STRONG_PASSWORD},
    )
    assert resp.status_code == 200

    async with SessionLocal() as db:
        user = await db.scalar(select(User).where(User.email == "erin@test.com"))
        assert user.failed_login_attempts == 0
        assert user.locked_until is None


async def test_refresh_rotates_token(client, register_and_login):
    tokens = await register_and_login("frank@test.com", STRONG_PASSWORD)
    old_refresh = tokens["refresh_token"]

    resp = await client.post("/api/v1/auth/refresh", json={"refresh_token": old_refresh})
    assert resp.status_code == 200
    new_refresh = resp.json()["refresh_token"]
    assert new_refresh != old_refresh

    # the rotated-out token must no longer work
    resp = await client.post("/api/v1/auth/refresh", json={"refresh_token": old_refresh})
    assert resp.status_code == 401

    # the new one does
    resp = await client.post("/api/v1/auth/refresh", json={"refresh_token": new_refresh})
    assert resp.status_code == 200


async def test_logout_invalidates_refresh_token(client, register_and_login):
    tokens = await register_and_login("gina@test.com", STRONG_PASSWORD)
    refresh = tokens["refresh_token"]

    resp = await client.post("/api/v1/auth/logout", json={"refresh_token": refresh})
    assert resp.status_code == 200

    resp = await client.post("/api/v1/auth/refresh", json={"refresh_token": refresh})
    assert resp.status_code == 401


NEW_STRONG_PASSWORD = "Qw7!zRt3#Nb9$Ky"


async def test_change_password_requires_authentication(client):
    resp = await client.post(
        "/api/v1/auth/change-password",
        json={"old_master_password": STRONG_PASSWORD, "new_master_password": NEW_STRONG_PASSWORD},
    )
    assert resp.status_code in (401, 403)


async def test_change_password_rejects_wrong_old_password(client, register_and_login):
    tokens = await register_and_login("henry@test.com", STRONG_PASSWORD)
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}

    resp = await client.post(
        "/api/v1/auth/change-password",
        headers=headers,
        json={"old_master_password": "wrong-password", "new_master_password": NEW_STRONG_PASSWORD},
    )
    assert resp.status_code == 401

    # old password still logs in -- nothing changed
    resp = await client.post(
        "/api/v1/auth/login",
        json={"email": "henry@test.com", "master_password": STRONG_PASSWORD},
    )
    assert resp.status_code == 200


async def test_change_password_rejects_common_new_password(client, register_and_login):
    tokens = await register_and_login("iris@test.com", STRONG_PASSWORD)
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}

    resp = await client.post(
        "/api/v1/auth/change-password",
        headers=headers,
        json={"old_master_password": STRONG_PASSWORD, "new_master_password": "aaaaaaaaaaaa"},
    )
    assert resp.status_code == 400


async def test_change_password_rotates_credentials_and_sessions(client, register_and_login):
    tokens = await register_and_login("jack@test.com", STRONG_PASSWORD)
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    old_refresh = tokens["refresh_token"]

    resp = await client.post(
        "/api/v1/auth/change-password",
        headers=headers,
        json={
            "old_master_password": STRONG_PASSWORD,
            "new_master_password": NEW_STRONG_PASSWORD,
        },
    )
    assert resp.status_code == 200
    new_tokens = resp.json()
    assert new_tokens["access_token"]
    assert new_tokens["refresh_token"]

    # old refresh session is gone
    resp = await client.post("/api/v1/auth/refresh", json={"refresh_token": old_refresh})
    assert resp.status_code == 401

    # old password no longer works, new one does
    resp = await client.post(
        "/api/v1/auth/login",
        json={"email": "jack@test.com", "master_password": STRONG_PASSWORD},
    )
    assert resp.status_code == 401

    resp = await client.post(
        "/api/v1/auth/login",
        json={"email": "jack@test.com", "master_password": NEW_STRONG_PASSWORD},
    )
    assert resp.status_code == 200


async def test_change_password_reencrypts_existing_entries(client, register_and_login):
    tokens = await register_and_login("kate@test.com", STRONG_PASSWORD)
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}

    resp = await client.post(
        "/api/v1/entries",
        headers=headers,
        json={"title": "Bank", "username": "kate", "password": "vault-secret", "tags": ""},
    )
    entry_id = resp.json()["id"]

    resp = await client.post(
        "/api/v1/auth/change-password",
        headers=headers,
        json={
            "old_master_password": STRONG_PASSWORD,
            "new_master_password": NEW_STRONG_PASSWORD,
        },
    )
    assert resp.status_code == 200
    new_headers = {"Authorization": f"Bearer {resp.json()['access_token']}"}

    resp = await client.get(f"/api/v1/entries/{entry_id}", headers=new_headers)
    assert resp.status_code == 200
    entry = resp.json()
    assert entry["username"] == "kate"
    assert entry["password"] == "vault-secret"


@pytest.mark.parametrize(
    "attempts,expected_minutes",
    [
        (5, 1),
        (6, 2),
        (7, 4),
        (8, 8),
        (13, 60),
        (100, 60),
    ],
)
def test_lockout_duration_progressive_backoff(attempts, expected_minutes):
    assert lockout_duration_minutes(attempts) == expected_minutes
