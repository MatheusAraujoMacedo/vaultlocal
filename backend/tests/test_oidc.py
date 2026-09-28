import base64

import pytest
from app import oidc as oidc_module
from app.core.security import (
    create_google_handoff_token,
    create_oidc_state_token,
    verify_oidc_state_token,
)
from app.db import SessionLocal
from app.models import User
from sqlalchemy import select

AUTH_KEY = base64.b64encode(b"A" * 32).decode()


@pytest.mark.asyncio
async def test_oidc_state_token_roundtrip_and_type_binding():
    token = create_oidc_state_token("state-1", "nonce-1", "verifier-1")
    payload = verify_oidc_state_token(token)
    assert payload["state"] == "state-1"
    assert payload["nonce"] == "nonce-1"
    assert payload["code_verifier"] == "verifier-1"

    handoff = create_google_handoff_token("user@test.com", "google-sub", "user-id")
    with pytest.raises(ValueError):
        verify_oidc_state_token(handoff)


@pytest.mark.asyncio
async def test_google_start_requires_configured_provider(client, monkeypatch):
    async def fake_start():
        return (
            "https://accounts.google.com/o/oauth2/v2/auth?state=s",
            "state-s",
            "nonce-s",
            "verifier-s",
        )

    monkeypatch.setattr(oidc_module, "google_authorization_url", fake_start)
    monkeypatch.setattr("app.routers.auth.google_authorization_url", fake_start)
    response = await client.get("/api/v1/auth/oidc/google/start", follow_redirects=False)
    assert response.status_code == 302
    assert "accounts.google.com" in response.headers["location"]
    assert "vaultlocal_oidc_state=" in response.headers["set-cookie"]


@pytest.mark.asyncio
async def test_google_callback_new_identity_creates_handoff_cookie(client, monkeypatch):
    async def fake_claims(*args):
        return {"sub": "google-new", "email": "new-google@test.com"}

    monkeypatch.setattr("app.routers.auth.google_id_token_claims", fake_claims)
    state_token = create_oidc_state_token("state-new", "nonce-new", "verifier-new")

    response = await client.get(
        "/api/v1/auth/oidc/google/callback",
        params={"code": "code", "state": "state-new"},
        headers={"Cookie": f"vaultlocal_oidc_state={state_token}"},
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert response.headers["location"].endswith("/login?google=1")
    assert "vaultlocal_google_handoff=" in response.headers["set-cookie"]


@pytest.mark.asyncio
async def test_google_exchange_new_identity_returns_setup_required(client):
    token = create_google_handoff_token("new-google@test.com", "google-new", None)
    client.cookies.set("vaultlocal_google_handoff", token)

    response = await client.get("/api/v1/auth/oidc/google/exchange")
    assert response.status_code == 200
    assert response.json() == {
        "status": "setup_required",
        "email": "new-google@test.com",
        "salt_auth": None,
        "salt_crypto": None,
    }


@pytest.mark.asyncio
async def test_google_password_authenticates_linked_identity(client):
    response = await client.post(
        "/api/v1/auth/register",
        json={
            "email": "google-password@test.com",
            "salt_auth": base64.b64encode(b"f" * 16).decode(),
            "salt_crypto": base64.b64encode(b"g" * 16).decode(),
            "auth_key": AUTH_KEY,
        },
    )
    assert response.status_code == 201

    async with SessionLocal() as db:
        user = await db.scalar(select(User).where(User.email == "google-password@test.com"))
        assert user is not None
        user.google_sub = "google-password-sub"
        user.auth_method = "google"
        await db.commit()
        handoff = create_google_handoff_token(user.email, user.google_sub, user.id)

    client.cookies.set("vaultlocal_google_handoff", handoff)
    response = await client.post(
        "/api/v1/auth/oidc/google/password",
        json={"auth_key": AUTH_KEY},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "mfa_setup_required"
    assert response.json()["mfa_token"]


@pytest.mark.asyncio
async def test_google_complete_creates_google_account(client):
    token = create_google_handoff_token("create-google@test.com", "google-create", None)
    client.cookies.set("vaultlocal_google_handoff", token)

    response = await client.post(
        "/api/v1/auth/oidc/google/complete",
        json={
            "new_salt_auth": base64.b64encode(b"b" * 16).decode(),
            "new_salt_crypto": base64.b64encode(b"c" * 16).decode(),
            "auth_key": AUTH_KEY,
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "mfa_setup_required"
    assert body["mfa_token"]

    async with SessionLocal() as db:
        user = await db.scalar(select(User).where(User.email == "create-google@test.com"))
        assert user is not None
        assert user.auth_method == "google"
        assert user.google_sub == "google-create"
        assert user.mfa_configured is False


@pytest.mark.asyncio
async def test_google_callback_links_existing_email(client, monkeypatch):
    salt_auth = base64.b64encode(b"d" * 16).decode()
    salt_crypto = base64.b64encode(b"e" * 16).decode()

    async def fake_claims(*args):
        return {"sub": "google-existing", "email": "existing-google@test.com"}

    monkeypatch.setattr("app.routers.auth.google_id_token_claims", fake_claims)

    response = await client.post(
        "/api/v1/auth/register",
        json={
            "email": "existing-google@test.com",
            "salt_auth": salt_auth,
            "salt_crypto": salt_crypto,
            "auth_key": AUTH_KEY,
        },
    )
    assert response.status_code == 201

    state_token = create_oidc_state_token("state-existing", "nonce-existing", "verifier-existing")
    response = await client.get(
        "/api/v1/auth/oidc/google/callback",
        params={"code": "code", "state": "state-existing"},
        headers={"Cookie": f"vaultlocal_oidc_state={state_token}"},
        follow_redirects=False,
    )
    assert response.status_code == 302

    async with SessionLocal() as db:
        user = await db.scalar(select(User).where(User.email == "existing-google@test.com"))
        assert user is not None
        assert user.google_sub == "google-existing"
        assert user.auth_method == "google"


@pytest.mark.asyncio
async def test_google_exchange_existing_returns_real_salts(client):
    response = await client.post(
        "/api/v1/auth/register",
        json={
            "email": "existing-google@test.com",
            "salt_auth": base64.b64encode(b"d" * 16).decode(),
            "salt_crypto": base64.b64encode(b"e" * 16).decode(),
            "auth_key": AUTH_KEY,
        },
    )
    assert response.status_code == 201
    async with SessionLocal() as db:
        user = await db.scalar(select(User).where(User.email == "existing-google@test.com"))
        assert user is not None
        user.google_sub = "google-existing"
        user.auth_method = "google"
        await db.commit()
        token = create_google_handoff_token(user.email, user.google_sub, user.id)

    client.cookies.set("vaultlocal_google_handoff", token)
    response = await client.get("/api/v1/auth/oidc/google/exchange")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "existing"
    assert body["email"] == "existing-google@test.com"
    assert body["salt_auth"]
    assert body["salt_crypto"]


@pytest.mark.asyncio
async def test_google_callback_rejects_state_mismatch(client, monkeypatch):
    async def fake_claims(*args):
        raise AssertionError("OIDC provider must not be called")

    monkeypatch.setattr("app.routers.auth.google_id_token_claims", fake_claims)
    state_token = create_oidc_state_token("expected-state", "nonce", "verifier")
    response = await client.get(
        "/api/v1/auth/oidc/google/callback",
        params={"code": "code", "state": "wrong-state"},
        headers={"Cookie": f"vaultlocal_oidc_state={state_token}"},
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert response.headers["location"].endswith("/login?oauth_error=google_failed")
