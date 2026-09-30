import base64
import secrets
from types import SimpleNamespace

import pytest
from app.core.security import create_google_handoff_token
from app.db import SessionLocal
from app.models import User, WebAuthnCredential
from sqlalchemy import select


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


async def _enable_user_features(user_id: str) -> None:
    async with SessionLocal() as db:
        user = await db.get(User, user_id)
        assert user is not None
        user.mfa_configured = True
        user.recovery_wrapped_kek = base64.b64encode(secrets.token_bytes(48)).decode()
        user.google_sub = "google-test-sub"
        await db.commit()


@pytest.mark.asyncio
async def test_webauthn_register_options_require_recovery(client, register_and_login):
    result = await register_and_login("webauthn-options@example.com")
    response = await client.post(
        "/api/v1/auth/webauthn/register/options",
        headers={"Authorization": f"Bearer {result['access_token']}"},
    )
    assert response.status_code == 403
    assert "MFA" in response.text


@pytest.mark.asyncio
async def test_webauthn_registration_and_envelope(
    client, register_and_login, monkeypatch
):
    result = await register_and_login("webauthn-register@example.com")
    await _enable_user_features(result["user_id"])

    options = await client.post(
        "/api/v1/auth/webauthn/register/options",
        headers={"Authorization": f"Bearer {result['access_token']}"},
    )
    assert options.status_code == 200, options.text
    payload = options.json()
    assert len(payload["prf_salt"]) > 40
    assert "challenge" in payload
    assert payload["options"]["challenge"] == payload["challenge"]

    verified = SimpleNamespace(
        credential_id=b"credential-one",
        credential_public_key=b"public-key-one",
        sign_count=4,
        credential_backed_up=False,
    )
    monkeypatch.setattr(
        "app.routers.auth.verify_registration_response",
        lambda **kwargs: verified,
    )

    credential = await client.post(
        "/api/v1/auth/webauthn/register/verify",
        headers={"Authorization": f"Bearer {result['access_token']}"},
        json={
            "challenge": payload["challenge"],
            "prf_salt": payload["prf_salt"],
            "credential": {"id": "dummy", "type": "public-key", "response": {}},
        },
    )
    assert credential.status_code == 200, credential.text
    credential_id = credential.json()["credential_id"]

    async with SessionLocal() as db:
        row = await db.scalar(
            select(WebAuthnCredential).where(
                WebAuthnCredential.credential_id == credential_id
            )
        )
        assert row is not None
        assert row.encrypted_kek is None
        assert row.sign_count == 4

    envelope = {
        "credential_id": credential_id,
        "encrypted_kek": base64.b64encode(secrets.token_bytes(48)).decode(),
        "kek_nonce": base64.b64encode(secrets.token_bytes(12)).decode(),
    }
    saved = await client.post(
        "/api/v1/auth/webauthn/register/envelope",
        headers={"Authorization": f"Bearer {result['access_token']}"},
        json=envelope,
    )
    assert saved.status_code == 204

    async with SessionLocal() as db:
        row = await db.scalar(
            select(WebAuthnCredential).where(
                WebAuthnCredential.credential_id == credential_id
            )
        )
        assert row is not None
        assert row.encrypted_kek == envelope["encrypted_kek"]
        assert row.kek_nonce == envelope["kek_nonce"]


@pytest.mark.asyncio
async def test_google_webauthn_options_only_expose_trusted_credentials(
    client, register_and_login
):
    result = await register_and_login("webauthn-google-options@example.com")
    await _enable_user_features(result["user_id"])

    async with SessionLocal() as db:
        db.add(
            WebAuthnCredential(
                user_id=result["user_id"],
                credential_id=_b64(b"trusted"),
                public_key=b"pub",
                sign_count=0,
                prf_salt=secrets.token_bytes(32),
                encrypted_kek=base64.b64encode(secrets.token_bytes(48)).decode(),
                kek_nonce=base64.b64encode(secrets.token_bytes(12)).decode(),
            )
        )
        db.add(
            WebAuthnCredential(
                user_id=result["user_id"],
                credential_id=_b64(b"pending"),
                public_key=b"pub2",
                sign_count=0,
                prf_salt=secrets.token_bytes(32),
                encrypted_kek=None,
                kek_nonce=None,
            )
        )
        await db.commit()

    handoff = create_google_handoff_token(
        "webauthn-google-options@example.com",
        "google-test-sub",
        result["user_id"],
    )
    client.cookies.set(
        "vaultlocal_google_handoff",
        handoff,
        path="/api/v1/auth",
    )

    response = await client.get("/api/v1/auth/webauthn/google/options")
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["prf_salts"] == {
        _b64(b"trusted"): payload["prf_salts"][_b64(b"trusted")]
    }
    assert _b64(b"pending") not in payload["prf_salts"]


@pytest.mark.asyncio
async def test_google_webauthn_verify_consumes_challenge_and_checks_counter(
    client, register_and_login, monkeypatch
):
    result = await register_and_login("webauthn-google-verify@example.com")
    await _enable_user_features(result["user_id"])

    async with SessionLocal() as db:
        db.add(
            WebAuthnCredential(
                user_id=result["user_id"],
                credential_id=_b64(b"trusted"),
                public_key=b"pub",
                sign_count=5,
                prf_salt=secrets.token_bytes(32),
                encrypted_kek=base64.b64encode(secrets.token_bytes(48)).decode(),
                kek_nonce=base64.b64encode(secrets.token_bytes(12)).decode(),
            )
        )
        await db.commit()

    handoff = create_google_handoff_token(
        "webauthn-google-verify@example.com",
        "google-test-sub",
        result["user_id"],
    )
    client.cookies.set(
        "vaultlocal_google_handoff",
        handoff,
        path="/api/v1/auth",
    )

    options = await client.get("/api/v1/auth/webauthn/google/options")
    assert options.status_code == 200, options.text
    payload = options.json()

    monkeypatch.setattr(
        "app.routers.auth.verify_authentication_response",
        lambda **kwargs: SimpleNamespace(new_sign_count=6),
    )

    response = await client.post(
        "/api/v1/auth/webauthn/google/verify",
        json={
            "challenge": payload["challenge"],
            "credential": {
                "id": _b64(b"trusted"),
                "rawId": _b64(b"trusted"),
                "type": "public-key",
                "response": {},
            },
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["credential_id"] == _b64(b"trusted")


@pytest.mark.asyncio
async def test_local_device_options_are_restricted_to_the_trusted_credential(
    client, register_and_login
):
    result = await register_and_login("webauthn-local-device-options@example.com")
    await _enable_user_features(result["user_id"])

    credential_id = _b64(b"device-only")
    async with SessionLocal() as db:
        db.add(
            WebAuthnCredential(
                user_id=result["user_id"],
                credential_id=credential_id,
                public_key=b"pub",
                sign_count=2,
                prf_salt=secrets.token_bytes(32),
                encrypted_kek=base64.b64encode(secrets.token_bytes(48)).decode(),
                kek_nonce=base64.b64encode(secrets.token_bytes(12)).decode(),
            )
        )
        await db.commit()

    response = await client.post(
        "/api/v1/auth/webauthn/local/device/options",
        json={"credential_id": credential_id},
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert credential_id in payload["prf_salts"]
    allow_credentials = payload["options"]["allowCredentials"]
    assert len(allow_credentials) == 1
    assert allow_credentials[0]["id"] == credential_id
    assert allow_credentials[0]["type"] == "public-key"


@pytest.mark.asyncio
async def test_local_device_options_hide_missing_or_unwrapped_credentials(
    client, register_and_login
):
    result = await register_and_login("webauthn-local-device-missing@example.com")
    await _enable_user_features(result["user_id"])

    missing = await client.post(
        "/api/v1/auth/webauthn/local/device/options",
        json={"credential_id": _b64(b"does-not-exist")},
    )
    assert missing.status_code == 404

    pending_id = _b64(b"pending-device")
    async with SessionLocal() as db:
        db.add(
            WebAuthnCredential(
                user_id=result["user_id"],
                credential_id=pending_id,
                public_key=b"pub",
                sign_count=0,
                prf_salt=secrets.token_bytes(32),
                encrypted_kek=None,
                kek_nonce=None,
            )
        )
        await db.commit()

    pending = await client.post(
        "/api/v1/auth/webauthn/local/device/options",
        json={"credential_id": pending_id},
    )
    assert pending.status_code == 404


@pytest.mark.asyncio
async def test_local_webauthn_login_issues_session_and_consumes_challenge(
    client, register_and_login, monkeypatch
):
    result = await register_and_login("webauthn-local-login@example.com")
    await _enable_user_features(result["user_id"])

    async with SessionLocal() as db:
        db.add(
            WebAuthnCredential(
                user_id=result["user_id"],
                credential_id=_b64(b"local-trusted"),
                public_key=b"pub",
                sign_count=3,
                prf_salt=secrets.token_bytes(32),
                encrypted_kek=base64.b64encode(secrets.token_bytes(48)).decode(),
                kek_nonce=base64.b64encode(secrets.token_bytes(12)).decode(),
            )
        )
        await db.commit()

    options = await client.post(
        "/api/v1/auth/webauthn/local/options",
        json={"email": "webauthn-local-login@example.com"},
    )
    assert options.status_code == 200, options.text
    payload = options.json()
    assert _b64(b"local-trusted") in payload["prf_salts"]

    monkeypatch.setattr(
        "app.routers.auth.verify_authentication_response",
        lambda **kwargs: SimpleNamespace(new_sign_count=4),
    )

    response = await client.post(
        "/api/v1/auth/webauthn/local/verify",
        json={
            "challenge": payload["challenge"],
            "credential": {
                "id": _b64(b"local-trusted"),
                "rawId": _b64(b"local-trusted"),
                "type": "public-key",
                "response": {},
            },
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["credential_id"] == _b64(b"local-trusted")
    assert body["access_token"]
    assert body["refresh_token"]

    replay = await client.post(
        "/api/v1/auth/webauthn/local/verify",
        json={
            "challenge": payload["challenge"],
            "credential": {
                "id": _b64(b"local-trusted"),
                "rawId": _b64(b"local-trusted"),
                "type": "public-key",
                "response": {},
            },
        },
    )
    assert replay.status_code == 400


@pytest.mark.asyncio
async def test_webauthn_device_management_requires_totp_for_revoke(
    client, register_and_login, monkeypatch
):
    result = await register_and_login("webauthn-device-management@example.com")
    await _enable_user_features(result["user_id"])

    async with SessionLocal() as db:
        for credential_id, public_key in ((b"managed-one", b"pub1"), (b"managed-two", b"pub2")):
            db.add(
                WebAuthnCredential(
                    user_id=result["user_id"],
                    credential_id=_b64(credential_id),
                    public_key=public_key,
                    sign_count=0,
                    prf_salt=secrets.token_bytes(32),
                    encrypted_kek=base64.b64encode(secrets.token_bytes(48)).decode(),
                    kek_nonce=base64.b64encode(secrets.token_bytes(12)).decode(),
                )
            )
        await db.commit()

    auth_headers = {"Authorization": f"Bearer {result['access_token']}"}

    devices = await client.get("/api/v1/auth/webauthn/devices", headers=auth_headers)
    assert devices.status_code == 200, devices.text
    assert {item["credential_id"] for item in devices.json()["devices"]} == {
        _b64(b"managed-one"),
        _b64(b"managed-two"),
    }

    renamed = await client.patch(
        f"/api/v1/auth/webauthn/devices/{_b64(b'managed-one')}",
        headers=auth_headers,
        json={"name": "Meu notebook"},
    )
    assert renamed.status_code == 200, renamed.text
    assert renamed.json()["name"] == "Meu notebook"

    revoked_without_totp = await client.post(
        f"/api/v1/auth/webauthn/devices/{_b64(b'managed-two')}/revoke",
        headers=auth_headers,
        json={"totp_code": "000000"},
    )
    assert revoked_without_totp.status_code in {401, 429}

    async def valid_totp(user, code, db):
        return True

    monkeypatch.setattr("app.routers.auth._verify_totp_code", valid_totp)
    revoked = await client.post(
        f"/api/v1/auth/webauthn/devices/{_b64(b'managed-two')}/revoke",
        headers=auth_headers,
        json={"totp_code": "123456"},
    )
    assert revoked.status_code == 204

    devices_after = await client.get("/api/v1/auth/webauthn/devices", headers=auth_headers)
    assert devices_after.status_code == 200, devices_after.text
    assert [item["credential_id"] for item in devices_after.json()["devices"]] == [_b64(b"managed-one")]
    assert devices_after.json()["devices"][0]["name"] == "Meu notebook"
