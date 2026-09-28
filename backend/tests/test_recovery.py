import base64
import json
import secrets

import pyotp
from app.core.totp import decrypt_totp_secret
from app.db import SessionLocal
from app.models import User, VaultEntry
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from sqlalchemy import select

AUTH_KEY = base64.b64encode(b"A" * 32).decode()
NEW_AUTH_KEY = base64.b64encode(b"B" * 32).decode()


def salt() -> str:
    return base64.b64encode(secrets.token_bytes(16)).decode()


def wrapped_key() -> str:
    return base64.b64encode(b"x" * 48).decode()


def wrapped_nonce() -> str:
    return base64.b64encode(b"y" * 12).decode()


RECOVERY_PRIVATE_KEYS: dict[str, ec.EllipticCurvePrivateKey] = {}


def recovery_material(email: str) -> tuple[str, str, str]:
    private = ec.generate_private_key(ec.SECP256R1())
    public = private.public_key().public_numbers()
    x = base64.urlsafe_b64encode(public.x.to_bytes(32, "big")).decode().rstrip("=")
    y = base64.urlsafe_b64encode(public.y.to_bytes(32, "big")).decode().rstrip("=")
    public_jwk = json.dumps(
        {"kty": "EC", "crv": "P-256", "x": x, "y": y, "alg": "ES256"},
        separators=(",", ":"),
    )
    private_pkcs8 = private.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    RECOVERY_PRIVATE_KEYS[email] = private
    return public_jwk, base64.b64encode(private_pkcs8).decode(), wrapped_nonce()


def recovery_payload(email: str) -> dict[str, str]:
    public_key, wrapped_signing_key, signing_nonce = recovery_material(email)
    return {
        "recovery_public_key": public_key,
        "recovery_wrapped_signing_key": wrapped_signing_key,
        "recovery_signing_nonce": signing_nonce,
    }


def new_recovery_payload(email: str) -> dict[str, str]:
    public_key, wrapped_signing_key, signing_nonce = recovery_material(email)
    return {
        "new_recovery_public_key": public_key,
        "new_recovery_wrapped_signing_key": wrapped_signing_key,
        "new_recovery_signing_nonce": signing_nonce,
    }


async def register(client, email: str) -> str:
    resp = await client.post(
        "/api/v1/auth/register",
        json={
            "email": email,
            "salt_auth": salt(),
            "salt_crypto": salt(),
            "auth_key": AUTH_KEY,
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


async def activate_totp(client, email: str) -> dict:
    login = await client.post(
        "/api/v1/auth/login",
        json={"email": email, "auth_key": AUTH_KEY},
    )
    assert login.status_code == 200, login.text
    mfa_token = login.json()["mfa_token"]
    headers = {"Authorization": f"Bearer {mfa_token}"}
    setup = await client.post("/api/v1/auth/totp/setup", headers=headers)
    assert setup.status_code == 200, setup.text
    code = pyotp.TOTP(setup.json()["secret"]).now()
    confirm = await client.post(
        "/api/v1/auth/totp/confirm",
        headers=headers,
        json={"totp_code": code},
    )
    assert confirm.status_code == 200, confirm.text
    return confirm.json()
async def test_new_user_recovery_setup_happens_before_totp(client):
    await register(client, "onboarding-recovery@test.com")
    login = await client.post(
        "/api/v1/auth/login",
        json={"email": "onboarding-recovery@test.com", "auth_key": AUTH_KEY},
    )
    assert login.json()["status"] == "mfa_setup_required"
    headers = {"Authorization": f"Bearer {login.json()['mfa_token']}"}

    setup = await client.post(
        "/api/v1/auth/recovery/setup",
        headers=headers,
        json={
            "recovery_wrapped_kek": wrapped_key(),
            "recovery_nonce": wrapped_nonce(),
            **recovery_payload("onboarding-recovery@test.com"),
        },
    )
    assert setup.status_code == 204

    totp = await client.post("/api/v1/auth/totp/setup", headers=headers)
    code = pyotp.TOTP(totp.json()["secret"]).now()
    confirm = await client.post(
        "/api/v1/auth/totp/confirm", headers=headers, json={"totp_code": code}
    )
    assert confirm.status_code == 200

    async with SessionLocal() as db:
        user = await db.scalar(
            select(User).where(User.email == "onboarding-recovery@test.com")
        )
        assert user.recovery_wrapped_kek is not None
        assert user.recovery_nonce is not None


async def test_recovery_setup_is_one_time(client):
    await register(client, "recovery-once@test.com")
    login = await client.post(
        "/api/v1/auth/login",
        json={"email": "recovery-once@test.com", "auth_key": AUTH_KEY},
    )
    headers = {"Authorization": f"Bearer {login.json()['mfa_token']}"}
    first = await client.post(
        "/api/v1/auth/recovery/setup",
        headers=headers,
        json={
            "recovery_wrapped_kek": wrapped_key(),
            "recovery_nonce": wrapped_nonce(),
            **recovery_payload("recovery-once@test.com"),
        },
    )
    assert first.status_code == 204

    second = await client.post(
        "/api/v1/auth/recovery/setup",
        headers=headers,
        json={
            "recovery_wrapped_kek": wrapped_key(),
            "recovery_nonce": wrapped_nonce(),
            **recovery_payload("recovery-once@test.com"),
        },
    )
    assert second.status_code == 409


async def test_recovery_init_unknown_email_has_generic_random_challenge(client):
    first = await client.post(
        "/api/v1/auth/recovery/init", json={"email": "ghost-recovery@test.com"}
    )
    second = await client.post(
        "/api/v1/auth/recovery/init", json={"email": "ghost-recovery@test.com"}
    )
    assert first.status_code == second.status_code == 200
    assert len(base64.b64decode(first.json()["recovery_wrapped_kek"])) == 48
    assert len(base64.b64decode(first.json()["recovery_nonce"])) == 12
    assert len(base64.b64decode(first.json()["recovery_challenge"])) == 32
    assert first.json()["recovery_challenge"] != second.json()["recovery_challenge"]
async def prepare_recovery_account(client, email: str):
    user_id = await register(client, email)
    tokens = await activate_totp(client, email)
    async with SessionLocal() as db:
        user = await db.get(User, user_id)
        secret = decrypt_totp_secret(user.totp_secret_enc)
    login = await client.post(
        "/api/v1/auth/login",
        json={"email": email, "auth_key": AUTH_KEY},
    )
    mfa_headers = {"Authorization": f"Bearer {login.json()['mfa_token']}"}
    setup = await client.post(
        "/api/v1/auth/recovery/setup",
        headers=mfa_headers,
        json={
            "recovery_wrapped_kek": wrapped_key(),
            "recovery_nonce": wrapped_nonce(),
            **recovery_payload(email),
        },
    )
    assert setup.status_code == 204
    return user_id, secret, tokens


async def add_entry(user_id: str) -> str:
    async with SessionLocal() as db:
        entry = VaultEntry(
            user_id=user_id,
            title="Recovery test",
            site="example.com",
            username_enc=base64.b64encode(b"u").decode(),
            nonce_username=wrapped_nonce(),
            password_enc=base64.b64encode(b"p").decode(),
            nonce_password=wrapped_nonce(),
            notes_enc=None,
            nonce_notes=None,
            tags="test",
            wrapped_data_key=wrapped_key(),
            wrapped_nonce=wrapped_nonce(),
            crypto_version=2,
        )
        db.add(entry)
        await db.commit()
        await db.refresh(entry)
        return entry.id


async def verified_recovery_request(client, email: str):
    init = await client.post(
        "/api/v1/auth/recovery/init", json={"email": email}
    )
    assert init.status_code == 200
    challenge = base64.b64decode(init.json()["recovery_challenge"])
    private = RECOVERY_PRIVATE_KEYS[email]
    der_signature = private.sign(challenge, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_signature)
    raw_signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    payload = {
        "email": email,
        "recovery_challenge": base64.b64encode(challenge).decode(),
        "recovery_proof": base64.b64encode(raw_signature).decode(),
    }
    return await client.post("/api/v1/auth/recovery/verify", json=payload)


def recovery_signature(email: str, challenge: str) -> str:
    private = RECOVERY_PRIVATE_KEYS[email]
    der_signature = private.sign(base64.b64decode(challenge), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_signature)
    return base64.b64encode(r.to_bytes(32, "big") + s.to_bytes(32, "big")).decode()


async def test_recovery_verify_returns_token_and_current_entries(client):
    user_id, _, _ = await prepare_recovery_account(client, "recovery-verify@test.com")
    entry_id = await add_entry(user_id)
    resp = await verified_recovery_request(
        client, "recovery-verify@test.com"
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["recovery_token"]
    assert [e["id"] for e in body["entries"]] == [entry_id]


async def test_recovery_verify_challenge_is_single_use(client):
    await prepare_recovery_account(client, "recovery-single-use@test.com")
    init = await client.post(
        "/api/v1/auth/recovery/init",
        json={"email": "recovery-single-use@test.com"},
    )
    challenge = init.json()["recovery_challenge"]
    proof = recovery_signature(
        "recovery-single-use@test.com", challenge
    )
    payload = {
        "email": "recovery-single-use@test.com",
        "recovery_challenge": challenge,
        "recovery_proof": proof,
    }
    first = await client.post("/api/v1/auth/recovery/verify", json=payload)
    second = await client.post("/api/v1/auth/recovery/verify", json=payload)
    assert first.status_code == 200
    assert second.status_code == 401


async def test_recovery_verify_wrong_proof_rejected(client):
    await prepare_recovery_account(client, "recovery-bad-proof@test.com")
    init = await client.post(
        "/api/v1/auth/recovery/init",
        json={"email": "recovery-bad-proof@test.com"},
    )
    resp = await client.post(
        "/api/v1/auth/recovery/verify",
        json={
            "email": "recovery-bad-proof@test.com",
            "recovery_challenge": init.json()["recovery_challenge"],
            "recovery_proof": base64.b64encode(b"b" * 64).decode(),
        },
    )
    assert resp.status_code == 401


async def test_recovery_recover_rewraps_entries_and_preserves_totp(client):
    user_id, secret, old_tokens = await prepare_recovery_account(
        client, "recovery-complete@test.com"
    )
    entry_id = await add_entry(user_id)
    verify = await verified_recovery_request(
        client, "recovery-complete@test.com"
    )
    recovery_token = verify.json()["recovery_token"]

    response = await client.post(
        "/api/v1/auth/recovery/recover",
        headers={"Authorization": f"Bearer {recovery_token}"},
        json={
            "new_auth_key": NEW_AUTH_KEY,
            "new_salt_auth": salt(),
            "new_salt_crypto": salt(),
            "new_recovery_wrapped_kek": wrapped_key(),
            "new_recovery_nonce": wrapped_nonce(),
            **new_recovery_payload("recovery-complete-new@test.com"),
            "entries": [
                {
                    "id": entry_id,
                    "wrapped_data_key": base64.b64encode(b"z" * 48).decode(),
                    "wrapped_nonce": base64.b64encode(b"q" * 12).decode(),
                }
            ],
        },
    )
    assert response.status_code == 200
    assert response.json()["access_token"]

    old_refresh = old_tokens["refresh_token"]
    assert (await client.post("/api/v1/auth/refresh", json={"refresh_token": old_refresh})).status_code == 401

    async with SessionLocal() as db:
        user = await db.get(User, user_id)
        entry = await db.get(VaultEntry, entry_id)
        assert decrypt_totp_secret(user.totp_secret_enc) == secret
        assert user.mfa_configured is True
        assert user.recovery_wrapped_kek is not None
        assert entry.wrapped_data_key == base64.b64encode(b"z" * 48).decode()


async def test_recovery_recover_rejects_wrong_entry_set(client):
    user_id, _, _ = await prepare_recovery_account(client, "recovery-entry-set@test.com")
    await add_entry(user_id)
    verify = await verified_recovery_request(
        client, "recovery-entry-set@test.com"
    )
    resp = await client.post(
        "/api/v1/auth/recovery/recover",
        headers={"Authorization": f"Bearer {verify.json()['recovery_token']}"},
        json={
            "new_auth_key": NEW_AUTH_KEY,
            "new_salt_auth": salt(),
            "new_salt_crypto": salt(),
            "new_recovery_wrapped_kek": wrapped_key(),
            "new_recovery_nonce": wrapped_nonce(),
            **new_recovery_payload("recovery-entry-set-new@test.com"),
            "entries": [],
        },
    )
    assert resp.status_code == 400
async def test_password_reset_request_never_enumerates_unknown_email(client):
    resp = await client.post(
        "/api/v1/auth/password-reset/request",
        json={"email": "nobody@test.com", "totp_code": "000000"},
        headers={"X-Real-IP": "127.0.0.1"},
    )
    assert resp.status_code == 202
    assert resp.json() == {"ok": True}


async def test_password_reset_destructive_wipes_vault_and_mfa(client):
    user_id, secret, old_tokens = await prepare_recovery_account(
        client, "destructive-reset@test.com"
    )
    await add_entry(user_id)

    request = await client.post(
        "/api/v1/auth/password-reset/request",
        json={
            "email": "destructive-reset@test.com",
            "totp_code": pyotp.TOTP(secret).now(),
        },
        headers={"X-Real-IP": "127.0.0.1"},
    )
    assert request.status_code == 202
    token = request.json()["token"]
    assert token

    validated = await client.post(
        "/api/v1/auth/password-reset/validate", json={"token": token}
    )
    assert validated.status_code == 200

    confirm = await client.post(
        "/api/v1/auth/password-reset/confirm",
        json={
            "token": token,
            "new_auth_key": NEW_AUTH_KEY,
            "new_salt_auth": salt(),
            "new_salt_crypto": salt(),
        },
    )
    assert confirm.status_code == 204

    assert (await client.post(
        "/api/v1/auth/password-reset/validate", json={"token": token}
    )).status_code == 400
    assert (await client.post(
        "/api/v1/auth/password-reset/confirm",
        json={
            "token": token,
            "new_auth_key": NEW_AUTH_KEY,
            "new_salt_auth": salt(),
            "new_salt_crypto": salt(),
        },
    )).status_code == 400

    assert (await client.post(
        "/api/v1/auth/refresh", json={"refresh_token": old_tokens["refresh_token"]}
    )).status_code == 401

    async with SessionLocal() as db:
        user = await db.get(User, user_id)
        entries = list(await db.scalars(select(VaultEntry).where(VaultEntry.user_id == user_id)))
        assert entries == []
        assert user.mfa_configured is False
        assert user.totp_secret_enc is None
        assert user.recovery_wrapped_kek is None
        assert user.recovery_nonce is None


async def test_password_reset_request_requires_loopback_in_local_mode(client):
    user_id = await register(client, "reset-loopback@test.com")
    await activate_totp(client, "reset-loopback@test.com")
    async with SessionLocal() as db:
        user = await db.get(User, user_id)
        secret = decrypt_totp_secret(user.totp_secret_enc)

    resp = await client.post(
        "/api/v1/auth/password-reset/request",
        json={
            "email": "reset-loopback@test.com",
            "totp_code": pyotp.TOTP(secret).now(),
        },
        headers={"X-Real-IP": "192.168.1.10"},
    )
    assert resp.status_code == 202
    assert resp.json() == {"ok": True}
