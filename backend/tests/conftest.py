import base64
import os
import secrets
import tempfile

_tmp_dir = tempfile.mkdtemp(prefix="vaultlocal_test_")
os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{_tmp_dir}/test.db"
os.environ["JWT_SECRET"] = "test-secret-not-for-prod-0123456789ab"
os.environ["TOTP_ENCRYPTION_KEY"] = "a" * 64
os.environ["ALLOWED_HOSTS"] = "test,localhost,127.0.0.1"

import pyotp
import pytest
from app.core.limiter import limiter
from app.db import engine
from app.main import app
from app.models import Base
from httpx import ASGITransport, AsyncClient


@pytest.fixture(autouse=True)
async def _isolated_state():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    limiter.reset()
    yield


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.fixture
def register_and_login(client):
    async def _do(email: str, auth_key: str = base64.b64encode(b"A" * 32).decode()) -> dict:
        salt_auth = base64.b64encode(secrets.token_bytes(16)).decode()
        salt_crypto = base64.b64encode(secrets.token_bytes(16)).decode()
        resp = await client.post(
            "/api/v1/auth/register",
            json={"email": email, "salt_auth": salt_auth, "salt_crypto": salt_crypto, "auth_key": auth_key},
        )
        assert resp.status_code == 201, resp.text
        user_id = resp.json()["id"]

        resp = await client.post("/api/v1/auth/login", json={"email": email, "auth_key": auth_key})
        assert resp.status_code == 200, resp.text
        mfa_headers = {"Authorization": f"Bearer {resp.json()['mfa_token']}"}

        setup = await client.post("/api/v1/auth/totp/setup", headers=mfa_headers)
        assert setup.status_code == 200, setup.text
        code = pyotp.TOTP(setup.json()["secret"]).now()

        confirm = await client.post(
            "/api/v1/auth/totp/confirm", headers=mfa_headers, json={"totp_code": code}
        )
        assert confirm.status_code == 200, confirm.text
        return {**confirm.json(), "user_id": user_id}

    return _do
