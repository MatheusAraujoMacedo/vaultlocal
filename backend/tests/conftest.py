import base64
import os
import secrets
import tempfile

_tmp_dir = tempfile.mkdtemp(prefix="vaultlocal_test_")
os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{_tmp_dir}/test.db"
os.environ["JWT_SECRET"] = "test-secret-not-for-prod"

import pytest
from httpx import ASGITransport, AsyncClient

from app.core.limiter import limiter
from app.db import engine
from app.main import app
from app.models import Base


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
    async def _do(email: str, auth_key: str = "sim-auth-key-AAAAAAAAAAAAAAAAAAAA") -> dict:
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
        return {**resp.json(), "user_id": user_id}

    return _do
