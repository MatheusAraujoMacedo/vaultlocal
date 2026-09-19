import os
import tempfile

_tmp_dir = tempfile.mkdtemp(prefix="vaultlocal_test_")
os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{_tmp_dir}/test.db"
os.environ["JWT_SECRET"] = "test-secret-not-for-prod"

import pytest
from httpx import ASGITransport, AsyncClient

from app.core import kekstore
from app.core.limiter import limiter
from app.db import engine
from app.main import app
from app.models import Base


@pytest.fixture(autouse=True)
async def _isolated_state():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    kekstore._kek_store.clear()
    limiter.reset()
    yield


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.fixture
def register_and_login(client):
    async def _do(email: str, password: str) -> dict:
        resp = await client.post(
            "/api/v1/auth/register",
            json={"email": email, "master_password": password},
        )
        assert resp.status_code == 201, resp.text
        resp = await client.post(
            "/api/v1/auth/login",
            json={"email": email, "master_password": password},
        )
        assert resp.status_code == 200, resp.text
        return resp.json()

    return _do
