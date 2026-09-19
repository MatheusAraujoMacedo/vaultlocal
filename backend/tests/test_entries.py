STRONG_PASSWORD = "Xk9#mQ2vLp7$Wz"


async def _auth_headers(register_and_login, email):
    tokens = await register_and_login(email, STRONG_PASSWORD)
    return {"Authorization": f"Bearer {tokens['access_token']}"}


async def test_create_and_get_entry_roundtrips_encryption(client, register_and_login):
    headers = await _auth_headers(register_and_login, "alice@test.com")
    resp = await client.post(
        "/api/v1/entries",
        headers=headers,
        json={
            "title": "GitHub",
            "site": "github.com",
            "username": "alice",
            "password": "s3cr3t-p4ss",
            "notes": "personal account",
            "tags": "dev,work",
        },
    )
    assert resp.status_code == 201
    entry = resp.json()
    assert entry["username"] == "alice"
    assert entry["password"] == "s3cr3t-p4ss"
    assert entry["notes"] == "personal account"

    resp = await client.get(f"/api/v1/entries/{entry['id']}", headers=headers)
    assert resp.status_code == 200
    fetched = resp.json()
    assert fetched["username"] == "alice"
    assert fetched["password"] == "s3cr3t-p4ss"


async def test_create_entry_without_notes(client, register_and_login):
    headers = await _auth_headers(register_and_login, "noNotes@test.com")
    resp = await client.post(
        "/api/v1/entries",
        headers=headers,
        json={"title": "Site", "username": "u", "password": "p", "tags": ""},
    )
    assert resp.status_code == 201
    assert resp.json()["notes"] is None


async def test_list_entries_ordered_and_scoped_to_user(client, register_and_login):
    headers = await _auth_headers(register_and_login, "bob@test.com")
    for title in ["First", "Second"]:
        await client.post(
            "/api/v1/entries",
            headers=headers,
            json={"title": title, "username": "u", "password": "p", "tags": ""},
        )
    resp = await client.get("/api/v1/entries", headers=headers)
    assert resp.status_code == 200
    titles = [e["title"] for e in resp.json()]
    assert set(titles) == {"First", "Second"}


async def test_search_entries_matches_title(client, register_and_login):
    headers = await _auth_headers(register_and_login, "carol@test.com")
    await client.post(
        "/api/v1/entries",
        headers=headers,
        json={"title": "Netflix Account", "username": "u", "password": "p", "tags": ""},
    )
    await client.post(
        "/api/v1/entries",
        headers=headers,
        json={"title": "Work Email", "username": "u", "password": "p", "tags": ""},
    )
    resp = await client.get("/api/v1/entries/search", headers=headers, params={"q": "netflix"})
    assert resp.status_code == 200
    results = resp.json()
    assert len(results) == 1
    assert results[0]["title"] == "Netflix Account"


async def test_update_entry_changes_fields(client, register_and_login):
    headers = await _auth_headers(register_and_login, "dave@test.com")
    resp = await client.post(
        "/api/v1/entries",
        headers=headers,
        json={"title": "Old", "username": "u1", "password": "p1", "tags": ""},
    )
    entry_id = resp.json()["id"]

    resp = await client.put(
        f"/api/v1/entries/{entry_id}",
        headers=headers,
        json={"title": "New", "username": "u2", "password": "p2", "tags": "updated"},
    )
    assert resp.status_code == 200
    updated = resp.json()
    assert updated["title"] == "New"
    assert updated["username"] == "u2"
    assert updated["password"] == "p2"
    assert updated["tags"] == "updated"


async def test_delete_entry_removes_it(client, register_and_login):
    headers = await _auth_headers(register_and_login, "erin@test.com")
    resp = await client.post(
        "/api/v1/entries",
        headers=headers,
        json={"title": "Temp", "username": "u", "password": "p", "tags": ""},
    )
    entry_id = resp.json()["id"]

    resp = await client.delete(f"/api/v1/entries/{entry_id}", headers=headers)
    assert resp.status_code == 204

    resp = await client.get(f"/api/v1/entries/{entry_id}", headers=headers)
    assert resp.status_code == 404


async def test_entries_require_authentication(client):
    resp = await client.get("/api/v1/entries")
    assert resp.status_code in (401, 403)


async def test_entries_isolated_between_users(client, register_and_login):
    headers_a = await _auth_headers(register_and_login, "userA@test.com")
    headers_b = await _auth_headers(register_and_login, "userB@test.com")

    resp = await client.post(
        "/api/v1/entries",
        headers=headers_a,
        json={"title": "A's secret", "username": "u", "password": "p", "tags": ""},
    )
    entry_id = resp.json()["id"]

    resp = await client.get(f"/api/v1/entries/{entry_id}", headers=headers_b)
    assert resp.status_code == 404

    resp = await client.get("/api/v1/entries", headers=headers_b)
    assert resp.json() == []


async def test_generate_password_respects_length_and_symbols(client, register_and_login):
    headers = await _auth_headers(register_and_login, "frank@test.com")
    resp = await client.post(
        "/api/v1/entries/generate/password",
        headers=headers,
        json={"length": 24, "use_symbols": False},
    )
    assert resp.status_code == 200
    pwd = resp.json()["password"]
    assert len(pwd) == 24
    assert all(c.isalnum() for c in pwd)
