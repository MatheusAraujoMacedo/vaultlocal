def _entry_payload(**overrides):
    payload = dict(
        title="GitHub", site="github.com",
        username_enc="enc-username", nonce_username="nonce-u",
        password_enc="enc-password", nonce_password="nonce-p",
        notes_enc="enc-notes", nonce_notes="nonce-n",
        wrapped_data_key="wrapped-dk", wrapped_nonce="wrapped-n",
        tags="dev,work",
    )
    payload.update(overrides)
    return payload


async def _auth_headers(register_and_login, email):
    tokens = await register_and_login(email)
    return {"Authorization": f"Bearer {tokens['access_token']}"}


async def test_create_and_get_entry_roundtrips_blobs(client, register_and_login):
    headers = await _auth_headers(register_and_login, "alice@test.com")
    resp = await client.post("/api/v1/entries", headers=headers, json=_entry_payload())
    assert resp.status_code == 201
    entry = resp.json()
    assert entry["username_enc"] == "enc-username"
    assert entry["password_enc"] == "enc-password"
    assert entry["wrapped_data_key"] == "wrapped-dk"

    resp = await client.get(f"/api/v1/entries/{entry['id']}", headers=headers)
    assert resp.status_code == 200
    fetched = resp.json()
    assert fetched["username_enc"] == "enc-username"
    assert fetched["wrapped_nonce"] == "wrapped-n"


async def test_create_entry_without_notes(client, register_and_login):
    headers = await _auth_headers(register_and_login, "noNotes@test.com")
    resp = await client.post(
        "/api/v1/entries", headers=headers,
        json=_entry_payload(notes_enc=None, nonce_notes=None),
    )
    assert resp.status_code == 201
    assert resp.json()["notes_enc"] is None


async def test_list_entries_scoped_to_user(client, register_and_login):
    headers = await _auth_headers(register_and_login, "bob@test.com")
    for title in ["First", "Second"]:
        await client.post("/api/v1/entries", headers=headers, json=_entry_payload(title=title))
    resp = await client.get("/api/v1/entries", headers=headers)
    assert resp.status_code == 200
    titles = [e["title"] for e in resp.json()]
    assert set(titles) == {"First", "Second"}


async def test_search_entries_matches_title(client, register_and_login):
    headers = await _auth_headers(register_and_login, "carol@test.com")
    await client.post("/api/v1/entries", headers=headers, json=_entry_payload(title="Netflix Account"))
    await client.post("/api/v1/entries", headers=headers, json=_entry_payload(title="Work Email"))
    resp = await client.get("/api/v1/entries/search", headers=headers, params={"q": "netflix"})
    assert resp.status_code == 200
    results = resp.json()
    assert len(results) == 1
    assert results[0]["title"] == "Netflix Account"


async def test_update_entry_changes_blobs(client, register_and_login):
    headers = await _auth_headers(register_and_login, "dave@test.com")
    resp = await client.post("/api/v1/entries", headers=headers, json=_entry_payload(title="Old"))
    entry_id = resp.json()["id"]

    resp = await client.put(
        f"/api/v1/entries/{entry_id}", headers=headers,
        json=_entry_payload(title="New", username_enc="enc-username-2", tags="updated"),
    )
    assert resp.status_code == 200
    updated = resp.json()
    assert updated["title"] == "New"
    assert updated["username_enc"] == "enc-username-2"
    assert updated["tags"] == "updated"


async def test_delete_entry_removes_it(client, register_and_login):
    headers = await _auth_headers(register_and_login, "erin@test.com")
    resp = await client.post("/api/v1/entries", headers=headers, json=_entry_payload(title="Temp"))
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

    resp = await client.post("/api/v1/entries", headers=headers_a, json=_entry_payload(title="A's secret"))
    entry_id = resp.json()["id"]

    resp = await client.get(f"/api/v1/entries/{entry_id}", headers=headers_b)
    assert resp.status_code == 404

    resp = await client.get("/api/v1/entries", headers=headers_b)
    assert resp.json() == []


async def test_generate_password_respects_length_and_symbols(client, register_and_login):
    headers = await _auth_headers(register_and_login, "frank@test.com")
    resp = await client.post(
        "/api/v1/entries/generate/password", headers=headers,
        json={"length": 24, "use_symbols": False},
    )
    assert resp.status_code == 200
    pwd = resp.json()["password"]
    assert len(pwd) == 24
    assert all(c.isalnum() for c in pwd)
