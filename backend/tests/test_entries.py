import base64
import uuid

ENC_USERNAME = base64.b64encode(b"enc-username").decode()
ENC_USERNAME_2 = base64.b64encode(b"enc-username-2").decode()
ENC_PASSWORD = base64.b64encode(b"enc-password").decode()
ENC_NOTES = base64.b64encode(b"enc-notes").decode()
NONCE_USERNAME = base64.b64encode(b"n" * 12).decode()
NONCE_PASSWORD = base64.b64encode(b"p" * 12).decode()
NONCE_NOTES = base64.b64encode(b"o" * 12).decode()
WRAPPED_DATA_KEY = base64.b64encode(b"d" * 48).decode()
WRAPPED_NONCE = base64.b64encode(b"w" * 12).decode()


def _entry_payload(**overrides):
    payload = dict(
        id=str(uuid.uuid4()), crypto_version=2,
        title="GitHub", site="github.com",
        username_enc=ENC_USERNAME, nonce_username=NONCE_USERNAME,
        password_enc=ENC_PASSWORD, nonce_password=NONCE_PASSWORD,
        notes_enc=ENC_NOTES, nonce_notes=NONCE_NOTES,
        wrapped_data_key=WRAPPED_DATA_KEY, wrapped_nonce=WRAPPED_NONCE,
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
    assert entry["username_enc"] == ENC_USERNAME
    assert entry["password_enc"] == ENC_PASSWORD
    assert entry["wrapped_data_key"] == WRAPPED_DATA_KEY
    assert entry["crypto_version"] == 2

    resp = await client.get(f"/api/v1/entries/{entry['id']}", headers=headers)
    assert resp.status_code == 200
    fetched = resp.json()
    assert fetched["username_enc"] == ENC_USERNAME
    assert fetched["wrapped_nonce"] == WRAPPED_NONCE


async def test_create_entry_rejects_partial_password_history(client, register_and_login):
    headers = await _auth_headers(register_and_login, "history-pair@test.com")
    resp = await client.post(
        "/api/v1/entries",
        headers=headers,
        json=_entry_payload(password_history_enc=ENC_NOTES, nonce_password_history=None),
    )
    assert resp.status_code == 422


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




async def test_create_entry_rejects_duplicate_client_id(client, register_and_login):
    headers = await _auth_headers(register_and_login, "duplicate-id@test.com")
    payload = _entry_payload()
    first = await client.post("/api/v1/entries", headers=headers, json=payload)
    assert first.status_code == 201

    duplicate = await client.post("/api/v1/entries", headers=headers, json=payload)
    assert duplicate.status_code == 409


async def test_update_entry_rejects_path_body_id_mismatch(client, register_and_login):
    headers = await _auth_headers(register_and_login, "mismatch-id@test.com")
    created = await client.post("/api/v1/entries", headers=headers, json=_entry_payload())
    entry_id = created.json()["id"]
    other_id = str(uuid.uuid4())

    resp = await client.put(
        f"/api/v1/entries/{entry_id}",
        headers=headers,
        json=_entry_payload(id=other_id),
    )
    assert resp.status_code == 400

async def test_update_entry_changes_blobs(client, register_and_login):
    headers = await _auth_headers(register_and_login, "dave@test.com")
    resp = await client.post("/api/v1/entries", headers=headers, json=_entry_payload(title="Old"))
    entry_id = resp.json()["id"]

    resp = await client.put(
        f"/api/v1/entries/{entry_id}", headers=headers,
        json=_entry_payload(id=entry_id, title="New", username_enc=ENC_USERNAME_2, tags="updated"),
    )
    assert resp.status_code == 200
    updated = resp.json()
    assert updated["title"] == "New"
    assert updated["username_enc"] == ENC_USERNAME_2
    assert updated["tags"] == "updated"
    assert "updated_at" in updated
    assert updated["updated_at"] >= resp.json()["created_at"]


async def test_favorite_entry_roundtrips_and_is_filterable(client, register_and_login):
    headers = await _auth_headers(register_and_login, "favorite@test.com")
    first = await client.post("/api/v1/entries", headers=headers, json=_entry_payload(title="Favorite"))
    second = await client.post("/api/v1/entries", headers=headers, json=_entry_payload(title="Normal"))
    first_id = first.json()["id"]

    updated = await client.patch(
        f"/api/v1/entries/{first_id}/favorite",
        headers=headers,
        json={"favorite": True},
    )
    assert updated.status_code == 200
    assert updated.json()["favorite"] is True

    fetched = await client.get(f"/api/v1/entries/{first_id}", headers=headers)
    assert fetched.json()["favorite"] is True

    listed = await client.get("/api/v1/entries", headers=headers)
    favorites = [entry for entry in listed.json() if entry["favorite"]]
    assert [entry["id"] for entry in favorites] == [first_id]
    assert second.json()["favorite"] is False

    unfavorited = await client.patch(
        f"/api/v1/entries/{first_id}/favorite",
        headers=headers,
        json={"favorite": False},
    )
    assert unfavorited.status_code == 200
    assert unfavorited.json()["favorite"] is False


async def test_delete_entry_moves_it_to_trash_and_restore_works(client, register_and_login):
    headers = await _auth_headers(register_and_login, "erin@test.com")
    resp = await client.post("/api/v1/entries", headers=headers, json=_entry_payload(title="Temp"))
    entry_id = resp.json()["id"]

    resp = await client.delete(f"/api/v1/entries/{entry_id}", headers=headers)
    assert resp.status_code == 204

    resp = await client.get(f"/api/v1/entries/{entry_id}", headers=headers)
    assert resp.status_code == 404

    listed = await client.get("/api/v1/entries", headers=headers)
    assert listed.json() == []

    trash = await client.get("/api/v1/entries/trash", headers=headers)
    assert trash.status_code == 200
    assert len(trash.json()) == 1
    assert trash.json()[0]["id"] == entry_id
    assert "purge_at" in trash.json()[0]

    restored = await client.post(f"/api/v1/entries/{entry_id}/restore", headers=headers)
    assert restored.status_code == 200

    fetched = await client.get(f"/api/v1/entries/{entry_id}", headers=headers)
    assert fetched.status_code == 200

    trash = await client.get("/api/v1/entries/trash", headers=headers)
    assert trash.json() == []


async def test_permanent_delete_removes_trashed_entry(client, register_and_login):
    headers = await _auth_headers(register_and_login, "permanent@test.com")
    created = await client.post("/api/v1/entries", headers=headers, json=_entry_payload(title="Permanent"))
    entry_id = created.json()["id"]

    deleted = await client.delete(f"/api/v1/entries/{entry_id}", headers=headers)
    assert deleted.status_code == 204

    permanent = await client.delete(f"/api/v1/entries/{entry_id}/permanent", headers=headers)
    assert permanent.status_code == 204

    trash = await client.get("/api/v1/entries/trash", headers=headers)
    assert trash.json() == []


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


async def test_search_rejects_overlong_query(client, register_and_login):
    headers = await _auth_headers(register_and_login, "long-query@test.com")
    resp = await client.get("/api/v1/entries/search", headers=headers, params={"q": "x" * 129})
    assert resp.status_code == 422


async def test_create_entry_rejects_overlong_tags(client, register_and_login):
    headers = await _auth_headers(register_and_login, "long-tags@test.com")
    resp = await client.post(
        "/api/v1/entries", headers=headers,
        json=_entry_payload(tags="x" * 513),
    )
    assert resp.status_code == 422


async def test_entry_expiration_roundtrips(client, register_and_login):
    headers = await _auth_headers(register_and_login, "expiration@test.com")
    expires_at = "2030-01-02T03:04:05+00:00"
    payload = _entry_payload(expires_at=expires_at)

    created = await client.post("/api/v1/entries", headers=headers, json=payload)
    assert created.status_code == 201
    assert created.json()["expires_at"].startswith("2030-01-02T03:04:05")

    entry_id = created.json()["id"]
    fetched = await client.get(f"/api/v1/entries/{entry_id}", headers=headers)
    assert fetched.status_code == 200
    assert fetched.json()["expires_at"].startswith("2030-01-02T03:04:05")

    listed = await client.get("/api/v1/entries", headers=headers)
    assert listed.status_code == 200
    assert listed.json()[0]["expires_at"].startswith("2030-01-02T03:04:05")

    updated = await client.put(
        f"/api/v1/entries/{entry_id}",
        headers=headers,
        json=_entry_payload(id=entry_id, expires_at="2031-05-06T07:08:09+00:00"),
    )
    assert updated.status_code == 200
    assert updated.json()["expires_at"].startswith("2031-05-06T07:08:09")
