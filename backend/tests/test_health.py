async def _auth_headers(register_and_login, email):
    tokens = await register_and_login(email)
    return {"Authorization": f"Bearer {tokens['access_token']}"}


async def test_post_report_creates_new(client, register_and_login):
    headers = await _auth_headers(register_and_login, "health1@test.com")
    resp = await client.post(
        "/api/v1/health/report",
        headers=headers,
        json={"total_entries": 10, "weak_count": 2, "reused_count": 1, "old_count": 3},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["total_entries"] == 10
    assert body["weak_count"] == 2
    assert body["reused_count"] == 1
    assert body["old_count"] == 3
    assert body["breached_count"] == 0
    assert body["score"] == 100 - (15 * 2) - (10 * 1)  # 60
    assert "id" in body
    assert "created_at" in body
    assert "updated_at" in body


async def test_post_report_upserts_when_exists(client, register_and_login):
    headers = await _auth_headers(register_and_login, "health2@test.com")
    r1 = await client.post(
        "/api/v1/health/report",
        headers=headers,
        json={"total_entries": 10, "weak_count": 2, "reused_count": 1, "old_count": 0},
    )
    assert r1.status_code == 200
    first_id = r1.json()["id"]

    r2 = await client.post(
        "/api/v1/health/report",
        headers=headers,
        json={"total_entries": 12, "weak_count": 0, "reused_count": 0, "old_count": 0},
    )
    assert r2.status_code == 200
    body = r2.json()
    # same row was updated (upsert)
    assert body["id"] == first_id
    assert body["total_entries"] == 12
    assert body["weak_count"] == 0
    assert body["reused_count"] == 0


async def test_post_report_tracks_breach_count_and_score(client, register_and_login):
    headers = await _auth_headers(register_and_login, "health-breach@test.com")
    resp = await client.post(
        "/api/v1/health/report",
        headers=headers,
        json={
            "total_entries": 4,
            "weak_count": 1,
            "reused_count": 1,
            "old_count": 0,
            "breached_count": 1,
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["breached_count"] == 1
    assert body["score"] == 55


async def test_get_latest_returns_404_when_none(client, register_and_login):
    headers = await _auth_headers(register_and_login, "health3@test.com")
    resp = await client.get("/api/v1/health/latest", headers=headers)
    assert resp.status_code == 404


async def test_get_latest_returns_report_after_post(client, register_and_login):
    headers = await _auth_headers(register_and_login, "health4@test.com")
    await client.post(
        "/api/v1/health/report",
        headers=headers,
        json={"total_entries": 5, "weak_count": 1, "reused_count": 2, "old_count": 0},
    )
    resp = await client.get("/api/v1/health/latest", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["total_entries"] == 5
    assert body["weak_count"] == 1
    assert body["reused_count"] == 2


async def test_post_report_rejects_count_above_total(client, register_and_login):
    headers = await _auth_headers(register_and_login, "health5@test.com")
    resp = await client.post(
        "/api/v1/health/report",
        headers=headers,
        json={"total_entries": 5, "weak_count": 6, "reused_count": 0, "old_count": 0},
    )
    assert resp.status_code == 422


async def test_post_report_rejects_negative_counts(client, register_and_login):
    headers = await _auth_headers(register_and_login, "health6@test.com")
    resp = await client.post(
        "/api/v1/health/report",
        headers=headers,
        json={"total_entries": 5, "weak_count": -1, "reused_count": 0, "old_count": 0},
    )
    assert resp.status_code == 422


async def test_health_endpoints_require_auth(client):
    resp = await client.post(
        "/api/v1/health/report",
        json={"total_entries": 1, "weak_count": 0, "reused_count": 0, "old_count": 0},
    )
    assert resp.status_code in (401, 403)
    resp = await client.get("/api/v1/health/latest")
    assert resp.status_code in (401, 403)


async def test_reports_are_scoped_per_user(client, register_and_login):
    headers_a = await _auth_headers(register_and_login, "userA@test.com")
    headers_b = await _auth_headers(register_and_login, "userB@test.com")

    await client.post(
        "/api/v1/health/report",
        headers=headers_a,
        json={"total_entries": 10, "weak_count": 5, "reused_count": 0, "old_count": 0},
    )

    # user B has no report
    r = await client.get("/api/v1/health/latest", headers=headers_b)
    assert r.status_code == 404

    # user A sees their own
    r = await client.get("/api/v1/health/latest", headers=headers_a)
    assert r.status_code == 200
    assert r.json()["weak_count"] == 5
