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


async def test_local_breach_status_and_range(client, register_and_login, monkeypatch, tmp_path):
    from app.config import settings

    headers = await _auth_headers(register_and_login, "health-local@test.com")
    monkeypatch.setattr(settings, "HIBP_LOCAL_DIR", str(tmp_path))
    (tmp_path / "sha1.index").write_text("5BAA6\tETAG\n", encoding="utf-8")
    (tmp_path / "5BAA6.txt").write_text(
        "1E4C9B93F3F0682250B6CF8331B7EE68FD8:10\r\n",
        encoding="utf-8",
    )

    status = await client.get("/api/v1/health/breach/local/status", headers=headers)
    assert status.status_code == 200
    assert status.json() == {"available": True, "source": "hibp-local-sha1"}

    resp = await client.get("/api/v1/health/breach/local/range/5BAA6", headers=headers)
    assert resp.status_code == 200
    assert resp.text.startswith("1E4C9B93F3F0682250B6CF8331B7EE68FD8:10")

    invalid = await client.get("/api/v1/health/breach/local/range/../5BAA6", headers=headers)
    assert invalid.status_code in (400, 404)


async def test_local_breach_status_reports_missing_index(client, register_and_login, monkeypatch, tmp_path):
    from app.config import settings

    headers = await _auth_headers(register_and_login, "health-local-missing@test.com")
    monkeypatch.setattr(settings, "HIBP_LOCAL_DIR", str(tmp_path))

    status = await client.get("/api/v1/health/breach/local/status", headers=headers)
    assert status.status_code == 200
    assert status.json()["available"] is False


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


async def test_get_timeline_returns_security_events(client, register_and_login):
    headers = await _auth_headers(register_and_login, "health-timeline@test.com")

    await client.post(
        "/api/v1/health/report",
        headers=headers,
        json={"total_entries": 1, "weak_count": 0, "reused_count": 0, "old_count": 0},
    )
    response = await client.get("/api/v1/health/timeline", headers=headers)
    assert response.status_code == 200
    event_types = [event["event_type"] for event in response.json()["events"]]
    assert event_types[0] == "health_scan"
    assert "login_success" in event_types
    assert "created_at" in response.json()["events"][0]


async def test_get_timeline_is_scoped_and_requires_auth(client, register_and_login):
    headers_a = await _auth_headers(register_and_login, "timeline-a@test.com")
    headers_b = await _auth_headers(register_and_login, "timeline-b@test.com")

    await client.get("/api/v1/health/timeline", headers=headers_b)
    await client.post(
        "/api/v1/health/report",
        headers=headers_a,
        json={"total_entries": 1, "weak_count": 0, "reused_count": 0, "old_count": 0},
    )

    events_b = await client.get("/api/v1/health/timeline", headers=headers_b)
    assert events_b.status_code == 200
    assert all(event["event_type"] != "health_scan" for event in events_b.json()["events"])

    unauthenticated = await client.get("/api/v1/health/timeline")
    assert unauthenticated.status_code in (401, 403)


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
