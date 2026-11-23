"""Access control: other websites must not be able to read or drive the API."""
import pytest
from fastapi.testclient import TestClient

from backend.src.api.main import app

EVIL = "https://evil.example"
SETTINGS = {"daily_sync_time": "09:00"}


@pytest.fixture
def client():
    # Not used as a context manager, so the lifespan (scheduler, browser) does
    # not start. base_url sets the Host header to an allowed host.
    return TestClient(app, base_url="http://localhost:8000")


def test_plain_request_without_origin_is_allowed(client):
    assert client.get("/api/schema").status_code == 200


def test_foreign_origin_cannot_read_data(client):
    r = client.get("/api/schema", headers={"Origin": EVIL})
    assert r.status_code == 403
    assert "access-control-allow-origin" not in r.headers


def test_foreign_origin_cannot_write(client):
    # Cross-site form/fetch POSTs always carry an Origin header (CSRF).
    r = client.post("/api/settings", json=SETTINGS, headers={"Origin": EVIL})
    assert r.status_code == 403


def test_foreign_preflight_is_rejected(client):
    r = client.options(
        "/api/settings",
        headers={"Origin": EVIL, "Access-Control-Request-Method": "POST"},
    )
    assert r.headers.get("access-control-allow-origin") != EVIL
    assert r.headers.get("access-control-allow-origin") != "*"


def test_vite_dev_origin_is_allowed(client):
    r = client.get("/api/schema", headers={"Origin": "http://localhost:5173"})
    assert r.status_code == 200
    assert r.headers["access-control-allow-origin"] == "http://localhost:5173"


def test_same_origin_post_is_allowed(client):
    # The Docker/web UI is served by the backend itself.
    r = client.post("/api/settings", json=SETTINGS, headers={"Origin": "http://localhost:8000"})
    assert r.status_code == 200


@pytest.mark.parametrize("origin", ["null", "file://"])
def test_opaque_origin_requires_token(client, origin):
    # Sandboxed iframes on any website also send Origin: null.
    assert client.get("/api/schema", headers={"Origin": origin}).status_code == 403
    bad = {"Origin": origin, "X-Cracked-Oura-Token": "wrong"}
    assert client.get("/api/schema", headers=bad).status_code == 403
    good = {"Origin": origin, "X-Cracked-Oura-Token": "test-token"}
    assert client.get("/api/schema", headers=good).status_code == 200


def test_dns_rebinding_host_is_rejected():
    rebound = TestClient(app, base_url="http://attacker.example:8000")
    assert rebound.get("/api/schema").status_code == 400


def test_query_rejects_non_column_attributes(client):
    r = client.get("/api/query", params={"path": "sleep.metadata"})
    assert r.status_code == 400
    assert "Unknown field" in r.json()["detail"]
