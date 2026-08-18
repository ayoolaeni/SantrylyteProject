import pytest

from app.models.user import User
from tests.conftest import login


PROTECTED_PAGE_ROUTES = ["/", "/alerts", "/incidents", "/reports"]
ADMIN_PAGE_ROUTES = ["/admin/sources", "/admin/rules", "/admin/users", "/admin/assets"]
PROTECTED_API_ROUTES = ["/api/v1/events", "/api/v1/incidents", "/api/v1/stats/summary"]
ADMIN_API_ROUTES = ["/api/v1/rules", "/api/v1/sources", "/api/v1/users", "/api/v1/assets"]


@pytest.mark.parametrize("path", PROTECTED_PAGE_ROUTES)
def test_anonymous_page_access_redirects_to_login(client, path):
    resp = client.get(path)
    assert resp.status_code in (302, 401)
    if resp.status_code == 302:
        assert "/auth/login" in resp.headers["Location"]


@pytest.mark.parametrize("path", ADMIN_PAGE_ROUTES)
def test_anonymous_admin_page_access_denied(client, path):
    resp = client.get(path)
    assert resp.status_code in (302, 401, 403)


@pytest.mark.parametrize("path", PROTECTED_API_ROUTES)
def test_anonymous_api_access_returns_401(client, path):
    resp = client.get(path)
    assert resp.status_code == 401
    assert resp.get_json()["error"]["code"] == "UNAUTHENTICATED"


@pytest.mark.parametrize("path", ADMIN_API_ROUTES)
def test_anonymous_admin_api_access_returns_401(client, path):
    resp = client.get(path)
    assert resp.status_code == 401


@pytest.mark.parametrize("path", ADMIN_API_ROUTES)
def test_analyst_forbidden_from_admin_api(analyst_client, path):
    resp = analyst_client.get(path)
    assert resp.status_code == 403
    assert resp.get_json()["error"]["code"] == "FORBIDDEN"


@pytest.mark.parametrize("path", ADMIN_PAGE_ROUTES)
def test_analyst_forbidden_from_admin_pages(analyst_client, path):
    resp = analyst_client.get(path)
    assert resp.status_code == 403


def test_admin_can_access_admin_api(admin_client):
    resp = admin_client.get("/api/v1/rules")
    assert resp.status_code == 200


def test_viewer_can_read_but_not_mutate(viewer_client, db, log_source):
    resp = viewer_client.get("/api/v1/events")
    assert resp.status_code == 200


def test_lockout_after_max_failed_attempts(client, db):
    from app.extensions import db as _db

    user = User(username="locktest", email="locktest@example.com", full_name="Lock Test", role="ANALYST")
    user.set_password("correct-password")
    _db.session.add(user)
    _db.session.commit()

    for _ in range(5):
        client.post("/auth/login", data={"username": "locktest", "password": "wrong"})

    resp = login(client, "locktest", "correct-password")
    assert b"locked" in resp.data.lower()

    refreshed = User.query.filter_by(username="locktest").first()
    assert refreshed.is_locked()


def test_login_error_message_does_not_enumerate_users(client):
    resp_unknown = client.post("/auth/login", data={"username": "nosuchuser", "password": "x"})
    resp_known = client.post("/auth/login", data={"username": "nosuchuser2", "password": "x"})
    # Same generic message regardless of whether the account exists.
    assert b"Invalid username or password" in resp_unknown.data
    assert b"Invalid username or password" in resp_known.data
