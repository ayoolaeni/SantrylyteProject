from app.extensions import db
from app.models.critical_asset import CriticalAsset
from app.models.log_source import LogSource
from app.models.triage_rule import TriageRule
from app.models.user import User


# ---------- Rules ----------

def test_rules_crud(admin_client):
    create = admin_client.post(
        "/api/v1/rules",
        json={
            "name": "Test rule",
            "condition": {"all": [{"field": "event_type", "op": "eq", "value": "AUTH_FAILURE"}]},
            "weight": 25,
            "category": "AUTHENTICATION",
        },
    )
    assert create.status_code == 201
    rule_id = create.get_json()["rule_id"]

    listed = admin_client.get("/api/v1/rules")
    assert listed.status_code == 200
    assert listed.get_json()["total"] == 1

    got = admin_client.get(f"/api/v1/rules/{rule_id}")
    assert got.status_code == 200
    assert got.get_json()["weight"] == 25.0

    patched = admin_client.patch(f"/api/v1/rules/{rule_id}", json={"weight": 55, "is_enabled": False})
    assert patched.status_code == 200
    assert patched.get_json()["weight"] == 55.0
    assert patched.get_json()["is_enabled"] is False

    tested = admin_client.post(
        f"/api/v1/rules/{rule_id}/test", json={"sample_event": {"event_type": "AUTH_FAILURE"}}
    )
    assert tested.status_code == 200
    assert tested.get_json()["matched"] is True

    deleted = admin_client.delete(f"/api/v1/rules/{rule_id}")
    assert deleted.status_code == 204
    assert TriageRule.query.count() == 0


def test_create_rule_missing_fields_rejected(admin_client):
    resp = admin_client.post("/api/v1/rules", json={"name": "incomplete"})
    assert resp.status_code == 422


def test_create_rule_bad_condition_rejected(admin_client):
    resp = admin_client.post(
        "/api/v1/rules",
        json={"name": "bad", "condition": {"field": "x", "op": "bogus", "value": 1}, "weight": 1, "category": "X"},
    )
    assert resp.status_code == 422


# ---------- Sources ----------

def test_sources_crud_and_token_lifecycle(admin_client):
    create = admin_client.post(
        "/api/v1/sources", json={"name": "web-01", "host_identifier": "10.0.0.5", "source_type": "NGINX_ACCESS"}
    )
    assert create.status_code == 201
    body = create.get_json()
    assert "ingest_token" in body
    source_id = body["source_id"]

    got = admin_client.get(f"/api/v1/sources/{source_id}")
    assert got.status_code == 200
    assert "ingest_token" not in got.get_json()  # only shown once, on creation/rotation

    disabled = admin_client.patch(f"/api/v1/sources/{source_id}", json={"is_enabled": False})
    assert disabled.status_code == 200
    assert disabled.get_json()["is_enabled"] is False

    rotated = admin_client.post(f"/api/v1/sources/{source_id}/rotate-token")
    assert rotated.status_code == 200
    assert rotated.get_json()["ingest_token"] != body["ingest_token"]

    deleted = admin_client.delete(f"/api/v1/sources/{source_id}")
    assert deleted.status_code == 204
    assert LogSource.query.count() == 0


def test_create_source_rejects_bad_type(admin_client):
    resp = admin_client.post(
        "/api/v1/sources", json={"name": "x", "host_identifier": "1.2.3.4", "source_type": "NOT_A_TYPE"}
    )
    assert resp.status_code == 422


# ---------- Users ----------

def test_users_crud(admin_client):
    create = admin_client.post(
        "/api/v1/users",
        json={"username": "newanalyst", "email": "na@example.com", "full_name": "New Analyst", "role": "ANALYST"},
    )
    assert create.status_code == 201
    body = create.get_json()
    assert "temporary_password" in body
    user_id = body["user_id"]

    patched = admin_client.patch(f"/api/v1/users/{user_id}", json={"role": "ADMIN"})
    assert patched.status_code == 200
    assert patched.get_json()["role"] == "ADMIN"

    deactivated = admin_client.delete(f"/api/v1/users/{user_id}")
    assert deactivated.status_code == 204
    assert db.session.get(User, user_id).is_active_flag is False


def test_create_user_duplicate_username_rejected(admin_client, admin_user):
    resp = admin_client.post(
        "/api/v1/users",
        json={"username": admin_user.username, "email": "dup@example.com", "full_name": "Dup", "role": "VIEWER"},
    )
    assert resp.status_code == 422


# ---------- Critical assets ----------

def test_assets_crud(admin_client):
    create = admin_client.post(
        "/api/v1/assets", json={"identifier": "10.1.1.1", "label": "Core DB", "criticality_multiplier": 2.0}
    )
    assert create.status_code == 201
    asset_id = create.get_json()["asset_id"]

    patched = admin_client.patch(f"/api/v1/assets/{asset_id}", json={"criticality_multiplier": 3.0})
    assert patched.status_code == 200
    assert patched.get_json()["criticality_multiplier"] == 3.0

    listed = admin_client.get("/api/v1/assets")
    assert listed.status_code == 200
    assert listed.get_json()["total"] == 1

    deleted = admin_client.delete(f"/api/v1/assets/{asset_id}")
    assert deleted.status_code == 204
    assert CriticalAsset.query.count() == 0


def test_create_asset_missing_fields_rejected(admin_client):
    resp = admin_client.post("/api/v1/assets", json={"identifier": "1.2.3.4"})
    assert resp.status_code == 422
