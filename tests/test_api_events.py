from app.extensions import db
from app.models.event import Event
from app.models.triage_rule import TriageRule


def _seed_high_severity_rule(db):
    rule = TriageRule(
        name="Directory traversal",
        condition={"all": [{"field": "http_path", "op": "regex", "value": r"\.\./"}]},
        weight=70,
        category="WEB_ATTACK",
    )
    db.session.add(rule)
    db.session.commit()


def test_ingest_requires_bearer_token(client):
    resp = client.post("/api/v1/ingest", json={"message": "hello"})
    assert resp.status_code == 401
    assert resp.get_json()["error"]["code"] == "UNAUTHENTICATED"


def test_ingest_rejects_bad_token(client, log_source):
    resp = client.post(
        "/api/v1/ingest", json={"message": "hello"}, headers={"Authorization": "Bearer wrong-token"}
    )
    assert resp.status_code == 401


def test_ingest_single_json_message_lands_in_db_with_priority(client, db, log_source):
    source, token = log_source
    _seed_high_severity_rule(db)

    line = '198.51.100.7 - - [10/Oct/2023:13:55:37 +0000] "GET /../../etc/passwd HTTP/1.1" 403 0 "-" "curl/8.0"'
    resp = client.post(
        "/api/v1/ingest",
        json={"message": line},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 202
    assert resp.get_json()["accepted"] == 1

    event = Event.query.first()
    assert event is not None
    assert event.priority_level == "HIGH"  # score 70 -> HIGH band
    assert event.source_id == source.source_id


def test_ingest_batch(client, log_source):
    source, token = log_source
    lines = [
        "Jul 10 10:00:01 web01 sshd[1]: Failed password for invalid user admin from 203.0.113.5 port 1 ssh2",
        "Jul 10 10:00:02 web01 sshd[2]: Failed password for invalid user admin from 203.0.113.5 port 2 ssh2",
    ]
    resp = client.post(
        "/api/v1/ingest",
        json={"events": [{"message": l} for l in lines]},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 202
    assert resp.get_json()["accepted"] == 2
    assert Event.query.count() == 2


def test_ingest_plain_text_body(client, log_source):
    _, token = log_source
    resp = client.post(
        "/api/v1/ingest",
        data="Jul 10 10:00:01 web01 sshd[1]: Accepted password for root from 203.0.113.5 port 1 ssh2",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "text/plain"},
    )
    assert resp.status_code == 202
    assert Event.query.count() == 1


def test_events_list_requires_auth(client):
    resp = client.get("/api/v1/events")
    assert resp.status_code == 401


def test_events_list_and_detail(analyst_client, db, log_source):
    _, token = log_source
    _seed_high_severity_rule(db)
    line = '198.51.100.7 - - [10/Oct/2023:13:55:37 +0000] "GET /../../etc/passwd HTTP/1.1" 403 0 "-" "curl/8.0"'
    analyst_client.post("/api/v1/ingest", json={"message": line}, headers={"Authorization": f"Bearer {token}"})

    resp = analyst_client.get("/api/v1/events")
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["total"] == 1

    event_id = body["data"][0]["event_id"]
    detail = analyst_client.get(f"/api/v1/events/{event_id}")
    assert detail.status_code == 200
    assert "matched_rules" in detail.get_json()


def test_acknowledge_and_dismiss(analyst_client, log_source):
    _, token = log_source
    analyst_client.post(
        "/api/v1/ingest",
        json={"message": "Jul 10 10:00:01 web01 sshd[1]: Accepted password for root from 203.0.113.5 port 1 ssh2"},
        headers={"Authorization": f"Bearer {token}"},
    )
    event_id = Event.query.first().event_id

    ack = analyst_client.post(f"/api/v1/events/{event_id}/acknowledge")
    assert ack.status_code == 200
    assert ack.get_json()["status"] == "ACKNOWLEDGED"

    dismiss_no_reason = analyst_client.post(f"/api/v1/events/{event_id}/dismiss", json={})
    assert dismiss_no_reason.status_code == 422

    dismiss = analyst_client.post(f"/api/v1/events/{event_id}/dismiss", json={"reason": "not real"})
    assert dismiss.status_code == 200
    assert dismiss.get_json()["status"] == "DISMISSED"


def test_viewer_cannot_acknowledge(viewer_client, log_source):
    _, token = log_source
    viewer_client.post(
        "/api/v1/ingest",
        json={"message": "Jul 10 10:00:01 web01 sshd[1]: Accepted password for root from 203.0.113.5 port 1 ssh2"},
        headers={"Authorization": f"Bearer {token}"},
    )
    event_id = Event.query.first().event_id
    resp = viewer_client.post(f"/api/v1/events/{event_id}/acknowledge")
    assert resp.status_code == 403


def test_create_incident_from_event(analyst_client, log_source):
    _, token = log_source
    analyst_client.post(
        "/api/v1/ingest",
        json={"message": "Jul 10 10:00:01 web01 sshd[1]: Accepted password for root from 203.0.113.5 port 1 ssh2"},
        headers={"Authorization": f"Bearer {token}"},
    )
    event_id = Event.query.first().event_id
    resp = analyst_client.post(f"/api/v1/events/{event_id}/create-incident", json={"title": "Manual"})
    assert resp.status_code == 201
    body = resp.get_json()
    assert body["title"] == "Manual"
    assert body["originating_event_id"] == event_id


def test_xss_payload_in_message_is_not_html_rendered(analyst_client, log_source):
    """Raw log content must round-trip through the JSON API untouched — HTML escaping is the
    client's job (ui.js only ever uses textContent), the API must never inject/execute it."""
    _, token = log_source
    payload_line = '{"event_type": "OTHER", "message": "<script>alert(1)</script>"}'
    analyst_client.post(
        "/api/v1/ingest", json={"message": payload_line}, headers={"Authorization": f"Bearer {token}"}
    )
    event = Event.query.first()
    assert event.message == "<script>alert(1)</script>"

    resp = analyst_client.get(f"/api/v1/events/{event.event_id}")
    assert resp.content_type.startswith("application/json")
    assert resp.get_json()["message"] == "<script>alert(1)</script>"
