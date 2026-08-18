from app.extensions import db
from app.models.event import Event
from app.models.incident import Incident
from app.models.triage_rule import TriageRule


def _seed_critical_rule(db):
    rule = TriageRule(
        name="Malware",
        condition={"all": [{"field": "event_type", "op": "eq", "value": "MALWARE_ALERT"}]},
        weight=150,
        category="MALWARE",
    )
    db.session.add(rule)
    db.session.commit()


def _make_critical_incident(analyst_client, db, log_source):
    _seed_critical_rule(db)
    _, token = log_source
    analyst_client.post(
        "/api/v1/ingest",
        json={"message": '{"event_type": "MALWARE_ALERT", "message": "ransomware detected", "hostname": "srv1"}'},
        headers={"Authorization": f"Bearer {token}"},
    )
    incident = Incident.query.first()
    assert incident is not None
    assert incident.state == "NEW"
    return incident


def test_critical_event_auto_creates_incident(analyst_client, db, log_source):
    incident = _make_critical_incident(analyst_client, db, log_source)
    assert incident.priority_level == "CRITICAL"
    assert incident.reference.startswith("INC-")
    assert len(incident.actions) == 1
    assert incident.actions[0].action_type == "CREATED"


def test_full_incident_lifecycle(analyst_client, db, log_source):
    incident = _make_critical_incident(analyst_client, db, log_source)
    ref = incident.reference

    r1 = analyst_client.post(f"/api/v1/incidents/{ref}/transition", json={"to_state": "ACKNOWLEDGED"})
    assert r1.status_code == 200
    assert r1.get_json()["state"] == "ACKNOWLEDGED"

    r2 = analyst_client.post(f"/api/v1/incidents/{ref}/transition", json={"to_state": "INVESTIGATING"})
    assert r2.status_code == 200

    # RESOLVED requires a resolution_summary
    r3_missing = analyst_client.post(f"/api/v1/incidents/{ref}/transition", json={"to_state": "RESOLVED"})
    assert r3_missing.status_code == 422

    r3 = analyst_client.post(
        f"/api/v1/incidents/{ref}/transition",
        json={"to_state": "RESOLVED", "resolution_summary": "Contained and cleaned."},
    )
    assert r3.status_code == 200
    assert r3.get_json()["state"] == "RESOLVED"

    r4 = analyst_client.post(f"/api/v1/incidents/{ref}/transition", json={"to_state": "CLOSED"})
    assert r4.status_code == 200
    assert r4.get_json()["state"] == "CLOSED"


def test_illegal_transition_rejected_with_409(analyst_client, db, log_source):
    incident = _make_critical_incident(analyst_client, db, log_source)
    # NEW only permits ACKNOWLEDGED; NEW -> RESOLVED and NEW -> CLOSED are both illegal edges.
    resp = analyst_client.post(f"/api/v1/incidents/{incident.reference}/transition", json={"to_state": "RESOLVED"})
    assert resp.status_code == 409
    assert resp.get_json()["error"]["code"] == "INVALID_TRANSITION"

    resp2 = analyst_client.post(f"/api/v1/incidents/{incident.reference}/transition", json={"to_state": "CLOSED"})
    assert resp2.status_code == 409
    assert resp2.get_json()["error"]["code"] == "INVALID_TRANSITION"


def test_reopen_from_closed_requires_admin(admin_client, analyst_client, db, log_source):
    incident = _make_critical_incident(analyst_client, db, log_source)
    ref = incident.reference
    analyst_client.post(f"/api/v1/incidents/{ref}/transition", json={"to_state": "ACKNOWLEDGED"})
    analyst_client.post(f"/api/v1/incidents/{ref}/transition", json={"to_state": "INVESTIGATING"})
    analyst_client.post(
        f"/api/v1/incidents/{ref}/transition",
        json={"to_state": "RESOLVED", "resolution_summary": "done"},
    )
    analyst_client.post(f"/api/v1/incidents/{ref}/transition", json={"to_state": "CLOSED"})

    forbidden = analyst_client.post(f"/api/v1/incidents/{ref}/transition", json={"to_state": "INVESTIGATING"})
    assert forbidden.status_code == 403

    allowed = admin_client.post(f"/api/v1/incidents/{ref}/transition", json={"to_state": "INVESTIGATING"})
    assert allowed.status_code == 200
    assert allowed.get_json()["state"] == "INVESTIGATING"


def test_assign_and_comment(analyst_client, admin_user, db, log_source):
    incident = _make_critical_incident(analyst_client, db, log_source)
    ref = incident.reference

    assign_resp = analyst_client.post(f"/api/v1/incidents/{ref}/assign", json={"user_id": admin_user.user_id})
    assert assign_resp.status_code == 200
    assert assign_resp.get_json()["assigned_to"] == admin_user.user_id

    comment_resp = analyst_client.post(f"/api/v1/incidents/{ref}/comment", json={"comment": "Investigating now."})
    assert comment_resp.status_code == 200
    comments = [a for a in comment_resp.get_json()["actions"] if a["action_type"] == "COMMENTED"]
    assert len(comments) == 1


def test_link_event(analyst_client, db, log_source):
    incident = _make_critical_incident(analyst_client, db, log_source)
    _, token = log_source
    analyst_client.post(
        "/api/v1/ingest",
        json={"message": "Jul 10 10:00:01 web01 sshd[1]: Accepted password for root from 203.0.113.5 port 1 ssh2"},
        headers={"Authorization": f"Bearer {token}"},
    )
    other_event = Event.query.filter(Event.event_id != incident.originating_event_id).first()

    resp = analyst_client.post(f"/api/v1/incidents/{incident.reference}/link-event", json={"event_id": other_event.event_id})
    assert resp.status_code == 200
    linked_ids = [e["event_id"] for e in resp.get_json()["linked_events"]]
    assert other_event.event_id in linked_ids


def test_only_admin_can_override_priority(analyst_client, admin_client, db, log_source):
    incident = _make_critical_incident(analyst_client, db, log_source)
    ref = incident.reference

    denied = analyst_client.patch(f"/api/v1/incidents/{ref}", json={"priority_level": "LOW"})
    assert denied.status_code == 403

    allowed = admin_client.patch(f"/api/v1/incidents/{ref}", json={"priority_level": "LOW"})
    assert allowed.status_code == 200
    assert allowed.get_json()["priority_level"] == "LOW"


def test_anonymous_cannot_access_incidents(client):
    resp = client.get("/api/v1/incidents")
    assert resp.status_code == 401
