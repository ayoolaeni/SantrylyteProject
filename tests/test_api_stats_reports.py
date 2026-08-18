import json
from datetime import datetime, timezone

from app.models.triage_rule import TriageRule


def _ingest_some_events(analyst_client, log_source):
    """auth.log lines carry no year, so a fixed 'Jul 10' date can land outside any
    stats window depending on when the suite runs — use JSON events with an explicit
    current timestamp instead, so these tests are deterministic year-round."""
    _, token = log_source
    now = datetime.now(timezone.utc).isoformat()
    events = [
        {"timestamp": now, "event_type": "AUTH_SUCCESS", "src_ip": "203.0.113.5", "username": "root", "message": "login ok"},
        {"timestamp": now, "event_type": "AUTH_FAILURE", "src_ip": "203.0.113.6", "username": "admin", "message": "login failed"},
    ]
    for event in events:
        analyst_client.post(
            "/api/v1/ingest", json={"message": json.dumps(event)}, headers={"Authorization": f"Bearer {token}"}
        )


def test_stats_summary(analyst_client, log_source):
    _ingest_some_events(analyst_client, log_source)
    resp = analyst_client.get("/api/v1/stats/summary")
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["events_last_24h"] == 2
    assert "open_incidents_by_priority" in body
    assert set(body["open_incidents_by_priority"]) == {"INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"}


def test_stats_timeseries(analyst_client, log_source):
    _ingest_some_events(analyst_client, log_source)
    resp = analyst_client.get("/api/v1/stats/timeseries?interval=1m&window=1h")
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["interval_seconds"] == 60
    assert isinstance(body["series"], list)


def test_stats_priority_distribution(analyst_client, log_source):
    _ingest_some_events(analyst_client, log_source)
    resp = analyst_client.get("/api/v1/stats/priority-distribution?window=24h")
    assert resp.status_code == 200
    body = resp.get_json()
    assert sum(body.values()) == 2


def test_stats_top_sources_and_attackers(analyst_client, log_source):
    _ingest_some_events(analyst_client, log_source)
    top_sources = analyst_client.get("/api/v1/stats/top-sources?limit=5&window=24h")
    assert top_sources.status_code == 200
    assert top_sources.get_json()[0]["count"] == 2

    top_attackers = analyst_client.get("/api/v1/stats/top-attackers?limit=5&window=24h")
    assert top_attackers.status_code == 200
    ips = {row["src_ip"] for row in top_attackers.get_json()}
    assert ips == {"203.0.113.5", "203.0.113.6"}


def test_stats_invalid_window_param(analyst_client):
    resp = analyst_client.get("/api/v1/stats/top-sources?window=notawindow")
    assert resp.status_code == 400


def test_reports_json(analyst_client, db, log_source):
    _ingest_some_events(analyst_client, log_source)
    resp = analyst_client.get("/api/v1/reports/incidents?format=json")
    assert resp.status_code == 200
    body = resp.get_json()
    assert "totals_by_priority" in body
    assert "top_source_ips" in body
    assert isinstance(body["incidents"], list)


def test_reports_csv(analyst_client, log_source):
    _ingest_some_events(analyst_client, log_source)
    resp = analyst_client.get("/api/v1/reports/incidents?format=csv")
    assert resp.status_code == 200
    assert resp.content_type.startswith("text/csv")
    assert b"SentryLite incident report" in resp.data


def test_reports_pdf(analyst_client, log_source):
    _ingest_some_events(analyst_client, log_source)
    resp = analyst_client.get("/api/v1/reports/incidents?format=pdf")
    assert resp.status_code == 200
    assert resp.content_type.startswith("application/pdf")
    assert resp.data[:4] == b"%PDF"


def test_reports_bad_format_rejected(analyst_client):
    resp = analyst_client.get("/api/v1/reports/incidents?format=xml")
    assert resp.status_code == 400


def test_reports_with_critical_incident(analyst_client, db, log_source):
    rule = TriageRule(
        name="Malware",
        condition={"all": [{"field": "event_type", "op": "eq", "value": "MALWARE_ALERT"}]},
        weight=150,
        category="MALWARE",
    )
    db.session.add(rule)
    db.session.commit()
    _, token = log_source
    analyst_client.post(
        "/api/v1/ingest",
        json={"message": '{"event_type": "MALWARE_ALERT", "message": "bad stuff", "hostname": "srv1"}'},
        headers={"Authorization": f"Bearer {token}"},
    )
    resp = analyst_client.get("/api/v1/reports/incidents?format=json")
    body = resp.get_json()
    assert body["totals_by_priority"]["CRITICAL"] == 1
    assert len(body["incidents"]) == 1
    assert any(r["rule_name"] == "Malware" for r in body["top_rules"])
