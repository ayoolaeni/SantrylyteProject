import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from flask import current_app, jsonify
from flask_login import current_user

from app.api import api_bp
from app.api.helpers import json_body
from app.extensions import db
from app.models.event import Event
from app.models.log_source import SOURCE_TYPES, LogSource
from app.security.audit import record as audit_record
from app.security.rbac import ApiError, role_required
from app.utils.time import coerce_utc

# Plain-language description of each source type, shown in the UI.
SOURCE_TYPE_INFO = {
    "SYSLOG": "Generic syslog (routers, firewalls, Linux servers). Format is detected automatically.",
    "AUTH_LOG": "Linux login and sudo activity (/var/log/auth.log or /var/log/secure).",
    "NGINX_ACCESS": "Nginx web server access log (who requested which page).",
    "APACHE_ACCESS": "Apache web server access log (who requested which page).",
    "JSON_GENERIC": "Applications that log one JSON object per line.",
    "WINDOWS_JSON": "Windows Security events exported as JSON (logons, account changes).",
}

# One harmless sample line per source type, used by "Send test event".
_TEST_LINES = {
    "SYSLOG": "{ts} {host} sentrylite-test[1]: SentryLite connectivity test from {host}",
    "AUTH_LOG": "{ts} {host} sshd[1]: Accepted publickey for sentrylite-test from 10.0.0.1 port 22 ssh2",
    "NGINX_ACCESS": '10.0.0.1 - - [{web_ts}] "GET /sentrylite-connectivity-test HTTP/1.1" 200 12 "-" "SentryLite-Test"',
    "APACHE_ACCESS": '10.0.0.1 - - [{web_ts}] "GET /sentrylite-connectivity-test HTTP/1.1" 200 12 "-" "SentryLite-Test"',
    "JSON_GENERIC": '{{"event_type": "OTHER", "message": "SentryLite connectivity test", "hostname": "{host}", "timestamp": "{iso}"}}',
    "WINDOWS_JSON": '{{"EventID": 4624, "TimeCreated": "{iso}", "Computer": "{host}", "TargetUserName": "sentrylite-test", "IpAddress": "10.0.0.1", "LogonType": 3}}',
}


def _generate_token():
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return token, token_hash


def _status(source, silent_minutes):
    if not source.is_enabled:
        return "DISABLED"
    if not source.last_seen_at:
        return "WAITING"
    return "SILENT" if source.is_silent(silent_minutes) else "RECEIVING"


def _source_view(source, counts, silent_minutes):
    d = source.to_dict()
    d["status"] = _status(source, silent_minutes)
    d["events_24h"] = counts.get(source.source_id, 0)
    d["type_description"] = SOURCE_TYPE_INFO.get(source.source_type, "")
    return d


def _event_counts_24h():
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    return dict(
        db.session.query(Event.source_id, db.func.count(Event.event_id))
        .filter(Event.timestamp >= since, Event.source_id.isnot(None))
        .group_by(Event.source_id)
        .all()
    )


def _get_source(source_id):
    source = db.session.get(LogSource, source_id)
    if not source:
        raise ApiError("NOT_FOUND", "Source not found", 404)
    return source


def _check_unique_name(name, exclude_id=None):
    query = LogSource.query.filter(db.func.lower(LogSource.name) == name.strip().lower())
    if exclude_id is not None:
        query = query.filter(LogSource.source_id != exclude_id)
    if query.first():
        raise ApiError("VALIDATION_ERROR", f"A source named '{name}' already exists", 422)


@api_bp.route("/sources", methods=["GET"])
@role_required("ADMIN")
def list_sources():
    silent_minutes = current_app.config["SOURCE_SILENT_MINUTES"]
    counts = _event_counts_24h()
    sources = LogSource.query.order_by(LogSource.name).all()
    data = [_source_view(s, counts, silent_minutes) for s in sources]
    return jsonify({"data": data, "page": 1, "per_page": len(data), "total": len(data)})


@api_bp.route("/sources/meta", methods=["GET"])
@role_required("ADMIN")
def sources_meta():
    cfg = current_app.config
    return jsonify(
        {
            "source_types": [{"value": t, "description": SOURCE_TYPE_INFO[t]} for t in SOURCE_TYPES],
            "syslog_udp_port": cfg["SYSLOG_UDP_PORT"],
            "syslog_tcp_port": cfg["SYSLOG_TCP_PORT"],
            "ingest_path": "/api/v1/ingest",
            "silent_minutes": cfg["SOURCE_SILENT_MINUTES"],
        }
    )


@api_bp.route("/sources/unregistered", methods=["GET"])
@role_required("ADMIN")
def unregistered_senders():
    """Hosts whose logs arrived in the last 24h without matching any registered source."""
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    rows = (
        db.session.query(Event.hostname, db.func.count(Event.event_id).label("n"), db.func.max(Event.received_at))
        .filter(Event.source_id.is_(None), Event.timestamp >= since)
        .group_by(Event.hostname)
        .order_by(db.desc("n"))
        .limit(20)
        .all()
    )
    return jsonify(
        [
            {"hostname": host, "events_24h": n, "last_seen_at": coerce_utc(last).isoformat() if last else None}
            for host, n, last in rows
        ]
    )


@api_bp.route("/sources", methods=["POST"])
@role_required("ADMIN")
def create_source():
    body = json_body()
    for field in ("name", "host_identifier", "source_type"):
        if not str(body.get(field) or "").strip():
            raise ApiError("VALIDATION_ERROR", f"'{field}' is required", 422)
    if body["source_type"] not in SOURCE_TYPES:
        raise ApiError("VALIDATION_ERROR", f"source_type must be one of {SOURCE_TYPES}", 422)
    _check_unique_name(body["name"])

    token, token_hash = _generate_token()
    source = LogSource(
        name=body["name"].strip(),
        host_identifier=body["host_identifier"].strip(),
        source_type=body["source_type"],
        ingest_token_hash=token_hash,
        is_enabled=body.get("is_enabled", True),
    )
    db.session.add(source)
    db.session.commit()
    audit_record("SOURCE_CREATED", user_id=current_user.user_id, detail=f"source={source.name}")

    response = _source_view(source, {}, current_app.config["SOURCE_SILENT_MINUTES"])
    response["ingest_token"] = token  # shown exactly once (§11.8)
    return jsonify(response), 201


@api_bp.route("/sources/<int:source_id>", methods=["GET"])
@role_required("ADMIN")
def get_source(source_id):
    source = _get_source(source_id)
    return jsonify(_source_view(source, _event_counts_24h(), current_app.config["SOURCE_SILENT_MINUTES"]))


@api_bp.route("/sources/<int:source_id>", methods=["PATCH"])
@role_required("ADMIN")
def update_source(source_id):
    source = _get_source(source_id)
    body = json_body()
    if "source_type" in body and body["source_type"] not in SOURCE_TYPES:
        raise ApiError("VALIDATION_ERROR", f"source_type must be one of {SOURCE_TYPES}", 422)
    if "name" in body:
        _check_unique_name(body["name"], exclude_id=source.source_id)
    for field in ("name", "host_identifier", "source_type", "is_enabled"):
        if field in body:
            setattr(source, field, body[field])
    db.session.commit()
    return jsonify(_source_view(source, _event_counts_24h(), current_app.config["SOURCE_SILENT_MINUTES"]))


@api_bp.route("/sources/<int:source_id>", methods=["DELETE"])
@role_required("ADMIN")
def delete_source(source_id):
    source = _get_source(source_id)
    # Keep the events this source already delivered; they just become "unregistered".
    Event.query.filter(Event.source_id == source.source_id).update({Event.source_id: None})
    db.session.delete(source)
    db.session.commit()
    audit_record("SOURCE_DELETED", user_id=current_user.user_id, detail=f"source={source.name}")
    return "", 204


@api_bp.route("/sources/<int:source_id>/rotate-token", methods=["POST"])
@role_required("ADMIN")
def rotate_token(source_id):
    source = _get_source(source_id)
    token, token_hash = _generate_token()
    source.ingest_token_hash = token_hash
    db.session.commit()
    response = source.to_dict()
    response["ingest_token"] = token
    return jsonify(response)


@api_bp.route("/sources/<int:source_id>/test-event", methods=["POST"])
@role_required("ADMIN")
def send_test_event(source_id):
    """Push one harmless sample line through the real pipeline as if this source sent it."""
    source = _get_source(source_id)
    if not source.is_enabled:
        raise ApiError("VALIDATION_ERROR", "Enable this source before sending a test event", 422)
    now = datetime.now(timezone.utc)
    day = now.strftime("%d").lstrip("0").rjust(2)
    host = "".join(ch if ch.isalnum() or ch in "-." else "-" for ch in source.host_identifier) or "host"
    line = _TEST_LINES[source.source_type].format(
        ts=f"{now.strftime('%b')} {day} {now.strftime('%H:%M:%S')}",
        web_ts=now.strftime("%d/%b/%Y:%H:%M:%S +0000"),
        iso=now.isoformat(),
        host=host,
    )
    current_app.raw_queue.put(source.source_id, line, received_at=now)
    if current_app.config.get("TESTING"):
        from app.ingestion.worker import process_pending

        process_pending(current_app._get_current_object(), current_app.raw_queue, max_items=5)
    return jsonify({"queued": True, "raw_message": line}), 202
