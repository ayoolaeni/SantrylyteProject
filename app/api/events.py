from datetime import datetime, timezone

from flask import jsonify, request
from flask_login import current_user

from app.api import api_bp
from app.api.helpers import json_body, list_param, paginated_response, parse_iso
from app.extensions import db
from app.models.event import Event
from app.models.incident import Incident
from app.models.incident_action import IncidentAction
from app.realtime.events import emit_incident_created
from app.security.audit import record as audit_record
from app.security.rbac import ApiError, role_required
from app.triage.engine import _auto_incident_title, _next_incident_reference


@api_bp.route("/events", methods=["GET"])
@role_required()
def list_events():
    query = Event.query

    priorities = list_param("priority")
    if priorities:
        query = query.filter(Event.priority_level.in_(priorities))

    source_id = request.args.get("source_id")
    if source_id:
        query = query.filter(Event.source_id == int(source_id))

    event_types = list_param("event_type")
    if event_types:
        query = query.filter(Event.event_type.in_(event_types))

    src_ip = request.args.get("src_ip")
    if src_ip:
        query = query.filter(Event.src_ip == src_ip)

    statuses = list_param("status")
    if statuses:
        query = query.filter(Event.status.in_(statuses))

    from_ts = parse_iso(request.args.get("from"))
    if from_ts:
        query = query.filter(Event.timestamp >= from_ts)
    to_ts = parse_iso(request.args.get("to"))
    if to_ts:
        query = query.filter(Event.timestamp <= to_ts)

    q = request.args.get("q")
    if q:
        like = f"%{q}%"
        query = query.filter(db.or_(Event.message.ilike(like), Event.raw_message.ilike(like)))

    sort = request.args.get("sort", "-timestamp")
    sort_field = sort.lstrip("-")
    column = getattr(Event, sort_field, None)
    if column is None:
        raise ApiError("INVALID_PARAM", f"Cannot sort by {sort_field}", 400)
    primary = column.desc() if sort.startswith("-") else column.asc()
    # Stable secondary ordering: newest first within ties (e.g. same severity_score).
    order_clauses = [primary] if sort_field == "timestamp" else [primary, Event.timestamp.desc()]
    query = query.order_by(*order_clauses)

    return paginated_response(query, lambda e: e.to_summary())


@api_bp.route("/events/<int:event_id>", methods=["GET"])
@role_required()
def get_event(event_id):
    event = db.session.get(Event, event_id)
    if not event:
        raise ApiError("NOT_FOUND", "Event not found", 404)
    return jsonify(event.to_dict())


@api_bp.route("/events/<int:event_id>/acknowledge", methods=["POST"])
@role_required("ADMIN", "ANALYST")
def acknowledge_event(event_id):
    event = db.session.get(Event, event_id)
    if not event:
        raise ApiError("NOT_FOUND", "Event not found", 404)
    event.status = "ACKNOWLEDGED"
    db.session.commit()
    return jsonify(event.to_summary())


@api_bp.route("/events/<int:event_id>/dismiss", methods=["POST"])
@role_required("ADMIN", "ANALYST")
def dismiss_event(event_id):
    event = db.session.get(Event, event_id)
    if not event:
        raise ApiError("NOT_FOUND", "Event not found", 404)
    body = json_body()
    if not body.get("reason"):
        raise ApiError("VALIDATION_ERROR", "A dismissal reason is required", 422)
    event.status = "DISMISSED"
    db.session.commit()
    audit_record("EVENT_DISMISSED", user_id=current_user.user_id, detail=f"event_id={event_id} reason={body['reason']}")
    return jsonify(event.to_summary())


@api_bp.route("/events/<int:event_id>/create-incident", methods=["POST"])
@role_required("ADMIN", "ANALYST")
def create_incident_from_event(event_id):
    event = db.session.get(Event, event_id)
    if not event:
        raise ApiError("NOT_FOUND", "Event not found", 404)
    body = json_body() if request.get_data() else {}

    incident = Incident(
        reference=_next_incident_reference(),
        title=body.get("title") or _auto_incident_title(event),
        originating_event_id=event.event_id,
        priority_level=event.priority_level,
        state="NEW",
        assigned_to=body.get("assign_to"),
        created_by=current_user.user_id,
    )
    db.session.add(incident)
    db.session.flush()
    db.session.add(
        IncidentAction(
            incident_id=incident.incident_id,
            user_id=current_user.user_id,
            action_type="CREATED",
            to_value="NEW",
            comment="Created from event by analyst.",
        )
    )
    event.status = "ACKNOWLEDGED"
    db.session.commit()
    emit_incident_created(incident.to_summary())
    return jsonify(incident.to_dict()), 201
