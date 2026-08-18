from datetime import datetime, timezone

from flask import jsonify, request
from flask_login import current_user

from app.api import api_bp
from app.api.helpers import json_body, list_param, paginated_response, parse_iso
from app.extensions import db
from app.models.event import Event
from app.models.incident import (
    ADMIN_ONLY_TRANSITIONS,
    REQUIRES_RESOLUTION_SUMMARY,
    Incident,
)
from app.models.incident_action import IncidentAction
from app.models.user import User
from app.realtime.events import emit_incident_updated
from app.security.rbac import ApiError, role_required
from app.triage.engine import _next_incident_reference


def _find_incident(identifier):
    incident = None
    if str(identifier).isdigit():
        incident = db.session.get(Incident, int(identifier))
    if incident is None:
        incident = Incident.query.filter_by(reference=identifier).first()
    if incident is None:
        raise ApiError("NOT_FOUND", "Incident not found", 404)
    return incident


def _log_action(incident, action_type, from_value=None, to_value=None, comment=None):
    db.session.add(
        IncidentAction(
            incident_id=incident.incident_id,
            user_id=current_user.user_id,
            action_type=action_type,
            from_value=from_value,
            to_value=to_value,
            comment=comment,
        )
    )


@api_bp.route("/incidents", methods=["GET"])
@role_required()
def list_incidents():
    query = Incident.query

    states = list_param("state")
    if states:
        query = query.filter(Incident.state.in_(states))

    priorities = list_param("priority")
    if priorities:
        query = query.filter(Incident.priority_level.in_(priorities))

    assigned_to = request.args.get("assigned_to")
    if assigned_to == "me":
        query = query.filter(Incident.assigned_to == current_user.user_id)
    elif assigned_to:
        query = query.filter(Incident.assigned_to == int(assigned_to))

    from_ts = parse_iso(request.args.get("from"))
    if from_ts:
        query = query.filter(Incident.created_at >= from_ts)
    to_ts = parse_iso(request.args.get("to"))
    if to_ts:
        query = query.filter(Incident.created_at <= to_ts)

    query = query.order_by(Incident.created_at.desc())
    return paginated_response(query, lambda i: i.to_summary())


@api_bp.route("/incidents/<identifier>", methods=["GET"])
@role_required()
def get_incident(identifier):
    return jsonify(_find_incident(identifier).to_dict())


@api_bp.route("/incidents", methods=["POST"])
@role_required("ADMIN", "ANALYST")
def create_incident():
    body = json_body()
    event_id = body.get("originating_event_id")
    if not event_id:
        raise ApiError("VALIDATION_ERROR", "originating_event_id is required", 422)
    event = db.session.get(Event, event_id)
    if not event:
        raise ApiError("NOT_FOUND", "originating_event_id does not reference a known event", 404)

    incident = Incident(
        reference=_next_incident_reference(),
        title=body.get("title") or f"Manual incident: {event.event_type}",
        description=body.get("description"),
        originating_event_id=event.event_id,
        priority_level=body.get("priority_level") or event.priority_level,
        state="NEW",
        assigned_to=body.get("assign_to"),
        created_by=current_user.user_id,
    )
    db.session.add(incident)
    db.session.flush()
    _log_action(incident, "CREATED", to_value="NEW", comment="Manually created.")
    db.session.commit()
    emit_incident_updated({"incident_id": incident.incident_id, "state": incident.state, "assigned_to": incident.assigned_to, "updated_by": current_user.user_id})
    return jsonify(incident.to_dict()), 201


@api_bp.route("/incidents/<identifier>", methods=["PATCH"])
@role_required("ADMIN", "ANALYST")
def update_incident(identifier):
    incident = _find_incident(identifier)
    body = json_body()

    if "title" in body:
        incident.title = body["title"]
    if "description" in body:
        incident.description = body["description"]
    if "priority_level" in body:
        if current_user.role != "ADMIN":
            raise ApiError("FORBIDDEN", "Only ADMIN may override incident priority", 403)
        incident.priority_level = body["priority_level"]

    db.session.commit()
    return jsonify(incident.to_dict())


@api_bp.route("/incidents/<identifier>/transition", methods=["POST"])
@role_required("ADMIN", "ANALYST")
def transition_incident(identifier):
    incident = _find_incident(identifier)
    body = json_body()
    to_state = body.get("to_state")

    if not to_state:
        raise ApiError("VALIDATION_ERROR", "to_state is required", 422)
    if not incident.can_transition_to(to_state):
        raise ApiError(
            "INVALID_TRANSITION", f"Cannot move {incident.state} -> {to_state}", 409,
            {"from": incident.state, "to": to_state},
        )
    if (incident.state, to_state) in ADMIN_ONLY_TRANSITIONS and current_user.role != "ADMIN":
        raise ApiError("FORBIDDEN", "Only ADMIN may reopen a closed incident", 403)

    resolution_summary = body.get("resolution_summary")
    if to_state in REQUIRES_RESOLUTION_SUMMARY and not resolution_summary:
        raise ApiError("VALIDATION_ERROR", f"resolution_summary is required to move to {to_state}", 422)

    from_state = incident.state
    incident.state = to_state
    now = datetime.now(timezone.utc)

    if to_state == "ACKNOWLEDGED" and incident.acknowledged_at is None:
        incident.acknowledged_at = now
    if to_state == "RESOLVED":
        incident.resolved_at = now
    if to_state == "CLOSED":
        incident.closed_at = now
    if resolution_summary:
        incident.resolution_summary = resolution_summary

    action_type = {
        "ACKNOWLEDGED": "ACKNOWLEDGED",
        "ESCALATED": "ESCALATED",
        "RESOLVED": "RESOLVED",
        "CLOSED": "CLOSED",
    }.get(to_state, "STATE_CHANGED")
    if from_state == "CLOSED" and to_state == "INVESTIGATING":
        action_type = "REOPENED"

    _log_action(incident, action_type, from_value=from_state, to_value=to_state, comment=resolution_summary)
    db.session.commit()

    emit_incident_updated(
        {"incident_id": incident.incident_id, "state": incident.state, "assigned_to": incident.assigned_to, "updated_by": current_user.user_id}
    )
    return jsonify(incident.to_dict())


@api_bp.route("/incidents/<identifier>/assign", methods=["POST"])
@role_required("ADMIN", "ANALYST")
def assign_incident(identifier):
    incident = _find_incident(identifier)
    body = json_body()
    user_id = body.get("user_id")
    if user_id is not None:
        assignee = db.session.get(User, user_id)
        if not assignee:
            raise ApiError("NOT_FOUND", "user_id does not reference a known user", 404)

    from_value = str(incident.assigned_to) if incident.assigned_to else None
    incident.assigned_to = user_id
    _log_action(incident, "ASSIGNED", from_value=from_value, to_value=str(user_id) if user_id else None)
    db.session.commit()

    emit_incident_updated(
        {"incident_id": incident.incident_id, "state": incident.state, "assigned_to": incident.assigned_to, "updated_by": current_user.user_id}
    )
    return jsonify(incident.to_dict())


@api_bp.route("/incidents/<identifier>/comment", methods=["POST"])
@role_required("ADMIN", "ANALYST")
def comment_incident(identifier):
    incident = _find_incident(identifier)
    body = json_body()
    comment = body.get("comment")
    if not comment:
        raise ApiError("VALIDATION_ERROR", "comment is required", 422)
    _log_action(incident, "COMMENTED", comment=comment)
    db.session.commit()
    return jsonify(incident.to_dict())


@api_bp.route("/incidents/<identifier>/link-event", methods=["POST"])
@role_required("ADMIN", "ANALYST")
def link_event(identifier):
    incident = _find_incident(identifier)
    body = json_body()
    event = db.session.get(Event, body.get("event_id"))
    if not event:
        raise ApiError("NOT_FOUND", "event_id does not reference a known event", 404)
    if event not in incident.linked_events:
        incident.linked_events.append(event)
    _log_action(incident, "EVENT_LINKED", to_value=str(event.event_id))
    db.session.commit()
    return jsonify(incident.to_dict())
