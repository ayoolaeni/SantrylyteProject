from collections import Counter
from datetime import datetime, timedelta, timezone

from flask import current_app, jsonify
from flask_login import current_user

from app.api import api_bp
from app.api.helpers import json_body
from app.extensions import db
from app.models.event import EVENT_TYPES, PRIORITY_LEVELS, Event
from app.models.triage_rule import RULE_ACTION_KEYS, RULE_CATEGORIES, TriageRule
from app.models.user import ROLES, User
from app.security.audit import record as audit_record
from app.security.rbac import ApiError, role_required
from app.triage.conditions import OPERATORS, ConditionError, evaluate, evaluate_base_condition
from app.triage.engine import combine_rule_actions, invalidate_rule_cache

# Event fields a rule can test, with a human label and value type (drives the rule builder).
RULE_FIELDS = [
    ("event_type", "Event type", "enum"),
    ("src_ip", "Source IP (attacker)", "ip"),
    ("dest_ip", "Destination IP (target)", "ip"),
    ("dest_port", "Destination port", "number"),
    ("username", "Username", "text"),
    ("hostname", "Hostname", "text"),
    ("protocol", "Protocol", "text"),
    ("action", "Action / outcome", "text"),
    ("http_method", "HTTP method", "text"),
    ("http_path", "HTTP path / URL", "text"),
    ("http_status", "HTTP status code", "number"),
    ("user_agent", "User agent", "text"),
    ("message", "Message", "text"),
    ("raw_message", "Raw log line", "text"),
]
_FIELD_NAMES = {f for f, _, _ in RULE_FIELDS}

OPERATOR_LABELS = {
    "eq": "is", "neq": "is not", "in": "is one of", "not_in": "is not one of",
    "contains": "contains", "not_contains": "does not contain", "startswith": "starts with",
    "endswith": "ends with", "regex": "matches pattern (regex)", "gt": "is greater than",
    "gte": "is at least", "lt": "is less than", "lte": "is at most", "in_cidr": "is in network",
    "not_in_cidr": "is not in network", "exists": "is present", "is_null": "is missing",
}

CORRELATION_TYPES = ("threshold", "distinct_count", "sequence")

SAMPLE_EVENTS = {
    "Failed SSH login": {"event_type": "AUTH_FAILURE", "src_ip": "203.0.113.50", "username": "root", "hostname": "web01", "message": "Failed password for root from 203.0.113.50 port 51234 ssh2"},
    "Successful admin login from internet": {"event_type": "AUTH_SUCCESS", "src_ip": "203.0.113.50", "username": "admin", "hostname": "web01", "message": "Accepted password for admin from 203.0.113.50"},
    "SQL injection request": {"event_type": "WEB_REQUEST", "src_ip": "198.51.100.7", "http_method": "GET", "http_path": "/product?id=1 union select password from users", "http_status": 500},
    "Directory traversal request": {"event_type": "WEB_REQUEST", "src_ip": "198.51.100.7", "http_method": "GET", "http_path": "/../../etc/passwd", "http_status": 403},
    "sudo to root": {"event_type": "PRIVILEGE_CHANGE", "username": "bob", "hostname": "db01", "message": "bob : TTY=pts/0 ; USER=root ; COMMAND=/bin/bash"},
    "Logging service stopped": {"event_type": "SERVICE_STOP", "hostname": "dc01", "message": "Stopped rsyslog system logging service"},
}


def _hits_24h():
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    counts, last = Counter(), {}
    rows = Event.query.filter(Event.timestamp >= since, Event.severity_score != 0).with_entities(
        Event.matched_rules, Event.timestamp
    )
    for matched, ts in rows:
        for r in matched or []:
            rid = r.get("rule_id")
            counts[rid] += 1
            if ts and (rid not in last or ts > last[rid]):
                last[rid] = ts
    return counts, last


def _rule_view(rule, counts, last):
    d = rule.to_dict()
    d["hits_24h"] = counts.get(rule.rule_id, 0)
    ts = last.get(rule.rule_id)
    if ts is not None and ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    d["last_triggered_at"] = ts.isoformat() if ts else None
    return d


def _validate_condition(condition):
    if not isinstance(condition, dict):
        raise ApiError("VALIDATION_ERROR", "condition must be a JSON object", 422)
    base = {k: v for k, v in condition.items() if k != "correlation"}
    if not base:
        raise ApiError("VALIDATION_ERROR", "a rule needs at least one condition", 422)
    try:
        evaluate_base_condition(condition, {})
        _check_fields(base)
    except ConditionError as exc:
        raise ApiError("VALIDATION_ERROR", f"invalid condition: {exc}", 422)

    corr = condition.get("correlation")
    if corr is None:
        return
    if not isinstance(corr, dict) or corr.get("type") not in CORRELATION_TYPES:
        raise ApiError("VALIDATION_ERROR", f"correlation.type must be one of {CORRELATION_TYPES}", 422)
    if corr.get("group_by") not in _FIELD_NAMES:
        raise ApiError("VALIDATION_ERROR", "correlation.group_by must be an event field", 422)
    window = corr.get("window_seconds", 120)
    if not isinstance(window, (int, float)) or not 1 <= window <= 86400:
        raise ApiError("VALIDATION_ERROR", "correlation.window_seconds must be between 1 and 86400", 422)
    count_key = "min_count" if corr["type"] == "sequence" else "count"
    count = corr.get(count_key, 1)
    if not isinstance(count, int) or count < 1:
        raise ApiError("VALIDATION_ERROR", f"correlation.{count_key} must be a whole number of at least 1", 422)
    if corr["type"] == "distinct_count" and corr.get("distinct_field") not in _FIELD_NAMES:
        raise ApiError("VALIDATION_ERROR", "correlation.distinct_field must be an event field", 422)
    if corr["type"] == "sequence":
        try:
            _check_fields(corr.get("first") or {})
            evaluate(corr.get("first"), {})
        except ConditionError as exc:
            raise ApiError("VALIDATION_ERROR", f"invalid correlation.first: {exc}", 422)


def _check_fields(node):
    for key in ("all", "any", "none"):
        if key in node:
            if not isinstance(node[key], list) or not node[key]:
                raise ConditionError(f"'{key}' must be a non-empty list")
            for child in node[key]:
                _check_fields(child)
            return
    if "field" in node and node["field"] not in _FIELD_NAMES:
        raise ConditionError(f"unknown field: {node['field']}")


def _validate_actions(actions):
    if actions is None:
        return {}
    if not isinstance(actions, dict):
        raise ApiError("VALIDATION_ERROR", "actions must be a JSON object", 422)
    unknown = set(actions) - set(RULE_ACTION_KEYS)
    if unknown:
        raise ApiError("VALIDATION_ERROR", f"unknown action(s): {', '.join(sorted(unknown))}", 422)

    clean = {}
    for key in ("create_incident", "suppress"):
        if actions.get(key):
            clean[key] = True
    for key in ("incident_priority", "min_priority"):
        value = actions.get(key)
        if value:
            if value not in PRIORITY_LEVELS:
                raise ApiError("VALIDATION_ERROR", f"{key} must be one of {PRIORITY_LEVELS}", 422)
            clean[key] = value

    if actions.get("assign_to"):
        from app.api.incidents import resolve_assignee

        clean["assign_to"] = resolve_assignee(actions["assign_to"]).user_id
        clean["create_incident"] = True  # assigning only makes sense if an incident exists

    user_ids = actions.get("notify_user_ids") or []
    if user_ids:
        try:
            user_ids = sorted({int(u) for u in user_ids})
        except (TypeError, ValueError):
            raise ApiError("VALIDATION_ERROR", "notify_user_ids must be a list of user ids", 422)
        found = {u.user_id for u in User.query.filter(User.user_id.in_(user_ids), User.username != "system")}
        missing = set(user_ids) - found
        if missing:
            raise ApiError("VALIDATION_ERROR", f"unknown user id(s) to notify: {sorted(missing)}", 422)
        clean["notify_user_ids"] = user_ids

    roles = actions.get("notify_roles") or []
    if roles:
        bad = set(roles) - set(ROLES)
        if bad:
            raise ApiError("VALIDATION_ERROR", f"notify_roles must be from {ROLES}", 422)
        clean["notify_roles"] = sorted(set(roles))

    if clean.get("suppress") and (clean.get("create_incident") or clean.get("min_priority")):
        raise ApiError(
            "VALIDATION_ERROR", "a suppress rule auto-dismisses events, so it cannot also raise priority or open incidents", 422
        )
    return clean


def _validate_weight(weight):
    try:
        weight = float(weight)
    except (TypeError, ValueError):
        raise ApiError("VALIDATION_ERROR", "weight must be a number", 422)
    if not -100 <= weight <= 200:
        raise ApiError("VALIDATION_ERROR", "weight must be between -100 and 200", 422)
    return weight


def _check_unique_name(name, exclude_id=None):
    query = TriageRule.query.filter(db.func.lower(TriageRule.name) == name.strip().lower())
    if exclude_id is not None:
        query = query.filter(TriageRule.rule_id != exclude_id)
    if query.first():
        raise ApiError("VALIDATION_ERROR", f"A rule named '{name}' already exists", 422)


def _get_rule(rule_id):
    rule = db.session.get(TriageRule, rule_id)
    if not rule:
        raise ApiError("NOT_FOUND", "Rule not found", 404)
    return rule


@api_bp.route("/rules", methods=["GET"])
@role_required("ADMIN")
def list_rules():
    counts, last = _hits_24h()
    rules = TriageRule.query.order_by(TriageRule.category, TriageRule.name).all()
    data = [_rule_view(r, counts, last) for r in rules]
    return jsonify({"data": data, "page": 1, "per_page": len(data), "total": len(data)})


@api_bp.route("/rules/meta", methods=["GET"])
@role_required("ADMIN")
def rules_meta():
    from app.api.incidents import ASSIGNABLE_ROLES

    users = (
        User.query.filter(User.is_active_flag.is_(True), User.username != "system")
        .order_by(User.full_name)
        .all()
    )
    return jsonify(
        {
            "fields": [{"name": n, "label": label, "type": t} for n, label, t in RULE_FIELDS],
            "operators": [{"op": op, "label": OPERATOR_LABELS.get(op, op)} for op in OPERATORS],
            "event_types": list(EVENT_TYPES),
            "categories": list(RULE_CATEGORIES),
            "priorities": list(reversed(PRIORITY_LEVELS)),
            "roles": list(ROLES),
            "users": [
                {"user_id": u.user_id, "full_name": u.full_name, "role": u.role, "assignable": u.role in ASSIGNABLE_ROLES}
                for u in users
            ],
            "sample_events": SAMPLE_EVENTS,
            "thresholds": {p: current_app.config[f"THRESHOLD_{p}"] for p in ("CRITICAL", "HIGH", "MEDIUM", "LOW")},
        }
    )


@api_bp.route("/rules", methods=["POST"])
@role_required("ADMIN")
def create_rule():
    body = json_body()
    for field in ("name", "condition", "weight", "category"):
        if field not in body or body[field] in (None, ""):
            raise ApiError("VALIDATION_ERROR", f"'{field}' is required", 422)
    _validate_condition(body["condition"])
    actions = _validate_actions(body.get("actions"))
    _check_unique_name(body["name"])

    rule = TriageRule(
        name=body["name"].strip(),
        description=body.get("description"),
        condition=body["condition"],
        actions=actions,
        weight=_validate_weight(body["weight"]),
        category=body["category"],
        mitre_technique=body.get("mitre_technique") or None,
        is_enabled=body.get("is_enabled", True),
        created_by=current_user.user_id,
    )
    db.session.add(rule)
    db.session.commit()
    invalidate_rule_cache()
    audit_record("RULE_CREATED", user_id=current_user.user_id, detail=f"rule={rule.name}")
    return jsonify(_rule_view(rule, Counter(), {})), 201


@api_bp.route("/rules/<int:rule_id>", methods=["GET"])
@role_required("ADMIN")
def get_rule(rule_id):
    counts, last = _hits_24h()
    return jsonify(_rule_view(_get_rule(rule_id), counts, last))


@api_bp.route("/rules/<int:rule_id>", methods=["PATCH"])
@role_required("ADMIN")
def update_rule(rule_id):
    rule = _get_rule(rule_id)
    body = json_body()

    if "condition" in body:
        _validate_condition(body["condition"])
        rule.condition = body["condition"]
    if "actions" in body:
        rule.actions = _validate_actions(body["actions"])
    if "weight" in body:
        rule.weight = _validate_weight(body["weight"])
    if "name" in body:
        _check_unique_name(body["name"], exclude_id=rule.rule_id)
        rule.name = body["name"].strip()
    for field in ("description", "category", "mitre_technique", "is_enabled"):
        if field in body:
            setattr(rule, field, body[field])

    db.session.commit()
    invalidate_rule_cache()
    audit_record("RULE_UPDATED", user_id=current_user.user_id, detail=f"rule={rule.name}")
    counts, last = _hits_24h()
    return jsonify(_rule_view(rule, counts, last))


@api_bp.route("/rules/<int:rule_id>", methods=["DELETE"])
@role_required("ADMIN")
def delete_rule(rule_id):
    rule = _get_rule(rule_id)
    db.session.delete(rule)
    db.session.commit()
    invalidate_rule_cache()
    audit_record("RULE_DELETED", user_id=current_user.user_id, detail=f"rule={rule.name}")
    return "", 204


def _explain(node, event):
    """Per-clause pass/fail for the rule tester (flat all/any/none lists and single clauses)."""
    if not node:
        return []
    for key in ("all", "any", "none"):
        if key in node:
            out = []
            for child in node[key]:
                if "field" in child:
                    out.append({
                        "field": child["field"], "op": child.get("op"), "value": child.get("value"),
                        "actual": event.get(child["field"]), "passed": bool(evaluate(child, event)),
                    })
                else:
                    out.append({"group": True, "passed": bool(evaluate(child, event))})
            return out
    if "field" in node:
        return [{
            "field": node["field"], "op": node.get("op"), "value": node.get("value"),
            "actual": event.get(node["field"]), "passed": bool(evaluate(node, event)),
        }]
    return []


@api_bp.route("/rules/<int:rule_id>/test", methods=["POST"])
@role_required("ADMIN")
def test_rule(rule_id):
    rule = _get_rule(rule_id)
    body = json_body()
    sample = body.get("sample_event")
    if body.get("event_id") is not None:
        event = db.session.get(Event, body["event_id"])
        if not event:
            raise ApiError("NOT_FOUND", "event_id does not reference a known event", 404)
        sample = event.to_dict()
    if not isinstance(sample, dict):
        raise ApiError("VALIDATION_ERROR", "sample_event object (or event_id) is required", 422)

    base = {k: v for k, v in (rule.condition or {}).items() if k != "correlation"}
    try:
        matched = evaluate_base_condition(rule.condition, sample)
        clauses = _explain(base, sample)
    except ConditionError as exc:
        raise ApiError("VALIDATION_ERROR", f"invalid condition: {exc}", 422)

    outcome = combine_rule_actions([rule]) if matched else None
    corr = (rule.condition or {}).get("correlation")
    return jsonify({
        "matched": bool(matched),
        "weight": float(rule.weight) if matched else 0.0,
        "clauses": clauses,
        "correlation_note": (
            "This rule also needs a pattern over time (see 'Repeats'). The tester checks one event, "
            "so a real event must also meet that threshold before the rule fires."
        ) if corr else None,
        "actions": (rule.actions or {}) if matched else {},
        "would_suppress": bool(outcome and outcome.suppressed_by),
        "would_create_incident": bool(outcome and outcome.create_incident),
    })
