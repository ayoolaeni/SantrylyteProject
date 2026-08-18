from datetime import datetime, timezone

from flask import jsonify
from flask_login import current_user

from app.api import api_bp
from app.api.helpers import json_body, paginated_response
from app.extensions import db
from app.models.triage_rule import TriageRule
from app.security.rbac import ApiError, role_required
from app.triage.conditions import ConditionError, evaluate_base_condition
from app.triage.engine import invalidate_rule_cache


def _validate_condition(condition):
    if not isinstance(condition, dict):
        raise ApiError("VALIDATION_ERROR", "condition must be a JSON object", 422)
    try:
        evaluate_base_condition(condition, {})
    except ConditionError as exc:
        raise ApiError("VALIDATION_ERROR", f"invalid condition: {exc}", 422)


@api_bp.route("/rules", methods=["GET"])
@role_required("ADMIN")
def list_rules():
    return paginated_response(TriageRule.query.order_by(TriageRule.rule_id), lambda r: r.to_dict())


@api_bp.route("/rules", methods=["POST"])
@role_required("ADMIN")
def create_rule():
    body = json_body()
    for field in ("name", "condition", "weight", "category"):
        if field not in body:
            raise ApiError("VALIDATION_ERROR", f"'{field}' is required", 422)
    _validate_condition(body["condition"])

    rule = TriageRule(
        name=body["name"],
        description=body.get("description"),
        condition=body["condition"],
        weight=body["weight"],
        category=body["category"],
        mitre_technique=body.get("mitre_technique"),
        is_enabled=body.get("is_enabled", True),
        created_by=current_user.user_id,
    )
    db.session.add(rule)
    db.session.commit()
    invalidate_rule_cache()
    return jsonify(rule.to_dict()), 201


@api_bp.route("/rules/<int:rule_id>", methods=["GET"])
@role_required("ADMIN")
def get_rule(rule_id):
    rule = db.session.get(TriageRule, rule_id)
    if not rule:
        raise ApiError("NOT_FOUND", "Rule not found", 404)
    return jsonify(rule.to_dict())


@api_bp.route("/rules/<int:rule_id>", methods=["PATCH"])
@role_required("ADMIN")
def update_rule(rule_id):
    rule = db.session.get(TriageRule, rule_id)
    if not rule:
        raise ApiError("NOT_FOUND", "Rule not found", 404)
    body = json_body()

    if "condition" in body:
        _validate_condition(body["condition"])
        rule.condition = body["condition"]
    for field in ("name", "description", "weight", "category", "mitre_technique", "is_enabled"):
        if field in body:
            setattr(rule, field, body[field])

    db.session.commit()
    invalidate_rule_cache()
    return jsonify(rule.to_dict())


@api_bp.route("/rules/<int:rule_id>", methods=["DELETE"])
@role_required("ADMIN")
def delete_rule(rule_id):
    rule = db.session.get(TriageRule, rule_id)
    if not rule:
        raise ApiError("NOT_FOUND", "Rule not found", 404)
    db.session.delete(rule)
    db.session.commit()
    invalidate_rule_cache()
    return "", 204


@api_bp.route("/rules/<int:rule_id>/test", methods=["POST"])
@role_required("ADMIN")
def test_rule(rule_id):
    rule = db.session.get(TriageRule, rule_id)
    if not rule:
        raise ApiError("NOT_FOUND", "Rule not found", 404)
    body = json_body()
    sample = body.get("sample_event")
    if not isinstance(sample, dict):
        raise ApiError("VALIDATION_ERROR", "sample_event object is required", 422)

    try:
        matched = evaluate_base_condition(rule.condition, sample)
    except ConditionError as exc:
        raise ApiError("VALIDATION_ERROR", f"invalid condition: {exc}", 422)

    return jsonify({"matched": bool(matched), "weight": float(rule.weight) if matched else 0.0})
