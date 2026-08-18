import hashlib
import secrets

from flask import jsonify

from app.api import api_bp
from app.api.helpers import json_body, paginated_response
from app.extensions import db
from app.models.log_source import SOURCE_TYPES, LogSource
from app.security.rbac import ApiError, role_required


def _generate_token():
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return token, token_hash


@api_bp.route("/sources", methods=["GET"])
@role_required("ADMIN")
def list_sources():
    return paginated_response(LogSource.query.order_by(LogSource.name), lambda s: s.to_dict())


@api_bp.route("/sources", methods=["POST"])
@role_required("ADMIN")
def create_source():
    body = json_body()
    for field in ("name", "host_identifier", "source_type"):
        if field not in body:
            raise ApiError("VALIDATION_ERROR", f"'{field}' is required", 422)
    if body["source_type"] not in SOURCE_TYPES:
        raise ApiError("VALIDATION_ERROR", f"source_type must be one of {SOURCE_TYPES}", 422)

    token, token_hash = _generate_token()
    source = LogSource(
        name=body["name"],
        host_identifier=body["host_identifier"],
        source_type=body["source_type"],
        ingest_token_hash=token_hash,
        is_enabled=body.get("is_enabled", True),
    )
    db.session.add(source)
    db.session.commit()

    response = source.to_dict()
    response["ingest_token"] = token  # shown exactly once (§11.8)
    return jsonify(response), 201


@api_bp.route("/sources/<int:source_id>", methods=["GET"])
@role_required("ADMIN")
def get_source(source_id):
    source = db.session.get(LogSource, source_id)
    if not source:
        raise ApiError("NOT_FOUND", "Source not found", 404)
    return jsonify(source.to_dict())


@api_bp.route("/sources/<int:source_id>", methods=["PATCH"])
@role_required("ADMIN")
def update_source(source_id):
    source = db.session.get(LogSource, source_id)
    if not source:
        raise ApiError("NOT_FOUND", "Source not found", 404)
    body = json_body()
    if "source_type" in body and body["source_type"] not in SOURCE_TYPES:
        raise ApiError("VALIDATION_ERROR", f"source_type must be one of {SOURCE_TYPES}", 422)
    for field in ("name", "host_identifier", "source_type", "is_enabled"):
        if field in body:
            setattr(source, field, body[field])
    db.session.commit()
    return jsonify(source.to_dict())


@api_bp.route("/sources/<int:source_id>", methods=["DELETE"])
@role_required("ADMIN")
def delete_source(source_id):
    source = db.session.get(LogSource, source_id)
    if not source:
        raise ApiError("NOT_FOUND", "Source not found", 404)
    db.session.delete(source)
    db.session.commit()
    return "", 204


@api_bp.route("/sources/<int:source_id>/rotate-token", methods=["POST"])
@role_required("ADMIN")
def rotate_token(source_id):
    source = db.session.get(LogSource, source_id)
    if not source:
        raise ApiError("NOT_FOUND", "Source not found", 404)
    token, token_hash = _generate_token()
    source.ingest_token_hash = token_hash
    db.session.commit()
    response = source.to_dict()
    response["ingest_token"] = token
    return jsonify(response)
