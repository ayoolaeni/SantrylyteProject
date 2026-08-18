from flask import jsonify

from app.api import api_bp
from app.api.helpers import json_body, paginated_response
from app.extensions import db
from app.models.critical_asset import CriticalAsset
from app.security.rbac import ApiError, role_required
from app.triage.modifiers import invalidate_asset_cache


@api_bp.route("/assets", methods=["GET"])
@role_required("ADMIN")
def list_assets():
    return paginated_response(CriticalAsset.query.order_by(CriticalAsset.label), lambda a: a.to_dict())


@api_bp.route("/assets", methods=["POST"])
@role_required("ADMIN")
def create_asset():
    body = json_body()
    for field in ("identifier", "label"):
        if field not in body:
            raise ApiError("VALIDATION_ERROR", f"'{field}' is required", 422)
    asset = CriticalAsset(
        identifier=body["identifier"],
        label=body["label"],
        criticality_multiplier=body.get("criticality_multiplier", 1.5),
        is_enabled=body.get("is_enabled", True),
    )
    db.session.add(asset)
    db.session.commit()
    invalidate_asset_cache()
    return jsonify(asset.to_dict()), 201


@api_bp.route("/assets/<int:asset_id>", methods=["PATCH"])
@role_required("ADMIN")
def update_asset(asset_id):
    asset = db.session.get(CriticalAsset, asset_id)
    if not asset:
        raise ApiError("NOT_FOUND", "Asset not found", 404)
    body = json_body()
    for field in ("identifier", "label", "criticality_multiplier", "is_enabled"):
        if field in body:
            setattr(asset, field, body[field])
    db.session.commit()
    invalidate_asset_cache()
    return jsonify(asset.to_dict())


@api_bp.route("/assets/<int:asset_id>", methods=["DELETE"])
@role_required("ADMIN")
def delete_asset(asset_id):
    asset = db.session.get(CriticalAsset, asset_id)
    if not asset:
        raise ApiError("NOT_FOUND", "Asset not found", 404)
    db.session.delete(asset)
    db.session.commit()
    invalidate_asset_cache()
    return "", 204
