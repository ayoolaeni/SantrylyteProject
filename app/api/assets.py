import ipaddress
import re
from collections import Counter
from datetime import datetime, timedelta, timezone

from flask import current_app, jsonify, request
from flask_login import current_user

from app.api import api_bp
from app.api.helpers import json_body
from app.extensions import db
from app.models.critical_asset import CriticalAsset
from app.models.event import Event
from app.security.audit import record as audit_record
from app.security.rbac import ApiError, role_required
from app.triage.engine import priority_for_score
from app.triage.modifiers import invalidate_asset_cache, match_critical_asset

_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9\-_.]{0,251}[A-Za-z0-9])?$")
MIN_MULTIPLIER, MAX_MULTIPLIER = 1.0, 5.0


def identifier_kind(identifier):
    """'ip', 'network' or 'hostname' — or raise if it is none of those."""
    value = identifier.strip()
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass
    if "/" in value:
        try:
            ipaddress.ip_network(value, strict=False)
            return "network"
        except ValueError:
            raise ApiError("VALIDATION_ERROR", f"'{value}' is not a valid network range (example: 10.0.0.0/24)", 422)
    if _HOSTNAME_RE.match(value):
        return "hostname"
    raise ApiError("VALIDATION_ERROR", f"'{value}' is not a valid IP address, network range or hostname", 422)


def _validate_multiplier(value):
    try:
        value = float(value)
    except (TypeError, ValueError):
        raise ApiError("VALIDATION_ERROR", "criticality_multiplier must be a number", 422)
    if not MIN_MULTIPLIER <= value <= MAX_MULTIPLIER:
        raise ApiError(
            "VALIDATION_ERROR", f"criticality_multiplier must be between {MIN_MULTIPLIER} and {MAX_MULTIPLIER}", 422
        )
    return round(value, 2)


def _check_unique(identifier, exclude_id=None):
    query = CriticalAsset.query.filter(db.func.lower(CriticalAsset.identifier) == identifier.strip().lower())
    if exclude_id is not None:
        query = query.filter(CriticalAsset.asset_id != exclude_id)
    if query.first():
        raise ApiError("VALIDATION_ERROR", f"'{identifier}' is already a critical asset", 422)


def _hits_24h():
    """Events in the last 24h whose score was boosted by each asset (keyed by asset label)."""
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    counts, last = Counter(), {}
    rows = Event.query.filter(Event.timestamp >= since, Event.severity_score > 0).with_entities(
        Event.modifiers_applied, Event.timestamp
    )
    for mods, ts in rows:
        for mod in mods or []:
            if mod.get("name") == "critical_asset":
                label = mod.get("asset")
                counts[label] += 1
                if ts and (label not in last or ts > last[label]):
                    last[label] = ts
    return counts, last


def _asset_view(asset, counts, last):
    d = asset.to_dict()
    d["kind"] = identifier_kind(asset.identifier) if asset.identifier else None
    d["threats_24h"] = counts.get(asset.label, 0)
    ts = last.get(asset.label)
    if ts is not None and ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    d["last_threat_at"] = ts.isoformat() if ts else None
    return d


def _get_asset(asset_id):
    asset = db.session.get(CriticalAsset, asset_id)
    if not asset:
        raise ApiError("NOT_FOUND", "Asset not found", 404)
    return asset


@api_bp.route("/assets", methods=["GET"])
@role_required("ADMIN")
def list_assets():
    counts, last = _hits_24h()
    assets = CriticalAsset.query.order_by(CriticalAsset.label).all()
    data = [_asset_view(a, counts, last) for a in assets]
    return jsonify({"data": data, "page": 1, "per_page": len(data), "total": len(data)})


@api_bp.route("/assets", methods=["POST"])
@role_required("ADMIN")
def create_asset():
    body = json_body()
    for field in ("identifier", "label"):
        if not str(body.get(field) or "").strip():
            raise ApiError("VALIDATION_ERROR", f"'{field}' is required", 422)
    identifier = body["identifier"].strip()
    identifier_kind(identifier)
    _check_unique(identifier)
    asset = CriticalAsset(
        identifier=identifier,
        label=body["label"].strip(),
        criticality_multiplier=_validate_multiplier(body.get("criticality_multiplier", 1.5)),
        is_enabled=body.get("is_enabled", True),
    )
    db.session.add(asset)
    db.session.commit()
    invalidate_asset_cache()
    audit_record("ASSET_CREATED", user_id=current_user.user_id, detail=f"asset={asset.identifier}")
    return jsonify(_asset_view(asset, Counter(), {})), 201


@api_bp.route("/assets/<int:asset_id>", methods=["PATCH"])
@role_required("ADMIN")
def update_asset(asset_id):
    asset = _get_asset(asset_id)
    body = json_body()
    if "identifier" in body:
        identifier = str(body["identifier"]).strip()
        identifier_kind(identifier)
        _check_unique(identifier, exclude_id=asset.asset_id)
        asset.identifier = identifier
    if "label" in body:
        if not str(body["label"]).strip():
            raise ApiError("VALIDATION_ERROR", "'label' is required", 422)
        asset.label = str(body["label"]).strip()
    if "criticality_multiplier" in body:
        asset.criticality_multiplier = _validate_multiplier(body["criticality_multiplier"])
    if "is_enabled" in body:
        asset.is_enabled = bool(body["is_enabled"])
    db.session.commit()
    invalidate_asset_cache()
    counts, last = _hits_24h()
    return jsonify(_asset_view(asset, counts, last))


@api_bp.route("/assets/<int:asset_id>", methods=["DELETE"])
@role_required("ADMIN")
def delete_asset(asset_id):
    asset = _get_asset(asset_id)
    db.session.delete(asset)
    db.session.commit()
    invalidate_asset_cache()
    audit_record("ASSET_DELETED", user_id=current_user.user_id, detail=f"asset={asset.identifier}")
    return "", 204


@api_bp.route("/assets/check", methods=["GET"])
@role_required("ADMIN")
def check_asset():
    """Which critical asset (if any) an IP or hostname falls under, and what that does to a score."""
    target = (request.args.get("target") or "").strip()
    if not target:
        raise ApiError("VALIDATION_ERROR", "target is required", 422)
    try:
        base_score = float(request.args.get("score", 50))
    except ValueError:
        raise ApiError("INVALID_PARAM", "score must be a number", 400)

    is_ip = True
    try:
        ipaddress.ip_address(target)
    except ValueError:
        is_ip = False
    invalidate_asset_cache()
    asset = match_critical_asset(target if is_ip else None, None if is_ip else target)

    cfg = current_app.config
    boosted = min(base_score * asset.criticality_multiplier, cfg["SCORE_CEILING"]) if asset else base_score
    return jsonify(
        {
            "target": target,
            "matched": asset is not None,
            "asset": {"identifier": asset.identifier, "label": asset.label, "criticality_multiplier": asset.criticality_multiplier}
            if asset else None,
            "example": {
                "base_score": base_score,
                "base_priority": priority_for_score(base_score, cfg),
                "final_score": round(boosted, 2),
                "final_priority": priority_for_score(boosted, cfg),
            },
        }
    )
