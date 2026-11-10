"""Admin-only "reset all data": back to a fresh install, keeping every user account."""
import os

from flask import current_app, jsonify
from flask_login import current_user

from app.api import api_bp
from app.api.helpers import json_body
from app.extensions import db, socketio
from app.models.audit_log import AuditLog
from app.models.critical_asset import CriticalAsset
from app.models.event import Event
from app.models.incident import Incident, incident_event
from app.models.incident_action import IncidentAction
from app.models.log_source import LogSource
from app.models.triage_rule import TriageRule
from app.realtime.events import NAMESPACE
from app.security.audit import record as audit_record
from app.security.rbac import ApiError, role_required

CONFIRM_WORD = "RESET"


def _restore_defaults():
    from seeds.seed_assets import ASSETS
    from seeds.seed_rules import DEFAULT_ACTIONS, RULES

    for spec in RULES:
        db.session.add(TriageRule(**spec, actions=DEFAULT_ACTIONS.get(spec["name"], {})))
    for spec in ASSETS:
        db.session.add(CriticalAsset(**spec))


def _clear_pending_ingestion(app):
    """Drop anything queued or spilled to disk, so old logs don't reappear after the reset."""
    queue = app.raw_queue
    while queue.get_nowait() is not None:
        pass
    for path in (queue.spill_path, os.path.join(app.config["SPILL_DIR"], "dead_letter.ndjson")):
        try:
            os.remove(path)
        except FileNotFoundError:
            pass


@api_bp.route("/admin/reset-data", methods=["POST"])
@role_required("ADMIN")
def reset_data():
    body = json_body()
    if body.get("confirm") != CONFIRM_WORD:
        raise ApiError("VALIDATION_ERROR", f"Type {CONFIRM_WORD} to confirm the reset", 422)

    from app import simulator
    from app.triage.correlator import correlator
    from app.triage.engine import invalidate_rule_cache
    from app.triage.modifiers import invalidate_asset_cache

    app = current_app._get_current_object()
    simulator.stop_background()
    _clear_pending_ingestion(app)

    counts = {
        "events": Event.query.count(),
        "incidents": Incident.query.count(),
        "log_sources": LogSource.query.count(),
    }
    db.session.execute(incident_event.delete())
    IncidentAction.query.delete(synchronize_session=False)
    Incident.query.delete(synchronize_session=False)
    Event.query.delete(synchronize_session=False)
    LogSource.query.delete(synchronize_session=False)
    AuditLog.query.delete(synchronize_session=False)
    TriageRule.query.delete(synchronize_session=False)
    CriticalAsset.query.delete(synchronize_session=False)
    _restore_defaults()
    db.session.commit()

    correlator.reset()
    invalidate_rule_cache()
    invalidate_asset_cache()
    app.extensions.pop("sentrylite_incident_refs", None)

    audit_record("DATA_RESET", user_id=current_user.user_id, detail=f"cleared={counts}")
    socketio.emit("data:reset", {"by": current_user.full_name}, namespace=NAMESPACE)
    return jsonify({"reset": True, "cleared": counts})
