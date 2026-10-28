from flask import current_app, jsonify
from flask_login import current_user

from app.api import api_bp
from app.api.helpers import json_body
from app.security.audit import record as audit_record
from app.security.rbac import ApiError, role_required
from app import simulator

MAX_BACKGROUND_MINUTES = 60


@api_bp.route("/simulate/scenarios", methods=["GET"])
@role_required("ADMIN", "ANALYST")
def simulator_scenarios():
    return jsonify({"scenarios": simulator.scenario_list(), "background": simulator.background_status()})


@api_bp.route("/simulate", methods=["POST"])
@role_required("ADMIN", "ANALYST")
def simulate():
    body = json_body()
    scenario = body.get("scenario")
    if scenario not in simulator.SCENARIOS:
        raise ApiError("VALIDATION_ERROR", f"scenario must be one of {sorted(simulator.SCENARIOS)}", 422)

    attacker_ip, lines, seconds = simulator.run_scenario(current_app._get_current_object(), scenario)
    audit_record("SIMULATION_RUN", user_id=current_user.user_id, detail=f"scenario={scenario} attacker={attacker_ip}")
    return jsonify(
        {
            "scenario": scenario,
            "name": simulator.SCENARIOS[scenario]["name"],
            "attacker_ip": attacker_ip,
            "lines": lines,
            "duration_seconds": seconds,
            "expect": simulator.SCENARIOS[scenario]["expect"],
        }
    ), 202


@api_bp.route("/simulate/background", methods=["GET"])
@role_required("ADMIN", "ANALYST")
def simulator_background_status():
    return jsonify(simulator.background_status())


@api_bp.route("/simulate/background", methods=["POST"])
@role_required("ADMIN", "ANALYST")
def simulator_background():
    body = json_body()
    action = body.get("action")
    if action == "stop":
        simulator.stop_background()
        audit_record("SIMULATION_BACKGROUND_STOP", user_id=current_user.user_id)
        return jsonify(simulator.background_status())
    if action != "start":
        raise ApiError("VALIDATION_ERROR", "action must be 'start' or 'stop'", 422)
    try:
        minutes = int(body.get("minutes", 10))
    except (TypeError, ValueError):
        raise ApiError("VALIDATION_ERROR", "minutes must be a whole number", 422)
    if not 1 <= minutes <= MAX_BACKGROUND_MINUTES:
        raise ApiError("VALIDATION_ERROR", f"minutes must be between 1 and {MAX_BACKGROUND_MINUTES}", 422)
    simulator.start_background(current_app._get_current_object(), minutes, current_user.full_name)
    audit_record("SIMULATION_BACKGROUND_START", user_id=current_user.user_id, detail=f"minutes={minutes}")
    return jsonify(simulator.background_status())
