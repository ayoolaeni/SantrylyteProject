"""Triage engine (§6.1): scores a NormalisedEvent, assigns a priority, persists it,
and auto-creates an incident when the priority is CRITICAL.
"""
import dataclasses
import secrets
from datetime import datetime, timezone

from app.extensions import db
from app.models.event import Event
from app.models.incident import Incident
from app.models.incident_action import IncidentAction
from app.triage import modifiers
from app.triage.conditions import evaluate, evaluate_base_condition
from app.triage.correlator import correlator
from app.triage.modifiers import _TTLCache


@dataclasses.dataclass
class _RuleView:
    """A detached, plain-data snapshot of a TriageRule row.

    The rule cache is a module-level singleton that outlives any single request, while
    Flask-SQLAlchemy tears down (removes) its scoped session at the end of every request.
    Caching live ORM instances meant any cache hit from a *later* request touched a
    detached instance and raised DetachedInstanceError the moment a lazy attribute (e.g.
    .condition) was read. Caching plain data sidesteps the session lifecycle entirely.
    """

    rule_id: int
    name: str
    weight: float
    condition: dict


def _load_enabled_rules():
    from app.models.triage_rule import TriageRule

    rows = TriageRule.query.filter_by(is_enabled=True).order_by(TriageRule.rule_id).all()
    return [_RuleView(r.rule_id, r.name, float(r.weight), r.condition) for r in rows]


_rule_cache = _TTLCache(_load_enabled_rules, ttl_seconds=30)


def invalidate_rule_cache():
    _rule_cache.invalidate()


def _event_to_dict(normalised):
    d = dataclasses.asdict(normalised)
    d.pop("timestamp", None)
    d["timestamp"] = normalised.timestamp
    return d


def _correlation_matches(rule, condition, event_dict, base_matches, now):
    corr = condition.get("correlation") if condition else None
    if not corr:
        return base_matches

    ctype = corr.get("type")
    group_field = corr.get("group_by")
    window = corr.get("window_seconds", 120)
    group_value = event_dict.get(group_field)
    if group_value is None:
        return False

    if ctype == "threshold":
        if not base_matches:
            return False
        key = ("rule", rule.rule_id, group_value)
        correlator.record(key, now, window_seconds=window)
        return correlator.count_since(key, now, window) > corr.get("count", 1)

    if ctype == "distinct_count":
        if not base_matches:
            return False
        distinct_field = corr.get("distinct_field")
        key = ("rule", rule.rule_id, group_value)
        correlator.record(key, now, event_dict.get(distinct_field), window_seconds=window)
        return correlator.distinct_count_since(key, now, window) > corr.get("count", 1)

    if ctype == "sequence":
        first_cond = corr.get("first")
        first_key = ("rule_seq", rule.rule_id, group_value)
        if first_cond and evaluate(first_cond, event_dict):
            correlator.record(first_key, now, window_seconds=window)
        if not base_matches:
            return False
        return correlator.count_since(first_key, now, window) >= corr.get("min_count", 1)

    return base_matches


def matches_rule(rule, event_dict, now):
    condition = rule.condition or {}
    base_matches = evaluate_base_condition(condition, event_dict)
    if "correlation" in condition:
        return _correlation_matches(rule, condition, event_dict, base_matches, now)
    return base_matches


def priority_for_score(score, config):
    if score >= config["THRESHOLD_CRITICAL"]:
        return "CRITICAL"
    if score >= config["THRESHOLD_HIGH"]:
        return "HIGH"
    if score >= config["THRESHOLD_MEDIUM"]:
        return "MEDIUM"
    if score >= config["THRESHOLD_LOW"]:
        return "LOW"
    return "INFORMATIONAL"


def score_event(normalised, config, rules=None):
    """Pure scoring: returns (score, priority, matched_rules, modifiers_applied). No DB writes."""
    event_dict = _event_to_dict(normalised)
    now = normalised.timestamp or datetime.now(timezone.utc)

    rules = rules if rules is not None else _rule_cache.get()
    score = 0.0
    matched = []
    for rule in rules:
        if matches_rule(rule, event_dict, now):
            score += float(rule.weight)
            matched.append({"rule_id": rule.rule_id, "name": rule.name, "weight": float(rule.weight)})

    modifiers_applied = []
    asset = modifiers.match_critical_asset(normalised.dest_ip, normalised.hostname)
    if asset:
        score *= float(asset.criticality_multiplier)
        modifiers_applied.append({"name": "critical_asset", "effect": f"x{asset.criticality_multiplier}", "asset": asset.label})

    if modifiers.is_outside_working_hours(now, config):
        score += config["OFF_HOURS_BONUS"]
        modifiers_applied.append({"name": "off_hours", "effect": f"+{config['OFF_HOURS_BONUS']}"})

    rc = modifiers.repeat_count(normalised.src_ip, now, config["REPEAT_WINDOW_SECONDS"])
    if rc > config["REPEAT_LIMIT"]:
        score += config["REPEAT_BONUS"]
        modifiers_applied.append({"name": "repeat_source", "effect": f"+{config['REPEAT_BONUS']}", "count": rc})

    score = max(0.0, min(score, config["SCORE_CEILING"]))
    priority = priority_for_score(score, config)
    return score, priority, matched, modifiers_applied


def _next_incident_reference():
    year = datetime.now(timezone.utc).year
    prefix = f"INC-{year}-"
    count = Incident.query.filter(Incident.reference.like(f"{prefix}%")).count()
    return f"{prefix}{count + 1:06d}"


def _auto_incident_title(event):
    label = event.event_type.replace("_", " ").title()
    origin = event.src_ip or event.hostname or event.username or "unknown source"
    return f"{label} from {origin}"


def triage_and_persist(normalised, config, source_id=None):
    """Score, persist the Event and (if CRITICAL) auto-create an Incident. Returns (event, incident)."""
    score, priority, matched, modifiers_applied = score_event(normalised, config)

    event = Event(
        source_id=source_id,
        timestamp=normalised.timestamp,
        received_at=normalised.received_at,
        event_type=normalised.event_type,
        src_ip=normalised.src_ip,
        dest_ip=normalised.dest_ip,
        dest_port=normalised.dest_port,
        username=normalised.username,
        hostname=normalised.hostname,
        protocol=normalised.protocol,
        action=normalised.action,
        http_method=normalised.http_method,
        http_path=normalised.http_path,
        http_status=normalised.http_status,
        bytes=normalised.bytes,
        user_agent=normalised.user_agent,
        message=normalised.message,
        raw_message=normalised.raw_message,
        matched_rules=matched,
        modifiers_applied=modifiers_applied,
        severity_score=round(score, 2),
        priority_level=priority,
        status="NEW",
    )
    db.session.add(event)
    db.session.flush()  # assign event_id

    incident = None
    if priority == "CRITICAL":
        incident = Incident(
            reference=_next_incident_reference(),
            title=_auto_incident_title(event),
            originating_event_id=event.event_id,
            priority_level=priority,
            state="NEW",
            created_by=None,
        )
        db.session.add(incident)
        db.session.flush()
        db.session.add(
            IncidentAction(
                incident_id=incident.incident_id,
                user_id=_system_user_id(),
                action_type="CREATED",
                to_value="NEW",
                comment="Auto-created by triage engine (CRITICAL severity).",
            )
        )

    return event, incident


_SYSTEM_USER_ID_CACHE = {"id": None}


def _system_user_id():
    """IncidentAction.user_id is NOT NULL; auto-created actions attribute to a system service account."""
    if _SYSTEM_USER_ID_CACHE["id"] is not None:
        return _SYSTEM_USER_ID_CACHE["id"]
    from app.models.user import User

    system_user = User.query.filter_by(username="system").first()
    if system_user is None:
        system_user = User(
            username="system",
            email="system@sentrylite.local",
            full_name="SentryLite Triage Engine",
            role="ADMIN",
            is_active_flag=False,
        )
        system_user.set_password(secrets.token_urlsafe(32))
        db.session.add(system_user)
        db.session.flush()
    _SYSTEM_USER_ID_CACHE["id"] = system_user.user_id
    return system_user.user_id
