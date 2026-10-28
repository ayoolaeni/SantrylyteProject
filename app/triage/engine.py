"""Triage engine (§6.1): scores a NormalisedEvent, assigns a priority, applies the
matched rules' actions, persists it, and opens (or groups into) an incident when the
priority is CRITICAL or a matched rule asks for one.
"""
import dataclasses
import secrets
import threading
from datetime import datetime, timedelta, timezone

from app.extensions import db
from app.models.event import PRIORITY_LEVELS, Event
from app.models.incident import Incident
from app.models.incident_action import IncidentAction
from app.triage import modifiers
from app.triage.conditions import evaluate, evaluate_base_condition
from app.triage.correlator import correlator
from app.triage.modifiers import _TTLCache

_OPEN_INCIDENT_STATES = ("NEW", "ACKNOWLEDGED", "INVESTIGATING", "ESCALATED")
# A repeat of the same attack (same title, i.e. same type + origin) while an incident for
# it is still open is linked to that incident instead of opening a new one.
INCIDENT_GROUPING_WINDOW = timedelta(hours=1)


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
    actions: dict = dataclasses.field(default_factory=dict)


def _load_enabled_rules():
    from app.models.triage_rule import TriageRule

    rows = TriageRule.query.filter_by(is_enabled=True).order_by(TriageRule.rule_id).all()
    return [_RuleView(r.rule_id, r.name, float(r.weight), r.condition, r.actions or {}) for r in rows]


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
    score, priority, matched, modifiers_applied, _ = _score(normalised, config, rules)
    return score, priority, matched, modifiers_applied


def _score(normalised, config, rules=None):
    """score_event plus the matched rule objects themselves (for their actions)."""
    event_dict = _event_to_dict(normalised)
    now = normalised.timestamp or datetime.now(timezone.utc)

    rules = rules if rules is not None else _rule_cache.get()
    score = 0.0
    matched = []
    matched_rules = []
    for rule in rules:
        if matches_rule(rule, event_dict, now):
            score += float(rule.weight)
            matched.append({"rule_id": rule.rule_id, "name": rule.name, "weight": float(rule.weight)})
            matched_rules.append(rule)

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
    return score, priority, matched, modifiers_applied, matched_rules


def _priority_rank(priority):
    return PRIORITY_LEVELS.index(priority) if priority in PRIORITY_LEVELS else 0


def max_priority(*priorities):
    candidates = [p for p in priorities if p in PRIORITY_LEVELS]
    return max(candidates, key=_priority_rank) if candidates else None


@dataclasses.dataclass
class RuleOutcome:
    """What the matched rules' actions add up to for one event."""

    min_priority: str = None
    create_incident: bool = False
    incident_priority: str = None
    assign_to: int = None
    notify_user_ids: set = dataclasses.field(default_factory=set)
    notify_roles: set = dataclasses.field(default_factory=set)
    suppressed_by: str = None
    explanations: list = dataclasses.field(default_factory=list)


def combine_rule_actions(matched_rules):
    outcome = RuleOutcome()
    for rule in matched_rules:
        actions = getattr(rule, "actions", None) or {}
        if not actions:
            continue
        if actions.get("suppress") and not outcome.suppressed_by:
            outcome.suppressed_by = rule.name
        if actions.get("min_priority") in PRIORITY_LEVELS:
            outcome.min_priority = max_priority(outcome.min_priority, actions["min_priority"])
        if actions.get("create_incident"):
            outcome.create_incident = True
            outcome.incident_priority = max_priority(outcome.incident_priority, actions.get("incident_priority"))
        if actions.get("assign_to") and outcome.assign_to is None:
            outcome.assign_to = int(actions["assign_to"])
        outcome.notify_user_ids.update(int(u) for u in actions.get("notify_user_ids") or [])
        outcome.notify_roles.update(actions.get("notify_roles") or [])
    return outcome


_reference_lock = threading.Lock()


def _next_incident_reference():
    """Hand out INC-<year>-NNNNNN references without collisions between worker threads.

    Counting committed rows isn't enough: two workers with uncommitted incidents in flight
    would both pick the same number and one batch would fail on the unique constraint. The
    last number issued is remembered per app (under a lock), and the database max is still
    consulted so references keep counting up across restarts.
    """
    from flask import current_app

    year = datetime.now(timezone.utc).year
    prefix = f"INC-{year}-"
    with _reference_lock:
        latest = (
            db.session.query(db.func.max(Incident.reference))
            .filter(Incident.reference.like(f"{prefix}%"))
            .scalar()
        )
        db_number = int(latest[len(prefix):]) if latest else 0
        issued = current_app.extensions.setdefault("sentrylite_incident_refs", {})
        number = max(db_number, issued.get(prefix, 0)) + 1
        issued[prefix] = number
    return f"{prefix}{number:06d}"


def _auto_incident_title(event):
    label = event.event_type.replace("_", " ").title()
    origin = event.src_ip or event.hostname or event.username or "unknown source"
    return f"{label} from {origin}"


def triage_and_persist(normalised, config, source_id=None):
    """Score, apply rule actions, persist the Event and open/group an Incident when called for.

    Returns (event, incident). `incident` is None when no incident is involved; when the
    event was grouped into an already-open incident, `incident.was_grouped` is True.
    `event.notifications` lists the real-time notifications to send once committed.
    """
    score, priority, matched, modifiers_applied, matched_rule_objs = _score(normalised, config)
    outcome = combine_rule_actions(matched_rule_objs)

    status = "NEW"
    if outcome.suppressed_by:
        status = "DISMISSED"
        modifiers_applied.append({"name": "suppressed", "effect": f"auto-dismissed by rule '{outcome.suppressed_by}'"})
    elif outcome.min_priority and _priority_rank(outcome.min_priority) > _priority_rank(priority):
        modifiers_applied.append({"name": "min_priority", "effect": f"raised {priority} -> {outcome.min_priority} by rule action"})
        priority = outcome.min_priority

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
        status=status,
    )
    db.session.add(event)
    db.session.flush()  # assign event_id
    event.notifications = []

    incident = None
    wants_incident = status != "DISMISSED" and (priority == "CRITICAL" or outcome.create_incident)
    if wants_incident:
        incident_priority = max_priority(priority, outcome.incident_priority) or priority
        incident = _open_or_group_incident(event, incident_priority, outcome, matched)

    _collect_rule_notifications(event, incident, outcome, matched)
    return event, incident


def _open_or_group_incident(event, incident_priority, outcome, matched):
    title = _auto_incident_title(event)
    since = datetime.now(timezone.utc) - INCIDENT_GROUPING_WINDOW
    existing = (
        Incident.query.filter(
            Incident.title == title,
            Incident.state.in_(_OPEN_INCIDENT_STATES),
            Incident.created_at >= since,
        )
        .order_by(Incident.created_at.desc())
        .first()
    )
    if existing is not None:
        existing.linked_events.append(event)
        if _priority_rank(incident_priority) > _priority_rank(existing.priority_level):
            existing.priority_level = incident_priority
        existing.was_grouped = True
        return existing

    reasons = ", ".join(r["name"] for r in matched) or "no rule"
    trigger = "CRITICAL severity" if event.priority_level == "CRITICAL" else "rule action"
    incident = Incident(
        reference=_next_incident_reference(),
        title=title,
        originating_event_id=event.event_id,
        priority_level=incident_priority,
        state="NEW",
        created_by=None,
    )
    db.session.add(incident)
    db.session.flush()
    incident.was_grouped = False
    system_id = _system_user_id()
    db.session.add(
        IncidentAction(
            incident_id=incident.incident_id,
            user_id=system_id,
            action_type="CREATED",
            to_value="NEW",
            comment=f"Auto-created by triage engine ({trigger}). Matched rules: {reasons}.",
        )
    )

    assignee = _active_user(outcome.assign_to)
    if assignee is not None:
        incident.assigned_to = assignee.user_id
        db.session.add(
            IncidentAction(
                incident_id=incident.incident_id,
                user_id=system_id,
                action_type="ASSIGNED",
                to_value=assignee.full_name[:100],
                comment="Auto-assigned by rule action.",
            )
        )
    return incident


def _active_user(user_id):
    if not user_id:
        return None
    from app.models.user import User

    user = db.session.get(User, int(user_id))
    if user is None or not user.is_active_flag or user.username == "system":
        return None
    return user


def _collect_rule_notifications(event, incident, outcome, matched):
    from app.models.user import User

    recipients = set(outcome.notify_user_ids)
    if outcome.notify_roles:
        rows = User.query.filter(
            User.role.in_(list(outcome.notify_roles)),
            User.is_active_flag.is_(True),
            User.username != "system",
        ).with_entities(User.user_id).all()
        recipients.update(uid for (uid,) in rows)

    if recipients:
        rule_names = ", ".join(r["name"] for r in matched)
        body = f"{event.event_type} from {event.src_ip or event.hostname or 'unknown'} matched: {rule_names}"
        link = f"/incidents/{incident.reference}" if incident is not None else f"/alerts#event-{event.event_id}"
        for uid in recipients:
            event.notifications.append(
                {"user_id": uid, "kind": "rule", "title": f"{event.priority_level} alert (rule notification)", "body": body, "link": link}
            )

    if incident is not None and not getattr(incident, "was_grouped", False) and incident.assigned_to:
        event.notifications.append(
            {
                "user_id": incident.assigned_to,
                "kind": "assigned",
                "title": f"Incident {incident.reference} assigned to you",
                "body": incident.title,
                "link": f"/incidents/{incident.reference}",
            }
        )


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
