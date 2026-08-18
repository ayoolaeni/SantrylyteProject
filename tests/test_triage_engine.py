from datetime import datetime, timezone

import pytest

from app.parsers.base import NormalisedEvent
from app.triage.conditions import ConditionError, evaluate, evaluate_base_condition
from app.triage.engine import priority_for_score, score_event
from app.models.triage_rule import TriageRule
from app.models.critical_asset import CriticalAsset


# ---------- Condition DSL operators ----------

EVENT = {
    "event_type": "AUTH_FAILURE",
    "src_ip": "203.0.113.5",
    "http_status": 403,
    "http_path": "/login?next=../../etc/passwd",
    "username": None,
    "dest_port": 22,
}


@pytest.mark.parametrize(
    "node,expected",
    [
        ({"field": "event_type", "op": "eq", "value": "AUTH_FAILURE"}, True),
        ({"field": "event_type", "op": "neq", "value": "AUTH_FAILURE"}, False),
        ({"field": "http_status", "op": "gt", "value": 400}, True),
        ({"field": "http_status", "op": "gte", "value": 403}, True),
        ({"field": "http_status", "op": "lt", "value": 400}, False),
        ({"field": "http_status", "op": "lte", "value": 403}, True),
        ({"field": "event_type", "op": "in", "value": ["AUTH_FAILURE", "AUTH_SUCCESS"]}, True),
        ({"field": "event_type", "op": "not_in", "value": ["AUTH_SUCCESS"]}, True),
        ({"field": "http_path", "op": "contains", "value": "etc/passwd"}, True),
        ({"field": "http_path", "op": "not_contains", "value": "nope"}, True),
        ({"field": "http_path", "op": "startswith", "value": "/login"}, True),
        ({"field": "http_path", "op": "endswith", "value": "passwd"}, True),
        ({"field": "http_path", "op": "regex", "value": r"\.\./"}, True),
        ({"field": "src_ip", "op": "in_cidr", "value": "203.0.113.0/24"}, True),
        ({"field": "src_ip", "op": "not_in_cidr", "value": "10.0.0.0/8"}, True),
        ({"field": "dest_port", "op": "exists", "value": True}, True),
        ({"field": "username", "op": "is_null", "value": True}, True),
    ],
)
def test_operators(node, expected):
    assert evaluate(node, EVENT) is expected


def test_all_combinator_is_and():
    node = {"all": [{"field": "event_type", "op": "eq", "value": "AUTH_FAILURE"}, {"field": "http_status", "op": "gte", "value": 500}]}
    assert evaluate(node, EVENT) is False


def test_any_combinator_is_or():
    node = {"any": [{"field": "event_type", "op": "eq", "value": "NOPE"}, {"field": "http_status", "op": "eq", "value": 403}]}
    assert evaluate(node, EVENT) is True


def test_none_combinator_is_nor():
    node = {"none": [{"field": "event_type", "op": "eq", "value": "NOPE"}]}
    assert evaluate(node, EVENT) is True


def test_unknown_operator_raises():
    with pytest.raises(ConditionError):
        evaluate({"field": "event_type", "op": "bogus_op", "value": "x"}, EVENT)


def test_catastrophic_regex_rejected():
    with pytest.raises(ConditionError):
        evaluate({"field": "http_path", "op": "regex", "value": "(a+)+$"}, EVENT)


def test_evaluate_base_condition_ignores_correlation_key():
    condition = {
        "all": [{"field": "event_type", "op": "eq", "value": "AUTH_FAILURE"}],
        "correlation": {"type": "threshold", "group_by": "src_ip", "count": 5, "window_seconds": 120},
    }
    assert evaluate_base_condition(condition, EVENT) is True


# ---------- Scoring table ----------

def _event(event_type="OTHER", **overrides):
    defaults = dict(
        timestamp=datetime(2024, 6, 4, 12, 0, 0, tzinfo=timezone.utc),  # a Tuesday, inside working hours
        event_type=event_type,
        raw_message="raw",
    )
    defaults.update(overrides)
    return NormalisedEvent(**defaults)


def _config(app):
    return app.config


def test_no_matching_rules_gives_informational(app):
    with app.app_context():
        event = _event(event_type="SYSTEM_ERROR")
        score, priority, matched, mods = score_event(event, _config(app), rules=[])
        assert score == 0
        assert priority == "INFORMATIONAL"
        assert matched == []


def test_single_rule_match_sums_weight(app, db):
    with app.app_context():
        rule = TriageRule(
            name="r1", condition={"all": [{"field": "event_type", "op": "eq", "value": "AUTH_FAILURE"}]},
            weight=40, category="AUTHENTICATION",
        )
        db.session.add(rule)
        db.session.commit()

        event = _event(event_type="AUTH_FAILURE")
        score, priority, matched, mods = score_event(event, _config(app), rules=[rule])
        assert score == 40
        assert priority == "MEDIUM"
        assert len(matched) == 1


def test_off_hours_modifier_adds_bonus(app):
    with app.app_context():
        off_hours_ts = datetime(2024, 6, 4, 23, 0, 0, tzinfo=timezone.utc)  # 23:00, outside 08:00-18:00
        event = _event(event_type="OTHER", timestamp=off_hours_ts)
        score, priority, matched, mods = score_event(event, _config(app), rules=[])
        assert score == _config(app)["OFF_HOURS_BONUS"]
        assert any(m["name"] == "off_hours" for m in mods)


def test_critical_asset_modifier_multiplies_score(app, db):
    with app.app_context():
        asset = CriticalAsset(identifier="10.0.0.10", label="DC", criticality_multiplier=2.0)
        db.session.add(asset)
        rule = TriageRule(
            name="r1", condition={"all": [{"field": "event_type", "op": "eq", "value": "AUTH_FAILURE"}]},
            weight=30, category="AUTHENTICATION",
        )
        db.session.add(rule)
        db.session.commit()

        event = _event(event_type="AUTH_FAILURE", dest_ip="10.0.0.10")
        score, priority, matched, mods = score_event(event, _config(app), rules=[rule])
        assert score == 60  # 30 * 2.0
        assert any(m["name"] == "critical_asset" for m in mods)


def test_score_is_clamped_to_ceiling(app, db):
    with app.app_context():
        rule = TriageRule(
            name="huge", condition={"all": [{"field": "event_type", "op": "eq", "value": "MALWARE_ALERT"}]},
            weight=500, category="MALWARE",
        )
        db.session.add(rule)
        db.session.commit()
        event = _event(event_type="MALWARE_ALERT")
        score, priority, matched, mods = score_event(event, _config(app), rules=[rule])
        assert score == _config(app)["SCORE_CEILING"]
        assert priority == "CRITICAL"


@pytest.mark.parametrize(
    "score,expected",
    [(0, "INFORMATIONAL"), (14.9, "INFORMATIONAL"), (15, "LOW"), (39.9, "LOW"), (40, "MEDIUM"),
     (64.9, "MEDIUM"), (65, "HIGH"), (89.9, "HIGH"), (90, "CRITICAL"), (200, "CRITICAL")],
)
def test_priority_thresholds(app, score, expected):
    with app.app_context():
        assert priority_for_score(score, app.config) == expected


def test_repeated_failed_login_correlation_threshold(app, db):
    """Rule 1 semantics: >5 AUTH_FAILURE from one src_ip within 120s should only fire on the 6th."""
    with app.app_context():
        rule = TriageRule(
            name="Repeated failed login",
            condition={
                "all": [{"field": "event_type", "op": "eq", "value": "AUTH_FAILURE"}],
                "correlation": {"type": "threshold", "group_by": "src_ip", "count": 5, "window_seconds": 120},
            },
            weight=40,
            category="AUTHENTICATION",
        )
        db.session.add(rule)
        db.session.commit()

        base_ts = datetime(2024, 6, 4, 12, 0, 0, tzinfo=timezone.utc)
        matched_flags = []
        for i in range(6):
            event = _event(event_type="AUTH_FAILURE", src_ip="203.0.113.5", timestamp=base_ts)
            _, _, matched, _ = score_event(event, _config(app), rules=[rule])
            matched_flags.append(bool(matched))

        assert matched_flags == [False, False, False, False, False, True]
