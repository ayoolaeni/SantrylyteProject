"""Loads the 12 default triage rules (§6.3). Run with `python -m seeds.seed_rules`."""
from app import create_app
from app.extensions import db
from app.models.triage_rule import TriageRule

RULES = [
    dict(
        name="Repeated failed login",
        category="AUTHENTICATION",
        mitre_technique="T1110",
        weight=40,
        description="More than 5 AUTH_FAILURE events from one src_ip within 120 seconds.",
        condition={
            "all": [{"field": "event_type", "op": "eq", "value": "AUTH_FAILURE"}],
            "correlation": {"type": "threshold", "group_by": "src_ip", "count": 5, "window_seconds": 120},
        },
    ),
    dict(
        name="Successful login after failures",
        category="AUTHENTICATION",
        mitre_technique="T1078",
        weight=70,
        description="AUTH_SUCCESS within 120 seconds of >=5 AUTH_FAILURE from the same src_ip.",
        condition={
            "all": [{"field": "event_type", "op": "eq", "value": "AUTH_SUCCESS"}],
            "correlation": {
                "type": "sequence",
                "group_by": "src_ip",
                "first": {"field": "event_type", "op": "eq", "value": "AUTH_FAILURE"},
                "min_count": 5,
                "window_seconds": 120,
            },
        },
    ),
    dict(
        name="Privilege escalation",
        category="PRIVILEGE",
        mitre_technique="T1548",
        weight=60,
        description="PRIVILEGE_CHANGE event where the target group is administrative.",
        condition={"all": [{"field": "event_type", "op": "eq", "value": "PRIVILEGE_CHANGE"}]},
    ),
    dict(
        name="Port scan pattern",
        category="RECON",
        mitre_technique="T1046",
        weight=35,
        description="More than 15 distinct dest_port values from one src_ip within 60 seconds.",
        condition={
            "all": [{"field": "dest_port", "op": "exists", "value": True}],
            "correlation": {
                "type": "distinct_count",
                "group_by": "src_ip",
                "distinct_field": "dest_port",
                "count": 15,
                "window_seconds": 60,
            },
        },
    ),
    dict(
        name="Directory traversal",
        category="WEB_ATTACK",
        mitre_technique="T1190",
        weight=50,
        description="http_path contains a directory traversal sequence.",
        condition={"all": [{"field": "http_path", "op": "regex", "value": r"(\.\./|%2e%2e|\.\.\\)"}]},
    ),
    dict(
        name="Malformed / oversized request",
        category="WEB_ATTACK",
        mitre_technique=None,
        weight=20,
        description="Raw request line longer than 4096 characters.",
        condition={"all": [{"field": "raw_message", "op": "regex", "value": r"^.{4097,}"}]},
    ),
    dict(
        name="Log service stopped",
        category="DEFENCE_EVASION",
        mitre_technique="T1562",
        weight=65,
        description="SERVICE_STOP event where the service is a logging service.",
        condition={
            "all": [
                {"field": "event_type", "op": "eq", "value": "SERVICE_STOP"},
                {"field": "message", "op": "regex", "value": "(?i)(rsyslog|syslog|auditd|journald|eventlog|logging)"},
            ]
        },
    ),
    dict(
        name="Sensitive file access",
        category="DATA_ACCESS",
        mitre_technique="T1005",
        weight=45,
        description="FILE_ACCESS event referencing a protected path.",
        condition={
            "all": [
                {"field": "event_type", "op": "eq", "value": "FILE_ACCESS"},
                {"field": "message", "op": "regex", "value": r"(?i)(/etc/shadow|/etc/passwd|\.ssh/|web\.config|\.env)"},
            ]
        },
    ),
    dict(
        name="SQL injection attempt",
        category="WEB_ATTACK",
        mitre_technique="T1190",
        weight=55,
        description="http_path or query matches a common SQL injection pattern.",
        condition={"all": [{"field": "http_path", "op": "regex", "value": r"(?i)(union\s+select|' or '1'='1|sleep\()"}]},
    ),
    dict(
        name="Root / admin login from external IP",
        category="AUTHENTICATION",
        mitre_technique="T1078",
        weight=60,
        description="AUTH_SUCCESS as root/admin/administrator from outside the internal networks.",
        condition={
            "all": [
                {"field": "event_type", "op": "eq", "value": "AUTH_SUCCESS"},
                {"field": "username", "op": "in", "value": ["root", "admin", "administrator"]},
                {
                    "field": "src_ip",
                    "op": "not_in_cidr",
                    "value": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
                },
            ]
        },
    ),
    dict(
        name="Account created outside change window",
        category="ACCOUNT",
        mitre_technique="T1136",
        weight=45,
        description="ACCOUNT_CREATED event (combines with the off-hours scoring modifier).",
        condition={"all": [{"field": "event_type", "op": "eq", "value": "ACCOUNT_CREATED"}]},
    ),
    dict(
        name="Web brute force",
        category="WEB_ATTACK",
        mitre_technique="T1110",
        weight=35,
        description="More than 20 responses with http_status 401/403 from one src_ip within 60 seconds.",
        condition={
            "all": [{"field": "http_status", "op": "in", "value": [401, 403]}],
            "correlation": {"type": "threshold", "group_by": "src_ip", "count": 20, "window_seconds": 60},
        },
    ),
]


def run():
    app = create_app()
    with app.app_context():
        db.create_all()
        for spec in RULES:
            existing = TriageRule.query.filter_by(name=spec["name"]).first()
            if existing:
                continue
            db.session.add(TriageRule(**spec))
        db.session.commit()
        print(f"Seeded {len(RULES)} default triage rules (skipping any that already exist).")


if __name__ == "__main__":
    run()
