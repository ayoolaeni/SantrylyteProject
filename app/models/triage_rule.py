from datetime import datetime, timezone

from app.extensions import db

# What a rule can do besides adding its weight to an event's score. Every key is optional;
# a rule with no actions just scores (the original behaviour).
#   create_incident    bool        open an incident for the matching event (grouped per attacker)
#   incident_priority  str | None  priority for that incident (defaults to the event's priority)
#   min_priority       str | None  raise the event's priority to at least this level
#   assign_to          int | None  user_id the resulting incident is assigned to
#   notify_user_ids    [int]       users who get a real-time notification
#   notify_roles       [str]       every active user with one of these roles is notified
#   suppress           bool        known-benign: auto-dismiss the event, no alert, no incident
RULE_ACTION_KEYS = (
    "create_incident", "incident_priority", "min_priority", "assign_to",
    "notify_user_ids", "notify_roles", "suppress",
)

RULE_CATEGORIES = (
    "AUTHENTICATION", "PRIVILEGE", "RECON", "WEB_ATTACK", "DEFENCE_EVASION",
    "DATA_ACCESS", "ACCOUNT", "MALWARE", "POLICY", "OTHER",
)


class TriageRule(db.Model):
    __tablename__ = "triage_rule"

    rule_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=True)
    condition = db.Column(db.JSON, nullable=False)
    actions = db.Column(db.JSON, nullable=True)
    weight = db.Column(db.Numeric(6, 2), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    mitre_technique = db.Column(db.String(20), nullable=True)
    is_enabled = db.Column(db.Boolean, nullable=False, default=True)
    created_by = db.Column(db.Integer, db.ForeignKey("user.user_id"), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    def to_dict(self):
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "description": self.description,
            "condition": self.condition,
            "actions": self.actions or {},
            "weight": float(self.weight),
            "category": self.category,
            "mitre_technique": self.mitre_technique,
            "is_enabled": self.is_enabled,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
