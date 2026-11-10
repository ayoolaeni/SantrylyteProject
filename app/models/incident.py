from datetime import datetime, timezone

from app.extensions import db
from app.utils.time import coerce_utc


def _iso_utc(dt):
    """ISO string that always carries its UTC offset (SQLite hands back naive datetimes)."""
    return coerce_utc(dt).isoformat() if dt else None


INCIDENT_STATES = (
    "NEW", "ACKNOWLEDGED", "INVESTIGATING", "ESCALATED",
    "RESOLVED", "FALSE_POSITIVE", "CLOSED",
)

TRANSITIONS = {
    "NEW": {"ACKNOWLEDGED"},
    "ACKNOWLEDGED": {"INVESTIGATING", "FALSE_POSITIVE"},
    "INVESTIGATING": {"ESCALATED", "RESOLVED", "FALSE_POSITIVE"},
    "ESCALATED": {"INVESTIGATING", "RESOLVED"},
    "RESOLVED": {"CLOSED", "INVESTIGATING"},
    "FALSE_POSITIVE": {"CLOSED"},
    "CLOSED": {"INVESTIGATING"},
}

# States reachable only by an ADMIN (reopen from CLOSED)
ADMIN_ONLY_TRANSITIONS = {("CLOSED", "INVESTIGATING")}

REQUIRES_RESOLUTION_SUMMARY = {"RESOLVED", "FALSE_POSITIVE"}


incident_event = db.Table(
    "incident_event",
    db.Column("incident_id", db.Integer, db.ForeignKey("incident.incident_id"), primary_key=True),
    db.Column("event_id", db.BigInteger, db.ForeignKey("event.event_id"), primary_key=True),
)


class Incident(db.Model):
    __tablename__ = "incident"

    incident_id = db.Column(db.Integer, primary_key=True)
    reference = db.Column(db.String(20), unique=True, nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    originating_event_id = db.Column(db.BigInteger, db.ForeignKey("event.event_id"), nullable=False)
    priority_level = db.Column(db.String(15), nullable=False)
    state = db.Column(db.String(20), nullable=False, default="NEW")
    assigned_to = db.Column(db.Integer, db.ForeignKey("user.user_id"), nullable=True)
    created_by = db.Column(db.Integer, db.ForeignKey("user.user_id"), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    acknowledged_at = db.Column(db.DateTime(timezone=True), nullable=True)
    resolved_at = db.Column(db.DateTime(timezone=True), nullable=True)
    closed_at = db.Column(db.DateTime(timezone=True), nullable=True)
    resolution_summary = db.Column(db.Text, nullable=True)
    # When the current assignee first opened the incident (cleared on reassignment), so the
    # admin who dispatched it can see whether it has actually been picked up.
    assignee_seen_at = db.Column(db.DateTime(timezone=True), nullable=True)

    originating_event = db.relationship("Event", foreign_keys=[originating_event_id])
    assignee = db.relationship("User", foreign_keys=[assigned_to])
    creator = db.relationship("User", foreign_keys=[created_by])
    linked_events = db.relationship("Event", secondary=incident_event, backref="linked_incidents")
    actions = db.relationship(
        "IncidentAction", backref="incident", order_by="IncidentAction.created_at", cascade="all, delete-orphan"
    )

    def can_transition_to(self, to_state):
        return to_state in TRANSITIONS.get(self.state, set())

    def participants(self):
        """Everyone who did something to this incident (not the triage engine), with what they did."""
        people = {}
        for action in self.actions:
            actor = action.actor
            if actor is None or actor.username == "system":
                continue
            entry = people.setdefault(actor.user_id, {
                "user_id": actor.user_id, "full_name": actor.full_name, "role": actor.role,
                "actions": {}, "last_action_at": None,
            })
            entry["actions"][action.action_type] = entry["actions"].get(action.action_type, 0) + 1
            created = _iso_utc(action.created_at)
            if created and (entry["last_action_at"] is None or created > entry["last_action_at"]):
                entry["last_action_at"] = created
        return sorted(people.values(), key=lambda p: p["last_action_at"] or "", reverse=True)

    def last_worked_by(self):
        """Who last moved the investigation forward (state change or note), for list views."""
        for action in reversed(self.actions):
            actor = action.actor
            if actor is None or actor.username == "system":
                continue
            if action.action_type in ("ASSIGNED", "UNASSIGNED", "VIEWED", "CREATED"):
                continue
            return {"full_name": actor.full_name, "at": _iso_utc(action.created_at)}
        return None

    def to_summary(self):
        return {
            "incident_id": self.incident_id,
            "reference": self.reference,
            "title": self.title,
            "priority_level": self.priority_level,
            "state": self.state,
            "assigned_to": self.assigned_to,
            "assignee_name": self.assignee.full_name if self.assignee else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "acknowledged_at": self.acknowledged_at.isoformat() if self.acknowledged_at else None,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "closed_at": self.closed_at.isoformat() if self.closed_at else None,
            "assignee_seen_at": _iso_utc(self.assignee_seen_at),
        }

    def to_list_item(self):
        """Summary plus who last worked on it (loads the actions, so only for list pages)."""
        d = self.to_summary()
        d["last_worked_by"] = self.last_worked_by()
        return d

    def to_dict(self):
        d = self.to_summary()
        d.update({
            "description": self.description,
            "originating_event_id": self.originating_event_id,
            "originating_event": self.originating_event.to_dict() if self.originating_event else None,
            "resolution_summary": self.resolution_summary,
            "created_by": self.created_by,
            "actions": [a.to_dict() for a in self.actions],
            "linked_events": [e.to_summary() for e in self.linked_events],
            "participants": self.participants(),
        })
        return d
