from datetime import datetime, timezone

from app.extensions import db

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

    originating_event = db.relationship("Event", foreign_keys=[originating_event_id])
    assignee = db.relationship("User", foreign_keys=[assigned_to])
    creator = db.relationship("User", foreign_keys=[created_by])
    linked_events = db.relationship("Event", secondary=incident_event, backref="linked_incidents")
    actions = db.relationship(
        "IncidentAction", backref="incident", order_by="IncidentAction.created_at", cascade="all, delete-orphan"
    )

    def can_transition_to(self, to_state):
        return to_state in TRANSITIONS.get(self.state, set())

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
        }

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
        })
        return d
