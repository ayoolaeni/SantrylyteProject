from datetime import datetime, timezone

from app.extensions import db
from app.models.types import BigIntPK

ACTION_TYPES = (
    "CREATED", "ACKNOWLEDGED", "ASSIGNED", "COMMENTED", "ESCALATED",
    "STATE_CHANGED", "EVENT_LINKED", "RESOLVED", "CLOSED", "REOPENED",
)


class IncidentAction(db.Model):
    """Append-only audit trail for an incident. No update or delete route exists for this table."""

    __tablename__ = "incident_action"

    action_id = db.Column(BigIntPK, primary_key=True)
    incident_id = db.Column(db.Integer, db.ForeignKey("incident.incident_id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.user_id"), nullable=False)
    action_type = db.Column(db.String(30), nullable=False)
    from_value = db.Column(db.String(100), nullable=True)
    to_value = db.Column(db.String(100), nullable=True)
    comment = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    actor = db.relationship("User")

    def to_dict(self):
        return {
            "action_id": self.action_id,
            "incident_id": self.incident_id,
            "user_id": self.user_id,
            "actor_name": self.actor.full_name if self.actor else None,
            "action_type": self.action_type,
            "from_value": self.from_value,
            "to_value": self.to_value,
            "comment": self.comment,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
