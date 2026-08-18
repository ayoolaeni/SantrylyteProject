from datetime import datetime, timezone

from app.extensions import db
from app.models.types import BigIntPK

# Application-level security audit log (NFR5.10) — distinct from incident_action,
# which audits incident workflow only. Covers login/logout/failed-login/config changes.


class AuditLog(db.Model):
    __tablename__ = "audit_log"

    audit_id = db.Column(BigIntPK, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.user_id"), nullable=True)
    event = db.Column(db.String(50), nullable=False)
    detail = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "audit_id": self.audit_id,
            "user_id": self.user_id,
            "event": self.event,
            "detail": self.detail,
            "ip_address": self.ip_address,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
