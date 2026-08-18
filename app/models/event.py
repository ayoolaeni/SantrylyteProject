from datetime import datetime, timezone

from app.extensions import db
from app.models.types import BigIntPK

EVENT_TYPES = (
    "AUTH_SUCCESS", "AUTH_FAILURE", "AUTH_LOGOUT", "PRIVILEGE_CHANGE",
    "ACCOUNT_CREATED", "ACCOUNT_LOCKED", "FILE_ACCESS", "PROCESS_EXEC",
    "NETWORK_CONNECTION", "FIREWALL_DENY", "WEB_REQUEST", "WEB_ERROR",
    "SERVICE_START", "SERVICE_STOP", "CONFIG_CHANGE", "MALWARE_ALERT",
    "SYSTEM_ERROR", "OTHER",
)

PRIORITY_LEVELS = ("INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL")

EVENT_STATUSES = ("NEW", "ACKNOWLEDGED", "ESCALATED", "DISMISSED")


class Event(db.Model):
    __tablename__ = "event"

    event_id = db.Column(BigIntPK, primary_key=True)
    source_id = db.Column(db.Integer, db.ForeignKey("log_source.source_id"), nullable=True)
    timestamp = db.Column(db.DateTime(timezone=True), nullable=False, index=True)
    received_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    event_type = db.Column(db.String(50), nullable=False, index=True)
    src_ip = db.Column(db.String(45), nullable=True, index=True)
    dest_ip = db.Column(db.String(45), nullable=True)
    dest_port = db.Column(db.Integer, nullable=True)
    username = db.Column(db.String(100), nullable=True, index=True)
    hostname = db.Column(db.String(255), nullable=True)
    protocol = db.Column(db.String(10), nullable=True)
    action = db.Column(db.String(30), nullable=True)
    http_method = db.Column(db.String(10), nullable=True)
    http_path = db.Column(db.Text, nullable=True)
    http_status = db.Column(db.Integer, nullable=True)
    bytes = db.Column(db.BigInteger, nullable=True)
    user_agent = db.Column(db.Text, nullable=True)
    message = db.Column(db.Text, nullable=True)
    raw_message = db.Column(db.Text, nullable=False)
    matched_rules = db.Column(db.JSON, nullable=True)
    modifiers_applied = db.Column(db.JSON, nullable=True)
    severity_score = db.Column(db.Numeric(6, 2), nullable=False, index=True)
    priority_level = db.Column(db.String(15), nullable=False, index=True)
    status = db.Column(db.String(20), nullable=False, default="NEW")

    source = db.relationship("LogSource")

    __table_args__ = (
        db.Index("ix_event_priority_ts", "priority_level", "timestamp"),
        db.Index("ix_event_srcip_ts", "src_ip", "timestamp"),
    )

    def to_summary(self):
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "event_type": self.event_type,
            "src_ip": self.src_ip,
            "priority_level": self.priority_level,
            "severity_score": float(self.severity_score) if self.severity_score is not None else None,
            "message": (self.message or "")[:200],
            "source_id": self.source_id,
            "status": self.status,
        }

    def to_dict(self):
        d = self.to_summary()
        d.update({
            "dest_ip": self.dest_ip,
            "dest_port": self.dest_port,
            "username": self.username,
            "hostname": self.hostname,
            "protocol": self.protocol,
            "action": self.action,
            "http_method": self.http_method,
            "http_path": self.http_path,
            "http_status": self.http_status,
            "bytes": self.bytes,
            "user_agent": self.user_agent,
            "raw_message": self.raw_message,
            "matched_rules": self.matched_rules or [],
            "modifiers_applied": self.modifiers_applied or [],
            "received_at": self.received_at.isoformat() if self.received_at else None,
            "source_name": self.source.name if self.source else None,
        })
        return d
