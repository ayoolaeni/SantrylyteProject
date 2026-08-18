from datetime import datetime, timezone

from app.extensions import db
from app.utils.time import coerce_utc

SOURCE_TYPES = (
    "SYSLOG",
    "AUTH_LOG",
    "NGINX_ACCESS",
    "APACHE_ACCESS",
    "JSON_GENERIC",
    "WINDOWS_JSON",
)


class LogSource(db.Model):
    __tablename__ = "log_source"

    source_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    host_identifier = db.Column(db.String(255), nullable=False)
    source_type = db.Column(db.String(40), nullable=False)
    ingest_token_hash = db.Column(db.String(128), unique=True, nullable=True)
    is_enabled = db.Column(db.Boolean, nullable=False, default=True)
    last_seen_at = db.Column(db.DateTime(timezone=True), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    def is_silent(self, silent_minutes):
        last_seen_at = coerce_utc(self.last_seen_at)
        if not last_seen_at:
            return False
        delta = datetime.now(timezone.utc) - last_seen_at
        return delta.total_seconds() > silent_minutes * 60

    def to_dict(self):
        return {
            "source_id": self.source_id,
            "name": self.name,
            "host_identifier": self.host_identifier,
            "source_type": self.source_type,
            "is_enabled": self.is_enabled,
            "last_seen_at": self.last_seen_at.isoformat() if self.last_seen_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "has_token": bool(self.ingest_token_hash),
        }
