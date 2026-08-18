from datetime import datetime, timezone

from app.extensions import db


class TriageRule(db.Model):
    __tablename__ = "triage_rule"

    rule_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=True)
    condition = db.Column(db.JSON, nullable=False)
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
            "weight": float(self.weight),
            "category": self.category,
            "mitre_technique": self.mitre_technique,
            "is_enabled": self.is_enabled,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
