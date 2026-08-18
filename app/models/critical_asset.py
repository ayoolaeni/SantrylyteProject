from app.extensions import db


class CriticalAsset(db.Model):
    __tablename__ = "critical_asset"

    asset_id = db.Column(db.Integer, primary_key=True)
    identifier = db.Column(db.String(255), unique=True, nullable=False)  # IP, CIDR or hostname
    label = db.Column(db.String(100), nullable=False)
    criticality_multiplier = db.Column(db.Numeric(3, 2), nullable=False, default=1.50)
    is_enabled = db.Column(db.Boolean, nullable=False, default=True)

    def to_dict(self):
        return {
            "asset_id": self.asset_id,
            "identifier": self.identifier,
            "label": self.label,
            "criticality_multiplier": float(self.criticality_multiplier),
            "is_enabled": self.is_enabled,
        }
