"""Seeds a couple of example critical assets. Run with `python -m seeds.seed_assets`."""
from app import create_app
from app.extensions import db
from app.models.critical_asset import CriticalAsset

ASSETS = [
    dict(identifier="10.0.0.10", label="Primary domain controller", criticality_multiplier=2.0),
    dict(identifier="10.0.0.0/24", label="Core server subnet", criticality_multiplier=1.5),
]


def run():
    app = create_app()
    with app.app_context():
        db.create_all()
        for spec in ASSETS:
            if not CriticalAsset.query.filter_by(identifier=spec["identifier"]).first():
                db.session.add(CriticalAsset(**spec))
        db.session.commit()
        print(f"Seeded {len(ASSETS)} example critical asset(s).")


if __name__ == "__main__":
    run()
