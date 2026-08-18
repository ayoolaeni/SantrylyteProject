"""Creates the initial admin (and a demo analyst) account. Run with `python -m seeds.seed_users`."""
from app import create_app
from app.extensions import db
from app.models.user import User


def run():
    app = create_app()
    with app.app_context():
        db.create_all()

        if not User.query.filter_by(username="admin").first():
            admin = User(
                username="admin",
                email="admin@sentrylite.local",
                full_name="Administrator",
                role="ADMIN",
                must_change_password=True,
            )
            admin.set_password("admin")
            db.session.add(admin)

        if not User.query.filter_by(username="analyst").first():
            analyst = User(
                username="analyst",
                email="analyst@sentrylite.local",
                full_name="Demo Analyst",
                role="ANALYST",
                must_change_password=True,
            )
            analyst.set_password("analyst123")
            db.session.add(analyst)

        db.session.commit()
        print("Seeded users: admin/admin and analyst/analyst123 (both must change password on first login)")


if __name__ == "__main__":
    run()
