from datetime import datetime, timedelta, timezone

from flask import Blueprint, current_app, flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required, login_user, logout_user
from flask_wtf import FlaskForm
from wtforms import PasswordField, StringField
from wtforms.validators import DataRequired

from app.extensions import db
from app.models.user import User
from app.security import audit

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])


class ChangePasswordForm(FlaskForm):
    current_password = PasswordField("Current password", validators=[DataRequired()])
    new_password = PasswordField("New password", validators=[DataRequired()])
    confirm_password = PasswordField("Confirm new password", validators=[DataRequired()])


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))

    form = LoginForm()
    generic_error = "Invalid username or password."

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data.strip()).first()

        if user and user.is_locked():
            flash("Account temporarily locked due to repeated failed logins. Try again later.", "error")
            audit.record("LOGIN_LOCKED", user_id=user.user_id, detail=f"username={user.username}")
            return render_template("auth/login.html", form=form)

        if user and user.is_active_flag and user.check_password(form.password.data):
            user.failed_login_count = 0
            user.locked_until = None
            user.last_login_at = datetime.now(timezone.utc)
            db.session.commit()
            login_user(user)
            session.permanent = True
            session["absolute_start"] = datetime.now(timezone.utc).isoformat()
            audit.record("LOGIN_SUCCESS", user_id=user.user_id)

            if user.must_change_password:
                return redirect(url_for("auth.change_password"))
            next_url = request.args.get("next") or url_for("dashboard.index")
            return redirect(next_url)

        if user:
            user.failed_login_count = (user.failed_login_count or 0) + 1
            max_attempts = current_app.config["LOGIN_MAX_ATTEMPTS"]
            if user.failed_login_count >= max_attempts:
                lockout_minutes = current_app.config["LOGIN_LOCKOUT_MINUTES"]
                user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=lockout_minutes)
            db.session.commit()
            audit.record("LOGIN_FAILURE", user_id=user.user_id, detail=f"username={user.username}")

        flash(generic_error, "error")

    return render_template("auth/login.html", form=form)


@auth_bp.route("/logout", methods=["POST"])
@login_required
def logout():
    audit.record("LOGOUT", user_id=current_user.user_id)
    logout_user()
    session.clear()
    return redirect(url_for("auth.login"))


@auth_bp.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if not current_user.check_password(form.current_password.data):
            flash("Current password is incorrect.", "error")
        elif form.new_password.data != form.confirm_password.data:
            flash("New passwords do not match.", "error")
        elif len(form.new_password.data) < 8:
            flash("New password must be at least 8 characters.", "error")
        else:
            current_user.set_password(form.new_password.data)
            current_user.must_change_password = False
            db.session.commit()
            audit.record("PASSWORD_CHANGED", user_id=current_user.user_id)
            flash("Password updated.", "success")
            return redirect(url_for("dashboard.index"))
    return render_template("auth/change_password.html", form=form)
