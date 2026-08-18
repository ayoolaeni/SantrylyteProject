from flask import Blueprint, render_template

from app.security.rbac import role_required

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


@admin_bp.route("/sources")
@role_required("ADMIN")
def sources():
    return render_template("admin/sources.html")


@admin_bp.route("/rules")
@role_required("ADMIN")
def rules():
    return render_template("admin/rules.html")


@admin_bp.route("/users")
@role_required("ADMIN")
def users():
    return render_template("admin/users.html")


@admin_bp.route("/assets")
@role_required("ADMIN")
def assets():
    return render_template("admin/assets.html")
