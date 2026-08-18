from flask import Blueprint, render_template
from flask_login import login_required

incidents_bp = Blueprint("incidents", __name__)


@incidents_bp.route("/incidents")
@login_required
def index():
    return render_template("incidents_list.html")


@incidents_bp.route("/incidents/<reference>")
@login_required
def detail(reference):
    return render_template("incident_detail.html", reference=reference)
