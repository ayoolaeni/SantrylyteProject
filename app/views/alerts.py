from flask import Blueprint, render_template
from flask_login import login_required

alerts_bp = Blueprint("alerts", __name__)


@alerts_bp.route("/alerts")
@login_required
def index():
    return render_template("alerts.html")
