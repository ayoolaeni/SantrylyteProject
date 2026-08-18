import csv
import io
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from flask import Response, jsonify, request

from app.api import api_bp
from app.api.helpers import parse_iso
from app.extensions import db
from app.models.event import Event
from app.models.incident import INCIDENT_STATES, Incident
from app.security.rbac import ApiError, role_required


def _default_range():
    now = datetime.now(timezone.utc)
    return now - timedelta(days=30), now


def _build_report(from_ts, to_ts):
    incidents = Incident.query.filter(Incident.created_at >= from_ts, Incident.created_at <= to_ts).all()
    events = Event.query.filter(Event.timestamp >= from_ts, Event.timestamp <= to_ts).all()

    by_priority = Counter(i.priority_level for i in incidents)
    by_state = Counter(i.state for i in incidents)

    ack_deltas = [
        (i.acknowledged_at - i.created_at).total_seconds() / 60
        for i in incidents
        if i.acknowledged_at is not None
    ]
    resolved_deltas = [
        (i.resolved_at - i.created_at).total_seconds() / 60
        for i in incidents
        if i.resolved_at is not None
    ]
    mtta = round(sum(ack_deltas) / len(ack_deltas), 1) if ack_deltas else None
    mttr = round(sum(resolved_deltas) / len(resolved_deltas), 1) if resolved_deltas else None

    rule_counts = Counter()
    for event in events:
        for rule in (event.matched_rules or []):
            rule_counts[rule.get("name", f"rule_{rule.get('rule_id')}")] += 1
    top_rules = rule_counts.most_common(10)

    ip_counts = Counter(e.src_ip for e in events if e.src_ip)
    top_ips = ip_counts.most_common(10)

    return {
        "range": {"from": from_ts.isoformat(), "to": to_ts.isoformat()},
        "totals_by_priority": {p: by_priority.get(p, 0) for p in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL")},
        "totals_by_state": {s: by_state.get(s, 0) for s in INCIDENT_STATES},
        "mtta_minutes": mtta,
        "mttr_minutes": mttr,
        "top_rules": [{"rule_name": name, "trigger_count": count} for name, count in top_rules],
        "top_source_ips": [{"src_ip": ip, "count": count} for ip, count in top_ips],
        "incidents": [
            {
                "reference": i.reference,
                "title": i.title,
                "priority_level": i.priority_level,
                "state": i.state,
                "assignee": i.assignee.full_name if i.assignee else None,
                "created_at": i.created_at.isoformat() if i.created_at else None,
                "closed_at": i.closed_at.isoformat() if i.closed_at else None,
            }
            for i in incidents
        ],
    }


def _csv_response(report):
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["SentryLite incident report", report["range"]["from"], report["range"]["to"]])
    writer.writerow([])
    writer.writerow(["MTTA (minutes)", report["mtta_minutes"]])
    writer.writerow(["MTTR (minutes)", report["mttr_minutes"]])
    writer.writerow([])
    writer.writerow(["Priority", "Count"])
    for k, v in report["totals_by_priority"].items():
        writer.writerow([k, v])
    writer.writerow([])
    writer.writerow(["State", "Count"])
    for k, v in report["totals_by_state"].items():
        writer.writerow([k, v])
    writer.writerow([])
    writer.writerow(["Top rules", "Trigger count"])
    for row in report["top_rules"]:
        writer.writerow([row["rule_name"], row["trigger_count"]])
    writer.writerow([])
    writer.writerow(["Top source IPs", "Count"])
    for row in report["top_source_ips"]:
        writer.writerow([row["src_ip"], row["count"]])
    writer.writerow([])
    writer.writerow(["Reference", "Title", "Priority", "State", "Assignee", "Created", "Closed"])
    for inc in report["incidents"]:
        writer.writerow(
            [inc["reference"], inc["title"], inc["priority_level"], inc["state"], inc["assignee"], inc["created_at"], inc["closed_at"]]
        )

    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=sentrylite_incident_report.csv"},
    )


def _pdf_response(report):
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4)
    styles = getSampleStyleSheet()
    story = [
        Paragraph("SentryLite Incident Report", styles["Title"]),
        Paragraph(f"{report['range']['from']} &ndash; {report['range']['to']}", styles["Normal"]),
        Spacer(1, 12),
        Paragraph(f"MTTA: {report['mtta_minutes']} min &nbsp;&nbsp; MTTR: {report['mttr_minutes']} min", styles["Normal"]),
        Spacer(1, 12),
    ]

    def _table(title, rows, header):
        story.append(Paragraph(title, styles["Heading2"]))
        data = [header] + rows
        t = Table(data, hAlign="LEFT")
        t.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#171d26")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                ]
            )
        )
        story.append(t)
        story.append(Spacer(1, 12))

    _table("Totals by priority", [[k, v] for k, v in report["totals_by_priority"].items()], ["Priority", "Count"])
    _table("Totals by state", [[k, v] for k, v in report["totals_by_state"].items()], ["State", "Count"])
    _table("Top 10 rules", [[r["rule_name"], r["trigger_count"]] for r in report["top_rules"]], ["Rule", "Triggers"])
    _table("Top 10 source IPs", [[r["src_ip"], r["count"]] for r in report["top_source_ips"]], ["Source IP", "Count"])
    _table(
        "Incidents",
        [[i["reference"], i["title"][:40], i["priority_level"], i["state"], i["assignee"] or "-"] for i in report["incidents"]],
        ["Reference", "Title", "Priority", "State", "Assignee"],
    )

    doc.build(story)
    buf.seek(0)
    return Response(
        buf.read(),
        mimetype="application/pdf",
        headers={"Content-Disposition": "attachment; filename=sentrylite_incident_report.pdf"},
    )


@api_bp.route("/reports/incidents", methods=["GET"])
@role_required()
def incident_report():
    default_from, default_to = _default_range()
    from_ts = parse_iso(request.args.get("from")) or default_from
    to_ts = parse_iso(request.args.get("to")) or default_to
    fmt = request.args.get("format", "json")

    report = _build_report(from_ts, to_ts)

    if fmt == "json":
        return jsonify(report)
    if fmt == "csv":
        return _csv_response(report)
    if fmt == "pdf":
        return _pdf_response(report)
    raise ApiError("INVALID_PARAM", "format must be json, csv or pdf", 400)
