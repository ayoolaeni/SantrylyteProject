import csv
import io
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from flask import Response, jsonify, request
from flask_login import current_user

from app.api import api_bp
from app.api.helpers import parse_iso
from app.extensions import db
from app.models.event import PRIORITY_LEVELS, Event
from app.models.incident import INCIDENT_STATES, Incident
from app.security.rbac import ApiError, role_required

_PRIORITIES_DESC = tuple(reversed(PRIORITY_LEVELS))  # CRITICAL first
_OPEN_STATES = ("NEW", "ACKNOWLEDGED", "INVESTIGATING", "ESCALATED")
_DATE_ONLY = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _default_range():
    now = datetime.now(timezone.utc)
    return now - timedelta(days=30), now


def _parse_bound(value, end_of_day):
    """A bare date (YYYY-MM-DD) means the whole day: 'to' covers up to the end of that day.

    Parsing a bare 'to' date as midnight silently dropped everything that happened on the
    last day of the range, which for the default range is today.
    """
    if value and _DATE_ONLY.match(value):
        day = datetime.fromisoformat(value).replace(tzinfo=timezone.utc)
        return day + timedelta(days=1) - timedelta(microseconds=1) if end_of_day else day
    return parse_iso(value)


def _minutes_between(start, end):
    if not start or not end:
        return None
    if start.tzinfo is None:
        start = start.replace(tzinfo=timezone.utc)
    if end.tzinfo is None:
        end = end.replace(tzinfo=timezone.utc)
    return round((end - start).total_seconds() / 60, 1)


def _avg(values):
    values = [v for v in values if v is not None]
    return round(sum(values) / len(values), 1) if values else None


def _iso(dt):
    return dt.isoformat() if dt else None


def _build_report(from_ts, to_ts):
    incidents = (
        Incident.query.filter(Incident.created_at >= from_ts, Incident.created_at <= to_ts)
        .order_by(Incident.created_at.desc())
        .all()
    )
    in_range = (Event.timestamp >= from_ts, Event.timestamp <= to_ts)

    # ---- events (aggregated in SQL: a month of events can be large) ----
    events_total = Event.query.filter(*in_range).count()
    events_by_priority = dict(
        db.session.query(Event.priority_level, db.func.count(Event.event_id)).filter(*in_range).group_by(Event.priority_level).all()
    )
    events_by_type = (
        db.session.query(Event.event_type, db.func.count(Event.event_id).label("n"))
        .filter(*in_range).group_by(Event.event_type).order_by(db.desc("n")).limit(10).all()
    )
    events_by_status = dict(
        db.session.query(Event.status, db.func.count(Event.event_id)).filter(*in_range).group_by(Event.status).all()
    )
    attackers = (
        db.session.query(
            Event.src_ip,
            db.func.count(Event.event_id).label("n"),
            db.func.max(Event.severity_score).label("max_score"),
            db.func.min(Event.timestamp),
            db.func.max(Event.timestamp),
        )
        .filter(*in_range, Event.src_ip.isnot(None))
        .group_by(Event.src_ip).order_by(db.desc("max_score"), db.desc("n")).limit(10).all()
    )

    rule_counts = Counter()
    asset_hits = Counter()
    scored = Event.query.filter(*in_range, Event.severity_score > 0).with_entities(Event.matched_rules, Event.modifiers_applied)
    for matched_rules, mods in scored:
        for rule in matched_rules or []:
            rule_counts[rule.get("name", f"rule_{rule.get('rule_id')}")] += 1
        for mod in mods or []:
            if mod.get("name") == "critical_asset":
                asset_hits[mod.get("asset") or "critical asset"] += 1

    # ---- incidents ----
    by_priority = Counter(i.priority_level for i in incidents)
    by_state = Counter(i.state for i in incidents)
    tta = [_minutes_between(i.created_at, i.acknowledged_at) for i in incidents]
    ttr = [_minutes_between(i.created_at, i.resolved_at) for i in incidents]

    workload = defaultdict(lambda: {"assigned": 0, "open": 0, "resolved": 0})
    for i in incidents:
        name = i.assignee.full_name if i.assignee else "Unassigned"
        workload[name]["assigned"] += 1
        if i.state in _OPEN_STATES:
            workload[name]["open"] += 1
        if i.state in ("RESOLVED", "CLOSED", "FALSE_POSITIVE"):
            workload[name]["resolved"] += 1

    return {
        "title": "SentryLite incident report",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generated_by": current_user.full_name if current_user and current_user.is_authenticated else None,
        "range": {"from": from_ts.isoformat(), "to": to_ts.isoformat()},
        "summary": {
            "events_total": events_total,
            "events_high_or_critical": events_by_priority.get("HIGH", 0) + events_by_priority.get("CRITICAL", 0),
            "incidents_total": len(incidents),
            "incidents_open": sum(1 for i in incidents if i.state in _OPEN_STATES),
            "incidents_unassigned": sum(1 for i in incidents if i.assigned_to is None and i.state in _OPEN_STATES),
            "unique_attackers": Event.query.filter(*in_range, Event.src_ip.isnot(None)).with_entities(Event.src_ip).distinct().count(),
        },
        "events_by_priority": {p: events_by_priority.get(p, 0) for p in _PRIORITIES_DESC},
        "events_by_type": [{"event_type": t, "count": n} for t, n in events_by_type],
        "events_by_status": {s: events_by_status.get(s, 0) for s in ("NEW", "ACKNOWLEDGED", "ESCALATED", "DISMISSED")},
        "totals_by_priority": {p: by_priority.get(p, 0) for p in _PRIORITIES_DESC},
        "totals_by_state": {s: by_state.get(s, 0) for s in INCIDENT_STATES},
        "mtta_minutes": _avg(tta),
        "mttr_minutes": _avg(ttr),
        "top_rules": [{"rule_name": name, "trigger_count": count} for name, count in rule_counts.most_common(10)],
        "top_source_ips": [
            {
                "src_ip": ip,
                "count": n,
                "max_score": float(max_score or 0),
                "first_seen": _iso(first),
                "last_seen": _iso(last),
            }
            for ip, n, max_score, first, last in attackers
        ],
        "critical_asset_hits": [{"asset": name, "count": n} for name, n in asset_hits.most_common()],
        "workload": [{"assignee": name, **counts} for name, counts in sorted(workload.items(), key=lambda kv: -kv[1]["assigned"])],
        "incidents": [
            {
                "reference": i.reference,
                "title": i.title,
                "priority_level": i.priority_level,
                "state": i.state,
                "assignee": i.assignee.full_name if i.assignee else None,
                "created_at": _iso(i.created_at),
                "acknowledged_at": _iso(i.acknowledged_at),
                "resolved_at": _iso(i.resolved_at),
                "closed_at": _iso(i.closed_at),
                "minutes_to_acknowledge": _minutes_between(i.created_at, i.acknowledged_at),
                "minutes_to_resolve": _minutes_between(i.created_at, i.resolved_at),
                "linked_events": len(i.linked_events) + 1,
                "resolution_summary": i.resolution_summary,
            }
            for i in incidents
        ],
    }


def _fmt_dt(iso):
    if not iso:
        return "-"
    return datetime.fromisoformat(iso).strftime("%Y-%m-%d %H:%M UTC")


def _fmt_minutes(value):
    if value is None:
        return "-"
    return f"{value} min" if value < 120 else f"{round(value / 60, 1)} h"


def _filename(report, ext):
    start = report["range"]["from"][:10]
    end = report["range"]["to"][:10]
    return f"sentrylite_report_{start}_to_{end}.{ext}"


def _csv_response(report):
    buf = io.StringIO()
    w = csv.writer(buf)
    s = report["summary"]
    w.writerow([report["title"]])
    w.writerow(["Period", _fmt_dt(report["range"]["from"]), _fmt_dt(report["range"]["to"])])
    w.writerow(["Generated", _fmt_dt(report["generated_at"]), report["generated_by"] or ""])
    w.writerow([])
    w.writerow(["SUMMARY"])
    w.writerow(["Events analysed", s["events_total"]])
    w.writerow(["High/critical events", s["events_high_or_critical"]])
    w.writerow(["Unique attacker IPs", s["unique_attackers"]])
    w.writerow(["Incidents opened", s["incidents_total"]])
    w.writerow(["Incidents still open", s["incidents_open"]])
    w.writerow(["Open and unassigned", s["incidents_unassigned"]])
    w.writerow(["Mean time to acknowledge (min)", report["mtta_minutes"]])
    w.writerow(["Mean time to resolve (min)", report["mttr_minutes"]])
    w.writerow([])
    w.writerow(["EVENTS BY PRIORITY", "Count"])
    for k, v in report["events_by_priority"].items():
        w.writerow([k, v])
    w.writerow([])
    w.writerow(["EVENTS BY TYPE", "Count"])
    for row in report["events_by_type"]:
        w.writerow([row["event_type"], row["count"]])
    w.writerow([])
    w.writerow(["INCIDENTS BY PRIORITY", "Count"])
    for k, v in report["totals_by_priority"].items():
        w.writerow([k, v])
    w.writerow([])
    w.writerow(["INCIDENTS BY STATE", "Count"])
    for k, v in report["totals_by_state"].items():
        w.writerow([k, v])
    w.writerow([])
    w.writerow(["TOP RULES TRIGGERED", "Trigger count"])
    for row in report["top_rules"]:
        w.writerow([row["rule_name"], row["trigger_count"]])
    w.writerow([])
    w.writerow(["TOP ATTACKER IPS", "Events", "Highest score", "First seen", "Last seen"])
    for row in report["top_source_ips"]:
        w.writerow([row["src_ip"], row["count"], row["max_score"], _fmt_dt(row["first_seen"]), _fmt_dt(row["last_seen"])])
    w.writerow([])
    w.writerow(["CRITICAL ASSET HITS", "Events"])
    for row in report["critical_asset_hits"]:
        w.writerow([row["asset"], row["count"]])
    w.writerow([])
    w.writerow(["WORKLOAD", "Assigned", "Open", "Resolved/closed"])
    for row in report["workload"]:
        w.writerow([row["assignee"], row["assigned"], row["open"], row["resolved"]])
    w.writerow([])
    w.writerow(["INCIDENTS"])
    w.writerow([
        "Reference", "Title", "Priority", "State", "Assignee", "Created", "Acknowledged",
        "Resolved", "Closed", "Minutes to acknowledge", "Minutes to resolve", "Events", "Resolution summary",
    ])
    for inc in report["incidents"]:
        w.writerow([
            inc["reference"], inc["title"], inc["priority_level"], inc["state"], inc["assignee"] or "Unassigned",
            _fmt_dt(inc["created_at"]), _fmt_dt(inc["acknowledged_at"]), _fmt_dt(inc["resolved_at"]),
            _fmt_dt(inc["closed_at"]), inc["minutes_to_acknowledge"], inc["minutes_to_resolve"],
            inc["linked_events"], inc["resolution_summary"] or "",
        ])

    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={_filename(report, 'csv')}"},
    )


_PRIORITY_COLOURS = {
    "CRITICAL": "#e5484d", "HIGH": "#f76808", "MEDIUM": "#c9a800", "LOW": "#3b9eff", "INFORMATIONAL": "#8b98a5",
}


def _pdf_response(report):
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    from xml.sax.saxutils import escape

    buf = io.BytesIO()
    page = landscape(A4)
    doc = SimpleDocTemplate(
        buf, pagesize=page, leftMargin=14 * mm, rightMargin=14 * mm, topMargin=14 * mm, bottomMargin=14 * mm,
        title="SentryLite Incident Report",
    )
    width = page[0] - 28 * mm
    styles = getSampleStyleSheet()
    cell = ParagraphStyle("cell", parent=styles["Normal"], fontSize=7.5, leading=9)
    small = ParagraphStyle("small", parent=styles["Normal"], fontSize=8.5, textColor=colors.HexColor("#4a5560"))
    h2 = ParagraphStyle("h2", parent=styles["Heading2"], fontSize=12, spaceBefore=10, spaceAfter=4)
    head_bg = colors.HexColor("#171d26")

    def p(text, style=cell):
        return Paragraph(escape(str(text if text is not None else "-")), style)

    def body_cell(value, is_priority):
        colour = _PRIORITY_COLOURS.get(value) if is_priority else None
        if colour:
            return Paragraph(f"<font color='{colour}'><b>{escape(str(value))}</b></font>", cell)
        return p(value)

    def table(header, rows, col_widths=None, priority_col=None):
        # Header cells are Paragraphs, which ignore TEXTCOLOR, so their colour goes in the markup.
        data = [[Paragraph(f"<font color='white'><b>{escape(h)}</b></font>", cell) for h in header]]
        if rows:
            data += [[body_cell(value, c == priority_col) for c, value in enumerate(row)] for row in rows]
        else:
            data.append([p("No data in this period")] + [p("") for _ in header[1:]])
        t = Table(data, colWidths=col_widths, hAlign="LEFT", repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), head_bg),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#c4ccd4")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f3f5f8")]),
        ]))
        return t

    s = report["summary"]
    story = [
        Paragraph("SentryLite Incident Report", styles["Title"]),
        Paragraph(
            f"Period: {_fmt_dt(report['range']['from'])} to {_fmt_dt(report['range']['to'])} &nbsp;&middot;&nbsp; "
            f"Generated {_fmt_dt(report['generated_at'])}"
            + (f" by {escape(report['generated_by'])}" if report["generated_by"] else ""),
            small,
        ),
        Spacer(1, 8),
    ]

    kpis = [
        ("Events analysed", s["events_total"]),
        ("High / critical events", s["events_high_or_critical"]),
        ("Unique attacker IPs", s["unique_attackers"]),
        ("Incidents opened", s["incidents_total"]),
        ("Still open", s["incidents_open"]),
        ("Mean time to acknowledge", _fmt_minutes(report["mtta_minutes"])),
        ("Mean time to resolve", _fmt_minutes(report["mttr_minutes"])),
    ]
    kpi_value = ParagraphStyle("kv", parent=styles["Normal"], fontSize=15, leading=18, fontName="Helvetica-Bold")
    kpi_table = Table(
        [[Paragraph(str(v), kpi_value) for _, v in kpis], [p(label, small) for label, _ in kpis]],
        colWidths=[width / len(kpis)] * len(kpis),
    )
    kpi_table.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#c4ccd4")),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e1e6eb")),
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f7f9fb")),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
    ]))
    story += [kpi_table, Spacer(1, 6)]

    half = (width - 8 * mm) / 2

    def side_by_side(left, right):
        t = Table([[left, right]], colWidths=[half + 4 * mm, half + 4 * mm], hAlign="LEFT")
        t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 0)]))
        return t

    story.append(Paragraph("Activity overview", h2))
    story.append(side_by_side(
        table(["Event priority", "Events"], [[k, v] for k, v in report["events_by_priority"].items()], [half * 0.6, half * 0.4], priority_col=0),
        table(["Incident priority", "Incidents"], [[k, v] for k, v in report["totals_by_priority"].items()], [half * 0.6, half * 0.4], priority_col=0),
    ))
    story.append(Spacer(1, 6))
    story.append(side_by_side(
        table(["Event type", "Events"], [[r["event_type"], r["count"]] for r in report["events_by_type"]], [half * 0.6, half * 0.4]),
        table(["Incident state", "Incidents"], [[k, v] for k, v in report["totals_by_state"].items()], [half * 0.6, half * 0.4]),
    ))

    story.append(Paragraph("Threats", h2))
    story.append(table(
        ["Attacker IP", "Events", "Highest score", "First seen", "Last seen"],
        [[r["src_ip"], r["count"], r["max_score"], _fmt_dt(r["first_seen"]), _fmt_dt(r["last_seen"])] for r in report["top_source_ips"]],
        [width * 0.24, width * 0.12, width * 0.14, width * 0.25, width * 0.25],
    ))
    story.append(Spacer(1, 6))
    story.append(side_by_side(
        table(["Detection rule", "Times triggered"], [[r["rule_name"], r["trigger_count"]] for r in report["top_rules"]], [half * 0.7, half * 0.3]),
        table(["Critical asset targeted", "Events"], [[r["asset"], r["count"]] for r in report["critical_asset_hits"]], [half * 0.7, half * 0.3]),
    ))

    story.append(Paragraph("Team workload", h2))
    story.append(table(
        ["Assignee", "Assigned", "Open", "Resolved / closed"],
        [[r["assignee"], r["assigned"], r["open"], r["resolved"]] for r in report["workload"]],
        [width * 0.4, width * 0.2, width * 0.2, width * 0.2],
    ))

    story.append(Paragraph(f"Incidents ({len(report['incidents'])})", h2))
    story.append(table(
        ["Reference", "Title", "Priority", "State", "Assignee", "Created", "To ack", "To resolve", "Resolution summary"],
        [
            [
                i["reference"], i["title"], i["priority_level"], i["state"], i["assignee"] or "Unassigned",
                _fmt_dt(i["created_at"]), _fmt_minutes(i["minutes_to_acknowledge"]),
                _fmt_minutes(i["minutes_to_resolve"]), i["resolution_summary"] or "",
            ]
            for i in report["incidents"]
        ],
        [width * w for w in (0.11, 0.2, 0.08, 0.1, 0.1, 0.12, 0.07, 0.07, 0.15)],
        priority_col=2,
    ))

    doc.build(story)
    buf.seek(0)
    return Response(
        buf.read(),
        mimetype="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={_filename(report, 'pdf')}"},
    )


@api_bp.route("/reports/incidents", methods=["GET"])
@role_required()
def incident_report():
    default_from, default_to = _default_range()
    from_ts = _parse_bound(request.args.get("from"), end_of_day=False) or default_from
    to_ts = _parse_bound(request.args.get("to"), end_of_day=True) or default_to
    if from_ts > to_ts:
        raise ApiError("INVALID_PARAM", "'from' must be before 'to'", 400)
    fmt = request.args.get("format", "json")
    if fmt not in ("json", "csv", "pdf"):
        raise ApiError("INVALID_PARAM", "format must be json, csv or pdf", 400)

    report = _build_report(from_ts, to_ts)

    if fmt == "csv":
        return _csv_response(report)
    if fmt == "pdf":
        return _pdf_response(report)
    return jsonify(report)
