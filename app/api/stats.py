import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from flask import jsonify, request

from app.api import api_bp
from app.extensions import db
from app.models.event import PRIORITY_LEVELS, Event
from app.models.incident import Incident
from app.models.log_source import LogSource
from app.security.rbac import ApiError, role_required

_WINDOW_RE = re.compile(r"^(\d+)([mhd])$")
_OPEN_STATES = ("NEW", "ACKNOWLEDGED", "INVESTIGATING", "ESCALATED")


def _parse_window(text, default_seconds=86400):
    if not text:
        return default_seconds
    m = _WINDOW_RE.match(text)
    if not m:
        raise ApiError("INVALID_PARAM", "window must look like '1h', '30m' or '7d'", 400)
    value, unit = int(m.group(1)), m.group(2)
    return value * {"m": 60, "h": 3600, "d": 86400}[unit]


def build_summary():
    from flask import current_app

    now = datetime.now(timezone.utc)
    day_ago = now - timedelta(hours=24)

    open_by_priority = dict(
        db.session.query(Incident.priority_level, db.func.count(Incident.incident_id))
        .filter(Incident.state.in_(_OPEN_STATES))
        .group_by(Incident.priority_level)
        .all()
    )
    events_24h = Event.query.filter(Event.timestamp >= day_ago).count()

    mtta_rows = db.session.query(Incident.created_at, Incident.acknowledged_at).filter(
        Incident.acknowledged_at.isnot(None)
    ).all()
    mttr_rows = db.session.query(Incident.created_at, Incident.resolved_at).filter(
        Incident.resolved_at.isnot(None)
    ).all()

    def _avg_minutes(rows):
        if not rows:
            return None
        total = sum((end - start).total_seconds() for start, end in rows)
        return round((total / len(rows)) / 60, 1)

    silent_minutes = current_app.config["SOURCE_SILENT_MINUTES"]
    sources = LogSource.query.filter_by(is_enabled=True).all()
    # A source that has never sent anything counts as silent, not online.
    silent = sum(1 for s in sources if not s.last_seen_at or s.is_silent(silent_minutes))
    online = len(sources) - silent

    return {
        "open_incidents_by_priority": {p: open_by_priority.get(p, 0) for p in PRIORITY_LEVELS},
        "events_last_24h": events_24h,
        "mtta_minutes": _avg_minutes(mtta_rows),
        "mttr_minutes": _avg_minutes(mttr_rows),
        "sources_online": online,
        "sources_silent": silent,
        "generated_at": now.isoformat(),
    }


@api_bp.route("/stats/summary", methods=["GET"])
@role_required()
def summary():
    return jsonify(build_summary())


@api_bp.route("/stats/timeseries", methods=["GET"])
@role_required()
def timeseries():
    interval_seconds = _parse_window(request.args.get("interval", "1m"), default_seconds=60)
    window_seconds = _parse_window(request.args.get("window", "1h"), default_seconds=3600)
    now = datetime.now(timezone.utc)
    start = now - timedelta(seconds=window_seconds)

    rows = Event.query.filter(Event.timestamp >= start).with_entities(
        Event.timestamp, Event.priority_level
    ).all()

    buckets = defaultdict(lambda: defaultdict(int))
    for ts, priority in rows:
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        epoch = int(ts.timestamp())
        bucket_epoch = epoch - (epoch % interval_seconds)
        buckets[bucket_epoch][priority] += 1

    series = []
    for bucket_epoch in sorted(buckets):
        bucket_dt = datetime.fromtimestamp(bucket_epoch, tz=timezone.utc)
        entry = {"bucket": bucket_dt.isoformat()}
        entry.update({p: buckets[bucket_epoch].get(p, 0) for p in PRIORITY_LEVELS})
        series.append(entry)

    return jsonify({"interval_seconds": interval_seconds, "window_seconds": window_seconds, "series": series})


@api_bp.route("/stats/priority-distribution", methods=["GET"])
@role_required()
def priority_distribution():
    window_seconds = _parse_window(request.args.get("window", "24h"))
    start = datetime.now(timezone.utc) - timedelta(seconds=window_seconds)
    rows = dict(
        db.session.query(Event.priority_level, db.func.count(Event.event_id))
        .filter(Event.timestamp >= start)
        .group_by(Event.priority_level)
        .all()
    )
    return jsonify({p: rows.get(p, 0) for p in PRIORITY_LEVELS})


@api_bp.route("/stats/top-sources", methods=["GET"])
@role_required()
def top_sources():
    window_seconds = _parse_window(request.args.get("window", "24h"))
    limit = min(50, int(request.args.get("limit", 10)))
    start = datetime.now(timezone.utc) - timedelta(seconds=window_seconds)

    rows = (
        db.session.query(LogSource.name, db.func.count(Event.event_id).label("count"))
        .join(Event, Event.source_id == LogSource.source_id)
        .filter(Event.timestamp >= start)
        .group_by(LogSource.name)
        .order_by(db.desc("count"))
        .limit(limit)
        .all()
    )
    return jsonify([{"source_name": name, "count": count} for name, count in rows])


@api_bp.route("/stats/top-attackers", methods=["GET"])
@role_required()
def top_attackers():
    window_seconds = _parse_window(request.args.get("window", "24h"))
    limit = min(50, int(request.args.get("limit", 10)))
    start = datetime.now(timezone.utc) - timedelta(seconds=window_seconds)

    rows = (
        db.session.query(
            Event.src_ip,
            db.func.count(Event.event_id).label("count"),
            db.func.sum(Event.severity_score).label("total_severity"),
        )
        .filter(Event.timestamp >= start, Event.src_ip.isnot(None))
        .group_by(Event.src_ip)
        .order_by(db.desc("total_severity"))
        .limit(limit)
        .all()
    )
    return jsonify(
        [{"src_ip": ip, "count": count, "total_severity": float(total or 0)} for ip, count, total in rows]
    )
