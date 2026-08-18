"""SocketIO handlers + emit helpers for the /live namespace (§9)."""
import logging
import threading
from collections import deque
from datetime import datetime, timedelta, timezone

from flask import current_app
from flask_login import current_user
from flask_socketio import join_room, leave_room

from app.extensions import socketio

logger = logging.getLogger("sentrylite.realtime")

ALLOWED_ROOMS = {"all_events", "priority_critical", "priority_high", "incidents"}
NAMESPACE = "/live"

_pending_events = deque()
_pending_lock = threading.Lock()
_background_tasks_started = False
_bg_lock = threading.Lock()


def queue_event_emit(event_summary):
    """Enqueue an event for the coalesced event:new emitter (up to 25 events / 250ms, §9 backpressure)."""
    with _pending_lock:
        _pending_events.append(event_summary)


def emit_alert_high(event_summary):
    rooms = ["priority_high"]
    if event_summary.get("priority_level") == "CRITICAL":
        rooms.append("priority_critical")
    for room in rooms:
        socketio.emit("alert:high", event_summary, room=room, namespace=NAMESPACE)


def emit_incident_created(incident_summary):
    socketio.emit("incident:created", incident_summary, room="incidents", namespace=NAMESPACE)


def emit_incident_updated(payload):
    socketio.emit("incident:updated", payload, room="incidents", namespace=NAMESPACE)


def emit_source_silent(payload):
    socketio.emit("source:silent", payload, namespace=NAMESPACE)


def _flush_event_batch():
    batch = []
    with _pending_lock:
        while _pending_events and len(batch) < 25:
            batch.append(_pending_events.popleft())
    if batch:
        socketio.emit("event:new", batch, room="all_events", namespace=NAMESPACE)


def _event_flush_loop():
    while True:
        socketio.sleep(0.25)
        try:
            _flush_event_batch()
        except Exception:
            logger.exception("event batch flush failed")


def _stats_tick_loop(app):
    from app.api.stats import build_summary

    with app.app_context():
        while True:
            socketio.sleep(5)
            try:
                socketio.emit("stats:tick", build_summary(), namespace=NAMESPACE)
            except Exception:
                logger.exception("stats tick failed")


def _source_silent_loop(app):
    from app.models.log_source import LogSource

    with app.app_context():
        while True:
            socketio.sleep(60)
            try:
                silent_minutes = app.config["SOURCE_SILENT_MINUTES"]
                cutoff = datetime.now(timezone.utc) - timedelta(minutes=silent_minutes)
                sources = LogSource.query.filter(
                    LogSource.is_enabled.is_(True),
                    LogSource.last_seen_at.isnot(None),
                    LogSource.last_seen_at < cutoff,
                ).all()
                for source in sources:
                    emit_source_silent(
                        {
                            "source_id": source.source_id,
                            "name": source.name,
                            "last_seen_at": source.last_seen_at.isoformat(),
                        }
                    )
            except Exception:
                logger.exception("source silent check failed")


def ensure_background_tasks_started():
    global _background_tasks_started
    with _bg_lock:
        if _background_tasks_started:
            return
        _background_tasks_started = True
        app = current_app._get_current_object()
        socketio.start_background_task(_event_flush_loop)
        socketio.start_background_task(_stats_tick_loop, app)
        socketio.start_background_task(_source_silent_loop, app)


def reset_realtime_state():
    """Test-only hook: each pytest `app` fixture creates a fresh SocketIO server, so the
    background loops (and the one-shot flag guarding them) must reset too, or a later
    test's `ensure_background_tasks_started()` silently no-ops against a torn-down app."""
    global _background_tasks_started
    with _bg_lock:
        _background_tasks_started = False


def handle_connect():
    if not current_user.is_authenticated:
        logger.info("rejected anonymous socket connection")
        return False
    join_room("all_events")
    join_room(f"user_{current_user.user_id}")
    ensure_background_tasks_started()
    return True


def handle_subscribe(data):
    if not current_user.is_authenticated:
        return
    for room in (data or {}).get("rooms", []):
        if room in ALLOWED_ROOMS:
            join_room(room)


def handle_unsubscribe(data):
    for room in (data or {}).get("rooms", []):
        leave_room(room)


def register_handlers():
    """Bind the /live namespace handlers onto the *current* socketio.server.

    This must be called every time create_app() runs, not just relied on via module
    import: `@socketio.on(...)` decorators only execute once (Python caches module
    imports), so a second create_app() call in the same process — every test, plus any
    multi-app scenario — would otherwise leave its brand-new socketio.server with no
    handlers registered at all, silently rejecting every connection at the transport
    layer before our code ever runs.
    """
    socketio.on_event("connect", handle_connect, namespace=NAMESPACE)
    socketio.on_event("subscribe", handle_subscribe, namespace=NAMESPACE)
    socketio.on_event("unsubscribe", handle_unsubscribe, namespace=NAMESPACE)
