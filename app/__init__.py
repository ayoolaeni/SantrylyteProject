"""Application factory for SentryLite."""
import os
import threading

from flask import Flask, jsonify, request

from config import get_config
from app.extensions import db, migrate, login_manager, socketio, csrf
from app.security.rbac import ApiError


def create_app(config_name=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(get_config(config_name))

    os.makedirs(app.instance_path, exist_ok=True)
    os.makedirs(app.config["SPILL_DIR"], exist_ok=True)

    from app.ingestion.queue import RawQueue

    app.raw_queue = RawQueue(app.config["RAW_QUEUE_MAXSIZE"], app.config["SPILL_DIR"])

    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    csrf.init_app(app)
    _configure_sqlite_concurrency(app)

    async_mode = "threading" if app.config.get("TESTING") else "eventlet"
    socketio.init_app(app, async_mode=async_mode, cors_allowed_origins=[])

    from app.models import User

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    _register_blueprints(app)
    _register_error_handlers(app)
    _register_security_headers(app)

    return app


_sqlite_pragmas_registered = False
_sqlite_write_lock = threading.Lock()


def _configure_sqlite_concurrency(app):
    """The dev/test DB is SQLite, but the app is inherently multi-writer (TRIAGE_WORKERS
    threads plus request handlers all committing concurrently). SQLite only ever allows
    one writer at a time — WAL mode plus a busy_timeout is the usual fix, but under
    eventlet a blocked writer holds the C-level SQLite lock in a call that doesn't yield
    the event loop, so contention doesn't retry quietly, it stalls the whole process.

    The fix: serialise only transactions that actually write (first INSERT/UPDATE/DELETE
    in a transaction takes the lock, held until commit/rollback) through one process-wide
    lock — matching what SQLite can actually do concurrently. Plain reads (the large
    majority of requests: the dashboard, the alert queue, every GET) never touch the
    lock and stay fully concurrent, which is what makes this different from — and much
    faster than — locking every transaction indiscriminately. Postgres (prod) is a real
    multi-writer database and gets none of this.
    """
    global _sqlite_pragmas_registered
    if not app.config["SQLALCHEMY_DATABASE_URI"].startswith("sqlite"):
        return
    if _sqlite_pragmas_registered:
        return
    _sqlite_pragmas_registered = True

    from sqlalchemy import event
    from sqlalchemy.engine import Engine

    @event.listens_for(Engine, "connect")
    def _set_sqlite_pragmas(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA busy_timeout=30000")
        cursor.close()

    _WRITE_PREFIXES = ("INSERT", "UPDATE", "DELETE")

    @event.listens_for(Engine, "before_cursor_execute")
    def _acquire_sqlite_write_lock(conn, cursor, statement, parameters, context, executemany):
        if conn.info.get("sqlite_write_lock_held"):
            return
        if statement.lstrip()[:6].upper() in _WRITE_PREFIXES:
            _sqlite_write_lock.acquire()
            conn.info["sqlite_write_lock_held"] = True

    @event.listens_for(Engine, "commit")
    def _release_sqlite_write_lock_commit(conn):
        if conn.info.pop("sqlite_write_lock_held", False):
            _sqlite_write_lock.release()

    @event.listens_for(Engine, "rollback")
    def _release_sqlite_write_lock_rollback(conn):
        if conn.info.pop("sqlite_write_lock_held", False):
            _sqlite_write_lock.release()


def _register_blueprints(app):
    from app.views.auth import auth_bp
    from app.views.dashboard import dashboard_bp
    from app.views.alerts import alerts_bp
    from app.views.incidents import incidents_bp
    from app.views.admin import admin_bp
    from app.api import api_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(alerts_bp)
    app.register_blueprint(incidents_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(api_bp, url_prefix="/api/v1")
    # Session-cookie-authenticated API routes keep CSRF protection (NFR5.3); only the
    # bearer-token ingest endpoint is exempted (log shippers can't carry a CSRF token).

    from app.realtime import events as realtime_events

    realtime_events.register_handlers()


def _register_error_handlers(app):
    @app.errorhandler(ApiError)
    def handle_api_error(err):
        return err.to_response()

    @app.errorhandler(404)
    def not_found(err):
        if request.path.startswith("/api/"):
            return jsonify({"error": {"code": "NOT_FOUND", "message": "Resource not found", "details": {}}}), 404
        from flask import render_template

        return render_template("404.html"), 404

    @app.errorhandler(403)
    def forbidden(err):
        if request.path.startswith("/api/"):
            return jsonify({"error": {"code": "FORBIDDEN", "message": "Forbidden", "details": {}}}), 403
        return "Forbidden", 403


def _register_security_headers(app):
    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; connect-src 'self' ws: wss:"
        )
        return response
