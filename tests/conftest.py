import pytest
from flask.globals import _cv_app
from flask.testing import FlaskClient

from app import create_app
from app.extensions import db as _db
from app.models.log_source import LogSource
from app.models.user import User
from app.triage.correlator import correlator
from app.triage.engine import invalidate_rule_cache
from app.triage.modifiers import invalidate_asset_cache

# The `app` fixture below holds one app context open for the whole test so that
# fixtures/test bodies can touch db.session without their own `with app.app_context()`.
# But Flask's RequestContext.push() reuses an already-active app context for the same
# app instead of pushing a fresh one — and flask-login caches current_user on
# `flask.g`, which lives on the app context. Left alone, that means every test-client
# request in a test shares one `g`, so the *first* login "sticks" and leaks into every
# later request (even ones sent by a different, differently-authenticated client).
#
# _IsolatedClient works around this by hiding the ambient app context from Flask for
# the duration of each request, forcing Flask to push a genuinely fresh one (fresh g).
# It does this via the raw `_cv_app` contextvar rather than `AppContext.pop()`/`.push()`
# — popping the ambient context for real would fire its teardown callback (Flask-
# SQLAlchemy's `db.session.remove()`), detaching every ORM object the test already
# holds (e.g. fixture-created users) even though we only meant to pause it briefly.
class _IsolatedClient(FlaskClient):
    _depth = 0

    def open(self, *args, **kwargs):
        # open() re-enters itself when follow_redirects=True chases a redirect chain;
        # only the outermost call should hide the ambient context.
        type(self)._depth += 1
        is_outermost = type(self)._depth == 1
        token = _cv_app.set(None) if is_outermost else None
        try:
            return super().open(*args, **kwargs)
        finally:
            if token is not None:
                _cv_app.reset(token)
            type(self)._depth -= 1


@pytest.fixture()
def app():
    application = create_app("testing")
    application.test_client_class = _IsolatedClient
    with application.app_context():
        _db.create_all()
        yield application
        _db.session.remove()
        _db.drop_all()


@pytest.fixture()
def db(app):
    return _db


@pytest.fixture(autouse=True)
def _reset_caches():
    from app.realtime.events import reset_realtime_state

    correlator.reset()
    invalidate_rule_cache()
    invalidate_asset_cache()
    reset_realtime_state()
    # flask_socketio.test_client.SocketIOTestClient.clients is a class-level dict that
    # otherwise accumulates every SocketIOTestClient ever created for the whole pytest
    # session, causing later realtime tests' connect handshakes to interact with an
    # earlier test's (now torn-down) app/server instances.
    from flask_socketio.test_client import SocketIOTestClient

    SocketIOTestClient.clients = {}
    yield
    correlator.reset()
    invalidate_rule_cache()
    invalidate_asset_cache()
    SocketIOTestClient.clients = {}


@pytest.fixture()
def client(app):
    return app.test_client()


def make_user(db, username, role, password="password123"):
    user = User(username=username, email=f"{username}@example.com", full_name=username.title(), role=role)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    return user


@pytest.fixture()
def admin_user(app, db):
    return make_user(db, "admin_test", "ADMIN")


@pytest.fixture()
def analyst_user(app, db):
    return make_user(db, "analyst_test", "ANALYST")


@pytest.fixture()
def viewer_user(app, db):
    return make_user(db, "viewer_test", "VIEWER")


def login(client, username, password="password123"):
    return client.post("/auth/login", data={"username": username, "password": password}, follow_redirects=True)


@pytest.fixture()
def admin_client(app, admin_user):
    # A dedicated test client (own cookie jar) — tests that need two authenticated
    # roles at once (e.g. admin_client + analyst_client) must not share one session.
    c = app.test_client()
    login(c, admin_user.username)
    return c


@pytest.fixture()
def analyst_client(app, analyst_user):
    c = app.test_client()
    login(c, analyst_user.username)
    return c


@pytest.fixture()
def viewer_client(app, viewer_user):
    c = app.test_client()
    login(c, viewer_user.username)
    return c


@pytest.fixture()
def log_source(app, db):
    import hashlib

    token = "test-token-123456"
    source = LogSource(
        name="test-source",
        host_identifier="203.0.113.5",
        source_type="AUTH_LOG",
        ingest_token_hash=hashlib.sha256(token.encode()).hexdigest(),
        is_enabled=True,
    )
    db.session.add(source)
    db.session.commit()
    return source, token
