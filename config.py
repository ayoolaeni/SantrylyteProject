"""Flask configuration classes, selected via FLASK_ENV / TestConfig override."""
import os
from datetime import timedelta

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


def _bool(name, default):
    return os.environ.get(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


def _list(name, default):
    raw = os.environ.get(name, default)
    return [x.strip() for x in raw.split(",") if x.strip()]


def _resolve_database_uri():
    """A bare `sqlite:///relative/path` is fragile (resolves against whatever the
    current process's CWD happens to be — differs between `flask`, `python run.py`,
    a systemd unit, etc.), so relative sqlite URIs are rewritten to be BASE_DIR-absolute.
    """
    url = os.environ.get("DATABASE_URL", "sqlite:///" + os.path.join(BASE_DIR, "instance", "sentrylite.db"))
    prefix = "sqlite:///"
    if url.startswith(prefix) and not url[len(prefix):].startswith("/") and ":" not in url[len(prefix):len(prefix) + 2]:
        relative_path = url[len(prefix):]
        url = "sqlite:///" + os.path.join(BASE_DIR, relative_path)
    return url


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-only-insecure-key-change-me")
    SQLALCHEMY_DATABASE_URI = _resolve_database_uri()
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {"pool_pre_ping": True}

    WTF_CSRF_ENABLED = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = _bool("SESSION_COOKIE_SECURE", False)
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=int(os.environ.get("SESSION_IDLE_MINUTES", 30)))
    SESSION_ABSOLUTE_MINUTES = 12 * 60

    SYSLOG_ENABLED = _bool("SYSLOG_ENABLED", True)
    SYSLOG_UDP_PORT = int(os.environ.get("SYSLOG_UDP_PORT", 5514))
    SYSLOG_TCP_PORT = int(os.environ.get("SYSLOG_TCP_PORT", 5514))
    SYSLOG_BIND = os.environ.get("SYSLOG_BIND", "0.0.0.0")

    TRIAGE_WORKERS = int(os.environ.get("TRIAGE_WORKERS", 4))
    RAW_QUEUE_MAXSIZE = int(os.environ.get("RAW_QUEUE_MAXSIZE", 100000))
    SPILL_DIR = os.environ.get("SPILL_DIR", os.path.join(BASE_DIR, "instance", "spill"))

    THRESHOLD_CRITICAL = float(os.environ.get("THRESHOLD_CRITICAL", 90))
    THRESHOLD_HIGH = float(os.environ.get("THRESHOLD_HIGH", 65))
    THRESHOLD_MEDIUM = float(os.environ.get("THRESHOLD_MEDIUM", 40))
    THRESHOLD_LOW = float(os.environ.get("THRESHOLD_LOW", 15))
    SCORE_CEILING = float(os.environ.get("SCORE_CEILING", 200))

    WORKING_HOURS_START = os.environ.get("WORKING_HOURS_START", "08:00")
    WORKING_HOURS_END = os.environ.get("WORKING_HOURS_END", "18:00")
    WORKING_DAYS = _list("WORKING_DAYS", "MON,TUE,WED,THU,FRI")
    OFF_HOURS_BONUS = float(os.environ.get("OFF_HOURS_BONUS", 10))

    REPEAT_WINDOW_SECONDS = int(os.environ.get("REPEAT_WINDOW_SECONDS", 120))
    REPEAT_LIMIT = int(os.environ.get("REPEAT_LIMIT", 10))
    REPEAT_BONUS = float(os.environ.get("REPEAT_BONUS", 20))

    INTERNAL_NETWORKS = _list("INTERNAL_NETWORKS", "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16")
    CORRELATOR_MAX_KEYS = int(os.environ.get("CORRELATOR_MAX_KEYS", 50000))

    LOGIN_MAX_ATTEMPTS = int(os.environ.get("LOGIN_MAX_ATTEMPTS", 5))
    LOGIN_LOCKOUT_MINUTES = 15
    INGEST_RATE_LIMIT_PER_MIN = int(os.environ.get("INGEST_RATE_LIMIT_PER_MIN", 500))
    SOURCE_SILENT_MINUTES = int(os.environ.get("SOURCE_SILENT_MINUTES", 15))

    RULE_CACHE_TTL_SECONDS = 30


class DevConfig(Config):
    DEBUG = True


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    WTF_CSRF_ENABLED = False
    SYSLOG_ENABLED = False
    SPILL_DIR = os.path.join(BASE_DIR, "instance", "test_spill")


class ProdConfig(Config):
    DEBUG = False
    # Secure by default (HTTPS is assumed to be terminated by a reverse proxy in
    # production, §11.11) — only relax this for a same-host HTTP demo (e.g. running
    # docker-compose locally without TLS) by setting SESSION_COOKIE_SECURE=false.
    SESSION_COOKIE_SECURE = _bool("SESSION_COOKIE_SECURE", True)


CONFIG_MAP = {
    "development": DevConfig,
    "testing": TestConfig,
    "production": ProdConfig,
}


def get_config(name=None):
    name = name or os.environ.get("FLASK_ENV", "development")
    return CONFIG_MAP.get(name, DevConfig)
