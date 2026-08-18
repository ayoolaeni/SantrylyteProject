"""Shared Flask extension instances, initialised in create_app()."""
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_socketio import SocketIO
from flask_wtf import CSRFProtect

db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
socketio = SocketIO(cors_allowed_origins=[], async_mode="eventlet")
csrf = CSRFProtect()

login_manager.login_view = "auth.login"
login_manager.session_protection = "strong"
