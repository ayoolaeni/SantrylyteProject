"""Entrypoint: socketio.run(app). Must monkey-patch eventlet before any other stdlib import."""
import os

if os.environ.get("FLASK_ENV", "development") != "testing":
    import eventlet

    eventlet.monkey_patch()

from dotenv import load_dotenv  # noqa: E402

load_dotenv()

from app import create_app  # noqa: E402
from app.extensions import socketio  # noqa: E402
from app.ingestion.bootstrap import start_services  # noqa: E402

app = create_app()

if __name__ == "__main__":
    start_services(app)
    port = int(os.environ.get("PORT", 5000))
    socketio.run(app, host="0.0.0.0", port=port, debug=app.config.get("DEBUG", False))
