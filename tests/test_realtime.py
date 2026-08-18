import time

from app.extensions import socketio
from app.models.user import User
from tests.conftest import login


def _login_socketio_client(app, client, username, password):
    login(client, username, password)
    return socketio.test_client(app, namespace="/live", flask_test_client=client)


def test_anonymous_socket_connection_is_rejected(app, client):
    sio = socketio.test_client(app, namespace="/live", flask_test_client=client)
    assert sio.is_connected(namespace="/live") is False


def test_authenticated_client_receives_event_new_after_ingestion(app, db, client, log_source):
    user = User(username="rt_analyst", email="rt@example.com", full_name="RT Analyst", role="ANALYST")
    user.set_password("password123")
    db.session.add(user)
    db.session.commit()

    sio = _login_socketio_client(app, client, "rt_analyst", "password123")
    assert sio.is_connected(namespace="/live")
    sio.emit("subscribe", {"rooms": ["all_events"]}, namespace="/live")
    sio.get_received(namespace="/live")  # drain any connect-time noise

    _, token = log_source
    client.post(
        "/api/v1/ingest",
        json={"message": "Jul 10 10:00:01 web01 sshd[1]: Accepted password for root from 203.0.113.5 port 1 ssh2"},
        headers={"Authorization": f"Bearer {token}"},
    )

    # event:new is coalesced and flushed every 250ms by a background task.
    deadline = time.monotonic() + 2.0
    received = []
    while time.monotonic() < deadline:
        received.extend(sio.get_received(namespace="/live"))
        if any(msg["name"] == "event:new" for msg in received):
            break
        time.sleep(0.1)

    event_new_messages = [m for m in received if m["name"] == "event:new"]
    assert event_new_messages, f"expected an event:new emission, got: {received}"
    batch = event_new_messages[0]["args"][0]
    assert any(e["event_type"] == "AUTH_SUCCESS" for e in batch)
