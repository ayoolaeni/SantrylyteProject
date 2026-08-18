"""POST /api/v1/ingest — bearer-token authenticated. Never blocks: enqueue and return (§8.1)."""
import hashlib
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone

from flask import current_app, jsonify, request

from app.api import api_bp
from app.extensions import csrf
from app.ingestion.worker import process_pending
from app.models.log_source import LogSource
from app.security.rbac import ApiError

MAX_BATCH = 500

_rate_state = defaultdict(deque)
_rate_lock = threading.Lock()


def _rate_limited(source_id, limit_per_min):
    now = time.monotonic()
    with _rate_lock:
        window = _rate_state[source_id]
        while window and now - window[0] > 60:
            window.popleft()
        if len(window) >= limit_per_min:
            return True
        window.append(now)
        return False


def _hash_token(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _extract_bearer_token():
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[len("Bearer "):].strip()
    return None


def _parse_timestamp(value):
    if not value:
        return None
    try:
        ts = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return ts
    except ValueError:
        return None


def _enqueue(source, message, timestamp_value):
    received_at = _parse_timestamp(timestamp_value) or datetime.now(timezone.utc)
    current_app.raw_queue.put(source.source_id, message, received_at=received_at)


@api_bp.route("/ingest", methods=["POST"])
@csrf.exempt
def ingest():
    token = _extract_bearer_token()
    if not token:
        raise ApiError("UNAUTHENTICATED", "Missing bearer token", 401)

    source = LogSource.query.filter_by(ingest_token_hash=_hash_token(token), is_enabled=True).first()
    if not source:
        raise ApiError("UNAUTHENTICATED", "Invalid or disabled ingest token", 401)

    if _rate_limited(source.source_id, current_app.config["INGEST_RATE_LIMIT_PER_MIN"]):
        raise ApiError("RATE_LIMITED", "Ingestion rate limit exceeded for this source", 429)

    accepted = 0
    rejected = 0
    content_type = (request.content_type or "").split(";")[0].strip()

    if content_type == "application/json":
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            raise ApiError("INVALID_BODY", "Malformed JSON body", 422)

        if "events" in payload:
            events = payload.get("events") or []
            if not isinstance(events, list):
                raise ApiError("INVALID_BODY", "'events' must be a list", 422)
            if len(events) > MAX_BATCH:
                raise ApiError("BATCH_TOO_LARGE", f"Max {MAX_BATCH} events per request", 422)
            for entry in events:
                message = isinstance(entry, dict) and entry.get("message")
                if not message:
                    rejected += 1
                    continue
                _enqueue(source, message, entry.get("timestamp"))
                accepted += 1
        elif "message" in payload:
            if not payload.get("message"):
                raise ApiError("INVALID_BODY", "'message' must not be empty", 422)
            _enqueue(source, payload["message"], payload.get("timestamp"))
            accepted = 1
        else:
            raise ApiError("INVALID_BODY", "Expected a 'message' or 'events' field", 422)
    else:
        text = request.get_data(as_text=True) or ""
        lines = [line for line in text.splitlines() if line.strip()]
        if not lines:
            raise ApiError("INVALID_BODY", "Empty request body", 422)
        for line in lines[:MAX_BATCH]:
            _enqueue(source, line, None)
            accepted += 1
        rejected = max(0, len(lines) - MAX_BATCH)

    # In TESTING mode there are no background worker threads, so drain inline for determinism.
    if current_app.config.get("TESTING"):
        process_pending(current_app._get_current_object(), current_app.raw_queue, max_items=accepted + 1)

    return jsonify({"accepted": accepted, "rejected": rejected}), 202
