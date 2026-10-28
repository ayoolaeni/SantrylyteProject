"""Worker thread loop: drain RawQueue -> parse -> triage -> persist -> emit (§3.1).

Each pass takes whatever is already queued (up to 50 items, without waiting), processes
it and commits straight away. A worker never waits on the queue while it holds an open
transaction: under eventlet, psycopg calls block the whole process, so if worker A held a
row lock (say on a log_source's last_seen_at) while parked in queue.get(), worker B's
UPDATE of that row would block the event loop forever and freeze the entire server.

Every item runs inside its own SAVEPOINT, so one bad line is rolled back on its own
instead of taking the rest of the batch with it. If the commit itself fails (e.g. a
transient DB outage), the batch's raw messages are spilled back to disk so nothing is lost
and the batch is retried once the DB recovers (NFR4).

`process_pending` reuses the same per-item logic synchronously (no threads, immediate
commit) so tests and TESTING-mode ingestion can process the queue deterministically.
"""
import json
import logging
import os
import time
from datetime import datetime, timezone

logger = logging.getLogger("sentrylite.worker")

BATCH_SIZE = 50
BATCH_INTERVAL_SECONDS = 0.5


def _dlq_path(app):
    return os.path.join(app.config["SPILL_DIR"], "dead_letter.ndjson")


def _write_dlq(app, item, reason="unparseable"):
    try:
        with open(_dlq_path(app), "a", encoding="utf-8") as f:
            f.write(json.dumps({**item, "reason": reason}) + "\n")
    except OSError:
        logger.exception("failed to write dead-letter queue entry")


def _process_item(app, item):
    """Parse + triage + stage a single raw item on the current db.session. Returns emit callbacks."""
    from app.extensions import db
    from app.models.log_source import LogSource
    from app.parsers.registry import parse_raw_message
    from app.triage.engine import triage_and_persist

    source = None
    if item.get("source_id"):
        source = db.session.get(LogSource, item["source_id"])
    elif item.get("host_hint"):
        source = LogSource.query.filter_by(host_identifier=item["host_hint"], is_enabled=True).first()

    source_type = source.source_type if source else None
    normalised = parse_raw_message(item["raw_message"], source_type)

    if normalised is None:
        _write_dlq(app, item)
        return []

    if source is None and normalised.hostname:
        # Not matched by sender IP: a source may be registered under the hostname that
        # appears in the log line itself (e.g. registered from "Unregistered senders").
        source = LogSource.query.filter(
            db.func.lower(LogSource.host_identifier) == normalised.hostname.lower(),
            LogSource.is_enabled.is_(True),
        ).first()

    try:
        received_at = datetime.fromisoformat(item["received_at"])
    except (KeyError, ValueError):
        received_at = datetime.now(timezone.utc)
    normalised.received_at = received_at
    normalised.source_id = source.source_id if source else None

    if source is not None:
        source.last_seen_at = received_at
        db.session.add(source)

    event, incident = triage_and_persist(normalised, app.config, source_id=normalised.source_id)

    event_summary = event.to_summary()
    if source is not None:
        event_summary["source_name"] = source.name
    incident_summary = incident.to_summary() if incident else None
    grouped = bool(incident is not None and getattr(incident, "was_grouped", False))

    from app.realtime.events import (
        emit_alert_high,
        emit_incident_created,
        emit_incident_updated,
        emit_user_notification,
        queue_event_emit,
    )

    emits = [lambda es=event_summary: queue_event_emit(es)]
    if event.priority_level in ("HIGH", "CRITICAL") and event.status != "DISMISSED":
        emits.append(lambda es=event_summary: emit_alert_high(es))
    if incident_summary and grouped:
        emits.append(lambda inc=incident_summary: emit_incident_updated(inc))
    elif incident_summary:
        emits.append(lambda inc=incident_summary: emit_incident_created(inc))
    for note in getattr(event, "notifications", None) or []:
        emits.append(lambda n=note: emit_user_notification(n["user_id"], n))
    return emits


def process_pending(app, raw_queue, max_items=1000):
    """Synchronously drain up to `max_items`, committing once at the end. Used by tests / TESTING mode."""
    from app.extensions import db

    processed = 0
    pending_emits = []
    with app.app_context():
        while processed < max_items:
            item = raw_queue.get(timeout=0.05)
            if item is None:
                break
            try:
                pending_emits.extend(_process_item(app, item))
            except Exception:
                logger.exception("process_pending: failed to process item, writing to DLQ")
                db.session.rollback()
                _write_dlq(app, item, reason="processing_error")
                continue
            processed += 1
        if processed:
            db.session.commit()
            for fn in pending_emits:
                fn()
    return processed


def _process_batch(app, raw_queue, batch, worker_id):
    """Process `batch` in one transaction (a savepoint per item), commit, then emit."""
    from app.extensions import db

    committed_raw = []
    pending_emits = []
    for item in batch:
        try:
            with db.session.begin_nested():
                emits = _process_item(app, item)
        except Exception:
            logger.exception("worker %s: failed to process item, writing to DLQ", worker_id)
            _write_dlq(app, item, reason="processing_error")
            continue
        committed_raw.append(item)
        pending_emits.extend(emits)

    try:
        db.session.commit()
    except Exception:
        logger.exception("worker %s: commit failed, re-spilling %d item(s)", worker_id, len(committed_raw))
        db.session.rollback()
        for raw in committed_raw:
            raw_queue.put_back(raw)
        time.sleep(1)
        return

    for fn in pending_emits:
        try:
            fn()
        except Exception:
            logger.exception("worker %s: realtime emit failed", worker_id)


def worker_loop(app, raw_queue, stop_event, worker_id=0):
    from app.extensions import db

    with app.app_context():
        while not stop_event.is_set():
            # The only blocking wait, taken with no transaction open (see module docstring).
            item = raw_queue.get(timeout=BATCH_INTERVAL_SECONDS)
            if item is None:
                db.session.remove()
                raw_queue.drain_spill()
                continue

            batch = [item]
            while len(batch) < BATCH_SIZE:
                nxt = raw_queue.get_nowait()
                if nxt is None:
                    break
                batch.append(nxt)

            _process_batch(app, raw_queue, batch, worker_id)
            db.session.remove()
