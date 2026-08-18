"""Worker thread loop: drain RawQueue -> parse -> triage -> persist -> emit (§3.1).

Commits happen in batches of up to 50 events or every 500ms, whichever comes first.
If a commit fails (e.g. a transient DB outage), the batch's raw messages are spilled
back to disk so nothing is lost and the batch is retried once the DB recovers (NFR4).

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
    incident_summary = incident.to_summary() if incident else None

    from app.realtime.events import emit_alert_high, emit_incident_created, queue_event_emit

    emits = [lambda es=event_summary: queue_event_emit(es)]
    if event.priority_level in ("HIGH", "CRITICAL"):
        emits.append(lambda es=event_summary: emit_alert_high(es))
    if incident_summary:
        emits.append(lambda inc=incident_summary: emit_incident_created(inc))
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


def worker_loop(app, raw_queue, stop_event, worker_id=0):
    from app.extensions import db

    with app.app_context():
        pending_raw = []
        pending_emits = []
        last_flush = time.monotonic()

        def flush():
            nonlocal pending_raw, pending_emits, last_flush
            if not pending_raw:
                last_flush = time.monotonic()
                return
            try:
                db.session.commit()
            except Exception:
                logger.exception("worker %s: commit failed, re-spilling %d item(s)", worker_id, len(pending_raw))
                db.session.rollback()
                for raw in pending_raw:
                    raw_queue.put_back(raw)
                pending_raw = []
                pending_emits = []
                last_flush = time.monotonic()
                time.sleep(1)
                return
            for fn in pending_emits:
                try:
                    fn()
                except Exception:
                    logger.exception("worker %s: realtime emit failed", worker_id)
            pending_raw = []
            pending_emits = []
            last_flush = time.monotonic()

        while not stop_event.is_set():
            item = raw_queue.get(timeout=0.5)

            if item is None:
                if (time.monotonic() - last_flush) >= BATCH_INTERVAL_SECONDS:
                    flush()
                raw_queue.drain_spill()
                continue

            try:
                pending_emits.extend(_process_item(app, item))
                pending_raw.append(item)
            except Exception:
                logger.exception("worker %s: failed to process item, writing to DLQ", worker_id)
                db.session.rollback()
                _write_dlq(app, item, reason="processing_error")
                continue

            if len(pending_raw) >= BATCH_SIZE or (time.monotonic() - last_flush) >= BATCH_INTERVAL_SECONDS:
                flush()

        flush()
