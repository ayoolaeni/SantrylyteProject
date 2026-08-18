"""Lightweight in-process throughput smoke test for the triage engine itself.

This is deliberately small and fast (part of the regular `pytest` run). The full
NFR1/NFR2 latency & sustained-throughput measurement against a running server is
`tools/load_test.py`, whose results are recorded in RESULTS.md.
"""
import time
from datetime import datetime, timezone

from app.parsers.base import NormalisedEvent
from app.triage.engine import score_event


def test_triage_engine_scores_1000_events_quickly(app, db):
    with app.app_context():
        events = [
            NormalisedEvent(
                timestamp=datetime(2024, 6, 4, 12, 0, 0, tzinfo=timezone.utc),
                event_type="WEB_REQUEST",
                raw_message="raw",
                src_ip=f"203.0.113.{i % 255}",
                http_status=200,
            )
            for i in range(1000)
        ]

        start = time.perf_counter()
        for event in events:
            score_event(event, app.config, rules=[])
        elapsed = time.perf_counter() - start

        # 1000 pure-Python scoring calls (no DB writes) should comfortably clear
        # the >=100 events/sec sustained-throughput bar (NFR2) with wide headroom.
        assert elapsed < 5.0, f"scoring 1000 events took {elapsed:.2f}s"
