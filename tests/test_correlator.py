from datetime import datetime, timedelta, timezone

from app.triage.correlator import Correlator


def test_count_since_counts_within_window():
    c = Correlator(max_keys=100)
    t0 = datetime(2024, 1, 1, tzinfo=timezone.utc)
    for i in range(3):
        c.record(("k",), t0 + timedelta(seconds=i))
    assert c.count_since(("k",), t0 + timedelta(seconds=2), window_seconds=60) == 3


def test_entries_outside_window_are_pruned():
    c = Correlator(max_keys=100)
    t0 = datetime(2024, 1, 1, tzinfo=timezone.utc)
    c.record(("k",), t0)
    c.record(("k",), t0 + timedelta(seconds=200))
    # Querying 60s after the second event: the first (200s earlier) should have been pruned.
    assert c.count_since(("k",), t0 + timedelta(seconds=260), window_seconds=60) == 1


def test_distinct_count_counts_unique_values_only():
    c = Correlator(max_keys=100)
    t0 = datetime(2024, 1, 1, tzinfo=timezone.utc)
    c.record(("k",), t0, distinct_value=22)
    c.record(("k",), t0 + timedelta(seconds=1), distinct_value=22)
    c.record(("k",), t0 + timedelta(seconds=2), distinct_value=80)
    assert c.distinct_count_since(("k",), t0 + timedelta(seconds=2), window_seconds=60) == 2


def test_sweep_removes_fully_stale_keys():
    c = Correlator(max_keys=100)
    t0 = datetime(2024, 1, 1, tzinfo=timezone.utc)
    c.record(("k",), t0, window_seconds=60)
    assert ("k",) in c._state
    c.sweep(t0 + timedelta(seconds=120), default_window_seconds=60)
    assert ("k",) not in c._state


def test_lru_eviction_when_over_capacity():
    c = Correlator(max_keys=2)
    t0 = datetime(2024, 1, 1, tzinfo=timezone.utc)
    c.record(("a",), t0)
    c.record(("b",), t0)
    c.record(("c",), t0)  # should evict the least-recently-used key ("a")
    assert len(c._state) == 2
    assert ("a",) not in c._state
    assert ("c",) in c._state


def test_reset_clears_all_state():
    c = Correlator(max_keys=100)
    t0 = datetime(2024, 1, 1, tzinfo=timezone.utc)
    c.record(("k",), t0)
    c.reset()
    assert c.count_since(("k",), t0, window_seconds=60) == 0
