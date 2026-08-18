"""SQLite (dev/test) doesn't persist tzinfo on DateTime(timezone=True) columns, so a value
read back from the DB is naive even though every timestamp in this app is UTC by convention
(§5). Postgres (prod) preserves it correctly. `coerce_utc` makes comparisons against a fresh
`datetime.now(timezone.utc)` safe regardless of which database produced the value.
"""
from datetime import timezone


def coerce_utc(dt):
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt
