"""Bounded RawQueue with a disk spill buffer so a full queue never drops data (NFR4).

The ingestion->triage handoff is intentionally just this class's public interface
(put/get/drain_spill) so a Redis-backed queue could later be dropped in without
touching the syslog listeners, the ingest API, or the worker loop (§2 background queue note).
"""
import json
import os
import queue
import threading
from datetime import datetime


class RawQueue:
    def __init__(self, maxsize, spill_dir):
        self._q = queue.Queue(maxsize=maxsize)
        self.spill_dir = spill_dir
        self.spill_path = os.path.join(spill_dir, "spill.ndjson")
        self._spill_lock = threading.Lock()
        os.makedirs(spill_dir, exist_ok=True)

    def put(self, source_id, raw_message, received_at=None, host_hint=None):
        item = {
            "source_id": source_id,
            "raw_message": raw_message,
            "received_at": (received_at or datetime.now().astimezone()).isoformat(),
            "host_hint": host_hint,
        }
        try:
            self._q.put_nowait(item)
            return True
        except queue.Full:
            self._spill(item)
            return False

    def put_back(self, item):
        """Re-queue an already-built item (e.g. after a failed commit) straight to the spill file."""
        self._spill(item)

    def _spill(self, item):
        with self._spill_lock:
            with open(self.spill_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(item) + "\n")

    def get(self, timeout=1):
        try:
            return self._q.get(timeout=timeout)
        except queue.Empty:
            return None

    def qsize(self):
        return self._q.qsize()

    def has_spill(self):
        return os.path.exists(self.spill_path) and os.path.getsize(self.spill_path) > 0

    def drain_spill(self, max_items=500):
        """Move spilled items back onto the in-memory queue while there is room. Returns count moved."""
        with self._spill_lock:
            if not os.path.exists(self.spill_path):
                return 0
            with open(self.spill_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
            if not lines:
                return 0

            moved = 0
            remaining = []
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                if moved >= max_items:
                    remaining.append(line)
                    continue
                try:
                    item = json.loads(line)
                except ValueError:
                    continue
                try:
                    self._q.put_nowait(item)
                    moved += 1
                except queue.Full:
                    remaining.append(line)

            with open(self.spill_path, "w", encoding="utf-8") as f:
                for line in remaining:
                    f.write(line + "\n")
            return moved
