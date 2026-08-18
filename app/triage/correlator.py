"""In-memory sliding-window state for rule correlation (§6.4).

State is a dict of deque[(timestamp, distinct_value)] keyed by (rule_id, group_value),
pruned on every access and evicted LRU-style once CORRELATOR_MAX_KEYS is exceeded.
State loss on restart is acceptable and is documented in DECISIONS.md.
"""
import threading
from collections import OrderedDict, deque
from datetime import timedelta


class Correlator:
    def __init__(self, max_keys=50000):
        self.max_keys = max_keys
        self._state = OrderedDict()  # key -> deque[(timestamp, distinct_value)]
        self._lock = threading.Lock()

    def record(self, key, timestamp, distinct_value=None, window_seconds=3600):
        with self._lock:
            dq = self._state.get(key)
            if dq is None:
                dq = deque()
                self._state[key] = dq
            else:
                self._state.move_to_end(key)
            dq.append((timestamp, distinct_value))
            self._prune(dq, timestamp, window_seconds)
            self._evict_if_needed()

    def count_since(self, key, timestamp, window_seconds):
        with self._lock:
            dq = self._state.get(key)
            if dq is None:
                return 0
            self._prune(dq, timestamp, window_seconds)
            return len(dq)

    def distinct_count_since(self, key, timestamp, window_seconds):
        with self._lock:
            dq = self._state.get(key)
            if dq is None:
                return 0
            self._prune(dq, timestamp, window_seconds)
            return len({v for _, v in dq if v is not None})

    def sweep(self, now, default_window_seconds=3600):
        """Periodic maintenance pass (called every 60s by a background thread)."""
        with self._lock:
            empty_keys = []
            for key, dq in self._state.items():
                self._prune(dq, now, default_window_seconds)
                if not dq:
                    empty_keys.append(key)
            for key in empty_keys:
                del self._state[key]

    def reset(self):
        with self._lock:
            self._state.clear()

    @staticmethod
    def _prune(dq, now, window_seconds):
        cutoff = now - timedelta(seconds=window_seconds)
        while dq and dq[0][0] < cutoff:
            dq.popleft()

    def _evict_if_needed(self):
        while len(self._state) > self.max_keys:
            self._state.popitem(last=False)  # evict least-recently-used


correlator = Correlator()
