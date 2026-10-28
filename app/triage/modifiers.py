"""Contextual scoring modifiers, applied in the fixed order defined in §6.1."""
import dataclasses
import ipaddress
import threading
import time
from datetime import datetime

from app.triage.correlator import correlator

_DAY_CODES = ["MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN"]


class _TTLCache:
    """A tiny TTL cache so rule/asset edits are visible within RULE_CACHE_TTL_SECONDS without a restart."""

    def __init__(self, loader, ttl_seconds):
        self._loader = loader
        self._ttl = ttl_seconds
        self._value = None
        self._loaded_at = 0.0
        self._lock = threading.Lock()

    def get(self):
        with self._lock:
            if self._value is None or (time.monotonic() - self._loaded_at) > self._ttl:
                self._value = self._loader()
                self._loaded_at = time.monotonic()
            return self._value

    def invalidate(self):
        with self._lock:
            self._value = None
            self._loaded_at = 0.0


@dataclasses.dataclass
class _AssetView:
    """Detached, plain-data snapshot of a CriticalAsset row — see _RuleView in triage/engine.py
    for why the cache must not hold live ORM instances across requests."""

    identifier: str
    label: str
    criticality_multiplier: float


def _load_critical_assets():
    from app.models.critical_asset import CriticalAsset

    rows = CriticalAsset.query.filter_by(is_enabled=True).all()
    return [_AssetView(a.identifier, a.label, float(a.criticality_multiplier)) for a in rows]


_asset_cache = _TTLCache(_load_critical_assets, ttl_seconds=30)


def invalidate_asset_cache():
    _asset_cache.invalidate()


def match_critical_asset(dest_ip, hostname):
    """Return the most specific matching critical asset, or None.

    An exact IP or hostname wins over a network range, and a narrower range wins over a
    wider one, so a host that is also inside a protected subnet gets its own multiplier.
    """
    assets = _asset_cache.get()
    ip_obj = None
    if dest_ip:
        try:
            ip_obj = ipaddress.ip_address(dest_ip)
        except ValueError:
            ip_obj = None

    best, best_prefix = None, -1
    for asset in assets:
        identifier = asset.identifier
        if hostname and identifier.lower() == hostname.lower():
            return asset
        if dest_ip and identifier == dest_ip:
            return asset
        if ip_obj is not None and "/" in identifier:
            try:
                network = ipaddress.ip_network(identifier, strict=False)
            except ValueError:
                continue
            if ip_obj in network and network.prefixlen > best_prefix:
                best, best_prefix = asset, network.prefixlen
    return best


def is_outside_working_hours(timestamp: datetime, config) -> bool:
    day_code = _DAY_CODES[timestamp.weekday()]
    if day_code not in config["WORKING_DAYS"]:
        return True
    start_h, start_m = (int(x) for x in config["WORKING_HOURS_START"].split(":"))
    end_h, end_m = (int(x) for x in config["WORKING_HOURS_END"].split(":"))
    minutes = timestamp.hour * 60 + timestamp.minute
    return not (start_h * 60 + start_m <= minutes < end_h * 60 + end_m)


def repeat_count(src_ip, timestamp, window_seconds):
    if not src_ip:
        return 0
    key = ("__repeat__", src_ip)
    correlator.record(key, timestamp, window_seconds=window_seconds)
    return correlator.count_since(key, timestamp, window_seconds)
