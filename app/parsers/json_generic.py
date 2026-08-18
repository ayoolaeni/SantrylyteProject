"""Generic JSON application log: one JSON object per line, fields map ~directly onto the schema."""
import json
from datetime import datetime, timezone

from app.models.event import EVENT_TYPES
from app.parsers.base import NormalisedEvent, Parser


class JsonGenericParser(Parser):
    format_name = "JSON_GENERIC"

    def detect(self, raw_message, source_type=None):
        try:
            obj = json.loads(raw_message)
        except (ValueError, TypeError):
            return False
        return isinstance(obj, dict)

    def parse(self, raw_message, source_type=None):
        try:
            obj = json.loads(raw_message)
        except (ValueError, TypeError):
            return None
        if not isinstance(obj, dict):
            return None

        ts = self._parse_timestamp(obj.get("timestamp") or obj.get("ts") or obj.get("time"))
        event_type = obj.get("event_type", "OTHER")
        if event_type not in EVENT_TYPES:
            event_type = "OTHER"

        return NormalisedEvent(
            timestamp=ts,
            event_type=event_type,
            raw_message=raw_message,
            message=obj.get("message") or obj.get("msg"),
            src_ip=obj.get("src_ip") or obj.get("ip"),
            dest_ip=obj.get("dest_ip"),
            dest_port=self._as_int(obj.get("dest_port")),
            username=obj.get("username") or obj.get("user"),
            hostname=obj.get("hostname") or obj.get("host"),
            protocol=obj.get("protocol"),
            action=obj.get("action"),
            http_method=obj.get("http_method") or obj.get("method"),
            http_path=obj.get("http_path") or obj.get("path"),
            http_status=self._as_int(obj.get("http_status") or obj.get("status")),
            bytes=self._as_int(obj.get("bytes")),
            user_agent=obj.get("user_agent"),
        )

    @staticmethod
    def _as_int(value):
        try:
            return int(value) if value is not None else None
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _parse_timestamp(value):
        if not value:
            return datetime.now(timezone.utc)
        try:
            ts = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            return ts
        except ValueError:
            return datetime.now(timezone.utc)
