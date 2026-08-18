"""Nginx combined access log format."""
import re
from datetime import datetime, timezone

from app.parsers.base import NormalisedEvent, Parser

_LINE_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+HTTP/[\d.]+"\s+'
    r'(?P<status>\d{3})\s+(?P<bytes>\d+|-)\s*(?:"(?P<referrer>[^"]*)"\s*"(?P<agent>[^"]*)")?'
)


class NginxAccessParser(Parser):
    format_name = "NGINX_ACCESS"

    def detect(self, raw_message, source_type=None):
        return bool(_LINE_RE.match(raw_message.strip()))

    def parse(self, raw_message, source_type=None):
        m = _LINE_RE.match(raw_message.strip())
        if not m:
            return None

        ts = self._parse_timestamp(m.group("ts"))
        status = int(m.group("status"))
        event_type = "WEB_ERROR" if status >= 400 else "WEB_REQUEST"
        raw_bytes = m.group("bytes")
        user = m.group("user")

        return NormalisedEvent(
            timestamp=ts,
            event_type=event_type,
            raw_message=raw_message,
            message=f'{m.group("method")} {m.group("path")} -> {status}',
            src_ip=m.group("ip"),
            username=None if user == "-" else user,
            http_method=m.group("method"),
            http_path=m.group("path"),
            http_status=status,
            bytes=None if raw_bytes == "-" else int(raw_bytes),
            user_agent=m.group("agent"),
        )

    @staticmethod
    def _parse_timestamp(text):
        try:
            return datetime.strptime(text, "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            return datetime.now(timezone.utc)
