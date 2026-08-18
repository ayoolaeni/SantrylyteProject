"""RFC 5424 syslog: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG"""
import re
from datetime import datetime, timezone

from app.parsers.base import NormalisedEvent, Parser

_LINE_RE = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<ver>\d)\s+(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<app>\S+)\s+"
    r"(?P<procid>\S+)\s+(?P<msgid>\S+)\s+(?P<sd>(?:\[.*?\]|-))\s*(?P<msg>.*)$"
)


class Rfc5424Parser(Parser):
    format_name = "SYSLOG_RFC5424"

    def detect(self, raw_message, source_type=None):
        return bool(_LINE_RE.match(raw_message.strip()))

    def parse(self, raw_message, source_type=None):
        m = _LINE_RE.match(raw_message.strip())
        if not m:
            return None

        try:
            ts = datetime.fromisoformat(m.group("ts").replace("Z", "+00:00"))
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
        except ValueError:
            ts = datetime.now(timezone.utc)

        msg = m.group("msg").strip()
        app = m.group("app")
        event_type = "OTHER"
        low = msg.lower()
        if "failed" in low and ("password" in low or "auth" in low):
            event_type = "AUTH_FAILURE"
        elif "accepted" in low and "password" in low:
            event_type = "AUTH_SUCCESS"

        return NormalisedEvent(
            timestamp=ts,
            event_type=event_type,
            raw_message=raw_message,
            message=msg,
            hostname=m.group("host") if m.group("host") != "-" else None,
            protocol=app if app != "-" else None,
        )
