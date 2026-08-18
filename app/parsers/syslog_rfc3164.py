"""RFC 3164 (BSD) syslog: <PRI>Mmm dd hh:mm:ss host tag: message"""
import re
from datetime import datetime, timezone

from app.parsers.base import NormalisedEvent, Parser

_LINE_RE = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<tag>[^:]+):\s?(?P<msg>.*)$"
)
_IP_RE = re.compile(r"from\s+(\d{1,3}(?:\.\d{1,3}){3})")
_MONTHS = {m: i + 1 for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
)}


class Rfc3164Parser(Parser):
    format_name = "SYSLOG_RFC3164"

    def detect(self, raw_message, source_type=None):
        return bool(_LINE_RE.match(raw_message.strip()))

    def parse(self, raw_message, source_type=None):
        m = _LINE_RE.match(raw_message.strip())
        if not m:
            return None

        ts = self._parse_timestamp(m.group("ts"))
        tag = m.group("tag").strip()
        msg = m.group("msg").strip()
        event_type = "OTHER"
        action = None

        low = msg.lower()
        if "sshd" in tag.lower() or "ssh" in tag.lower():
            if "failed password" in low or "authentication failure" in low:
                event_type, action = "AUTH_FAILURE", "FAILURE"
            elif "accepted password" in low or "accepted publickey" in low:
                event_type, action = "AUTH_SUCCESS", "SUCCESS"
        elif "sudo" in tag.lower():
            event_type = "PRIVILEGE_CHANGE"
        elif "systemd" in tag.lower():
            if "stopped" in low:
                event_type = "SERVICE_STOP"
            elif "started" in low:
                event_type = "SERVICE_START"

        ip_match = _IP_RE.search(msg)

        return NormalisedEvent(
            timestamp=ts,
            event_type=event_type,
            raw_message=raw_message,
            message=msg,
            hostname=m.group("host"),
            src_ip=ip_match.group(1) if ip_match else None,
            action=action,
        )

    @staticmethod
    def _parse_timestamp(text):
        try:
            month_str, day, time_str = text.split(None, 2)
            now = datetime.now(timezone.utc)
            month = _MONTHS.get(month_str, now.month)
            hour, minute, second = (int(x) for x in time_str.split(":"))
            return datetime(now.year, month, int(day), hour, minute, second, tzinfo=timezone.utc)
        except Exception:
            return datetime.now(timezone.utc)
