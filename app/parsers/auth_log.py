"""Linux /var/log/auth.log and /var/log/secure (sshd, sudo, useradd, usermod, passwd)."""
import re
from datetime import datetime, timezone

from app.parsers.base import NormalisedEvent, Parser
from app.parsers.syslog_rfc3164 import _MONTHS

_LINE_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
    r"(?P<tag>[\w\-.]+?)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
)
_USER_FROM_RE = re.compile(r"for\s+(?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})")
_SUDO_USER_RE = re.compile(r"USER=(?P<target>\S+)")
_SUDO_ACTOR_RE = re.compile(r"^\s*(?P<actor>\S+)\s*:")
_NEWUSER_RE = re.compile(r"name=(?P<name>[\w\-.]+)")
_GROUP_ADD_RE = re.compile(r"add\s+'(?P<user>[^']+)'\s+to\s+group\s+'(?P<group>[^']+)'")

_ADMIN_GROUPS = {"sudo", "wheel", "admin", "administrators"}


class AuthLogParser(Parser):
    format_name = "AUTH_LOG"

    def detect(self, raw_message, source_type=None):
        if source_type == "AUTH_LOG":
            return True
        m = _LINE_RE.match(raw_message.strip())
        if not m:
            return False
        return m.group("tag").lower() in (
            "sshd", "sudo", "useradd", "usermod", "passwd", "login", "su", "userdel",
        )

    def parse(self, raw_message, source_type=None):
        m = _LINE_RE.match(raw_message.strip())
        if not m:
            return None

        tag = m.group("tag").lower()
        msg = m.group("msg").strip()
        ts = self._parse_timestamp(m.group("ts"))
        event_type = "OTHER"
        action = None
        username = None
        src_ip = None

        if tag == "sshd":
            um = _USER_FROM_RE.search(msg)
            if um:
                username, src_ip = um.group("user"), um.group("ip")
            low = msg.lower()
            if "failed password" in low or "authentication failure" in low:
                event_type, action = "AUTH_FAILURE", "FAILURE"
            elif "accepted password" in low or "accepted publickey" in low:
                event_type, action = "AUTH_SUCCESS", "SUCCESS"
            elif "disconnected from" in low or "session closed" in low:
                event_type = "AUTH_LOGOUT"
        elif tag == "sudo":
            event_type = "PRIVILEGE_CHANGE"
            tm = _SUDO_USER_RE.search(msg)
            am = _SUDO_ACTOR_RE.search(msg)
            username = am.group("actor") if am else None
            if tm:
                msg = f"{msg} (target={tm.group('target')})"
        elif tag == "useradd":
            event_type = "ACCOUNT_CREATED"
            nm = _NEWUSER_RE.search(msg)
            username = nm.group("name") if nm else None
        elif tag == "usermod":
            gm = _GROUP_ADD_RE.search(msg)
            if gm and gm.group("group").lower() in _ADMIN_GROUPS:
                event_type = "PRIVILEGE_CHANGE"
                username = gm.group("user")
        elif tag == "passwd" and "locked" in msg.lower():
            event_type = "ACCOUNT_LOCKED"

        return NormalisedEvent(
            timestamp=ts,
            event_type=event_type,
            raw_message=raw_message,
            message=msg,
            hostname=m.group("host"),
            username=username,
            src_ip=src_ip,
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
