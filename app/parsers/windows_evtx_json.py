"""JSON-exported Windows Security event log (e.g. from `wevtutil qe Security /f:json`)."""
import json
from datetime import datetime, timezone

from app.parsers.base import NormalisedEvent, Parser
from app.parsers.json_generic import JsonGenericParser

_EVENT_ID_MAP = {
    4624: "AUTH_SUCCESS",
    4625: "AUTH_FAILURE",
    4634: "AUTH_LOGOUT",
    4720: "ACCOUNT_CREATED",
    4725: "ACCOUNT_LOCKED",
    4728: "PRIVILEGE_CHANGE",
    4732: "PRIVILEGE_CHANGE",
    4735: "PRIVILEGE_CHANGE",
    4663: "FILE_ACCESS",
    4688: "PROCESS_EXEC",
    7036: "SERVICE_STOP",
    7040: "SERVICE_START",
    4657: "CONFIG_CHANGE",
}


class WindowsEvtxJsonParser(Parser):
    format_name = "WINDOWS_JSON"

    def detect(self, raw_message, source_type=None):
        try:
            obj = json.loads(raw_message)
        except (ValueError, TypeError):
            return False
        return isinstance(obj, dict) and "EventID" in obj

    def parse(self, raw_message, source_type=None):
        try:
            obj = json.loads(raw_message)
        except (ValueError, TypeError):
            return None
        if not isinstance(obj, dict) or "EventID" not in obj:
            return None

        try:
            event_id = int(obj["EventID"])
        except (TypeError, ValueError):
            event_id = None

        event_type = _EVENT_ID_MAP.get(event_id, "OTHER")
        ts = JsonGenericParser._parse_timestamp(obj.get("TimeCreated"))
        username = obj.get("TargetUserName") or obj.get("SubjectUserName")
        action = None
        if event_type == "AUTH_SUCCESS":
            action = "SUCCESS"
        elif event_type == "AUTH_FAILURE":
            action = "FAILURE"

        return NormalisedEvent(
            timestamp=ts,
            event_type=event_type,
            raw_message=raw_message,
            message=obj.get("Message") or f"EventID {event_id}",
            src_ip=obj.get("IpAddress") if obj.get("IpAddress") not in (None, "-") else None,
            username=username,
            hostname=obj.get("Computer"),
            action=action,
        )
