"""Format detection + dispatch. Adding a parser touches only this file + parsers/ (NFR6)."""
from app.parsers.apache_access import ApacheAccessParser
from app.parsers.auth_log import AuthLogParser
from app.parsers.json_generic import JsonGenericParser
from app.parsers.nginx_access import NginxAccessParser
from app.parsers.syslog_rfc3164 import Rfc3164Parser
from app.parsers.syslog_rfc5424 import Rfc5424Parser
from app.parsers.windows_evtx_json import WindowsEvtxJsonParser

# Explicit source_type -> parser, used when the log_source declares its format.
_BY_SOURCE_TYPE = {
    "AUTH_LOG": AuthLogParser(),
    "NGINX_ACCESS": NginxAccessParser(),
    "APACHE_ACCESS": ApacheAccessParser(),
    "JSON_GENERIC": JsonGenericParser(),
    "WINDOWS_JSON": WindowsEvtxJsonParser(),
    "SYSLOG": None,  # resolved by auto-detection below (RFC5424 vs RFC3164)
}

# Auto-detection order matters: most specific/unambiguous formats first.
_AUTO_DETECT_ORDER = [
    WindowsEvtxJsonParser(),
    JsonGenericParser(),
    Rfc5424Parser(),
    Rfc3164Parser(),
    NginxAccessParser(),
    AuthLogParser(),
]


def parse_raw_message(raw_message, source_type=None):
    """Parse `raw_message` into a NormalisedEvent, or return None (caller writes to DLQ)."""
    raw_message = (raw_message or "").strip()
    if not raw_message:
        return None

    parser = _BY_SOURCE_TYPE.get(source_type) if source_type else None
    if parser is not None:
        result = parser.parse(raw_message, source_type)
        if result is not None:
            return result
        # Declared format didn't match this line; fall through to auto-detection.

    for candidate in _AUTO_DETECT_ORDER:
        if candidate.detect(raw_message, source_type):
            result = candidate.parse(raw_message, source_type)
            if result is not None:
                return result

    return None
