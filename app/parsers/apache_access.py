"""Apache combined access log format (same wire format as nginx combined)."""
from app.parsers.nginx_access import NginxAccessParser


class ApacheAccessParser(NginxAccessParser):
    format_name = "APACHE_ACCESS"
