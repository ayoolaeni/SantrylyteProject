"""Parser abstract base and the common normalised event shape (FR2)."""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


@dataclass
class NormalisedEvent:
    timestamp: datetime
    event_type: str
    raw_message: str
    message: Optional[str] = None
    src_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    username: Optional[str] = None
    hostname: Optional[str] = None
    protocol: Optional[str] = None
    action: Optional[str] = None
    http_method: Optional[str] = None
    http_path: Optional[str] = None
    http_status: Optional[int] = None
    bytes: Optional[int] = None
    user_agent: Optional[str] = None
    source_id: Optional[int] = None
    received_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class Parser(ABC):
    """One Parser subclass per log family. `detect` decides whether this parser applies."""

    format_name: str = "base"

    @abstractmethod
    def detect(self, raw_message: str, source_type: Optional[str] = None) -> bool:
        """Return True if this parser can handle the given raw line."""

    @abstractmethod
    def parse(self, raw_message: str, source_type: Optional[str] = None) -> Optional[NormalisedEvent]:
        """Return a NormalisedEvent, or None if the line cannot be parsed."""
