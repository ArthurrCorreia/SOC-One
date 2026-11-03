from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class Event:
    id: str
    timestamp: datetime
    host: str
    ip: str | None
    username: str | None
    service: str
    kind: str
    raw: str


@dataclass(frozen=True)
class Alert:
    id: str
    rule: str
    severity: str
    ip: str
    timestamp: datetime
    evidence: tuple[str, ...]
    host: str = ''
