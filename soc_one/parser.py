"""RFC3164 sem ano: o analista informa ano e deslocamento UTC."""
import hashlib
import ipaddress
import re
from datetime import datetime, timezone, timedelta
from .models import Event

HEADER = re.compile(r'^(?P<ts>\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}|\d{4}-\d\d-\d\dT\S+)\s+(?P<host>\S+)\s+(?P<service>[\w/-]+)(?:\[\d+\])?:\s*(?P<msg>.*)$')
AUTH = re.compile(r'^(Failed password|Accepted password|Accepted publickey) for (?:invalid user )?(\S+) from (\S+) port \d+(?:\s|$)')
MONTHS = {name: i for i, name in enumerate('Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec'.split(), 1)}


def parse_line(line: str, year: int, utc_offset: int = 0) -> Event | None:
    raw = line.strip()
    match = HEADER.match(raw)
    if not match:
        return None
    try:
        zone = timezone(timedelta(hours=utc_offset))
        stamp = match['ts']
        if stamp[0].isdigit():
            timestamp = datetime.fromisoformat(stamp.replace('Z', '+00:00'))
            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=zone)
        else:
            month, day, clock = stamp.split()
            h, m, s = map(int, clock.split(':'))
            timestamp = datetime(year, MONTHS[month], int(day), h, m, s, tzinfo=zone)
        timestamp = timestamp.astimezone(timezone.utc)
        auth = AUTH.match(match['msg']) if match['service'] == 'sshd' else None
        kind, ip, username = 'other', None, None
        if auth:
            ip = str(ipaddress.ip_address(auth[3]))
            username = auth[2]
            kind = 'failure' if auth[1].startswith('Failed') else 'success'
        elif match['service'] == 'sshd' and match['msg'].startswith(('Failed password', 'Accepted password', 'Accepted publickey')):
            return None
        event_id = hashlib.sha256((timestamp.isoformat() + '|' + raw).encode()).hexdigest()
        return Event(event_id, timestamp, match['host'], ip, username, match['service'], kind, raw)
    except (ValueError, KeyError, OverflowError):
        return None


def parse_text(text: str, year: int, utc_offset: int = 0) -> tuple[list[Event], int]:
    events, invalid = [], 0
    for line in text.splitlines():
        if not line.strip():
            continue
        event = parse_line(line, year, utc_offset)
        if event:
            events.append(event)
        else:
            invalid += 1
    return events, invalid
