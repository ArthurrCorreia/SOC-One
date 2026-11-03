"""Correlação determinística, por horário do evento, com janela inclusiva."""
import hashlib
from collections import defaultdict, deque
from datetime import timedelta
from .catalog import RULES
from .models import Alert, Event


def detect(events: list[Event]) -> list[Alert]:
    windows = defaultdict(deque)
    alerts = []
    unique = {event.id: event for event in events}
    longest_window = max(r['detection']['window_seconds'] for r in RULES.values())
    # Empates de segundo não provam causalidade: falhas precedem sucessos.
    for event in sorted(unique.values(), key=lambda e: (e.timestamp, e.kind != 'failure', e.id)):
        if not event.ip or event.service != 'sshd' or event.kind not in ('failure', 'success'):
            continue
        window = windows[event.ip, event.host]
        while window and event.timestamp - window[0].timestamp > timedelta(seconds=longest_window):
            window.popleft()
        if event.kind == 'failure':
            window.append(event)
        for rule_id, metadata in RULES.items():
            definition = metadata['detection']
            if event.kind != definition['event']:
                continue
            failures = [e for e in window
                        if event.timestamp - e.timestamp <= timedelta(seconds=definition['window_seconds'])
                        and ('username' not in definition['group_by'] or e.username == event.username)]
            if len(failures) < definition['threshold']:
                continue
            if len({e.username for e in failures if e.username}) < definition.get('distinct_users', 1):
                continue
            key = hashlib.sha256(f'{rule_id}|{event.id}'.encode()).hexdigest()
            evidence = [e.id for e in failures]
            if event.kind == 'success':
                evidence.append(event.id)
            alerts.append(Alert(key, rule_id, metadata['severity'], event.ip, event.timestamp, tuple(evidence), event.host))
    return alerts
