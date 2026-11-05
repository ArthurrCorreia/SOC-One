"""Transformações de apresentação; não alteram regras nem registros persistidos."""
from datetime import datetime, timedelta
from collections import Counter

SEVERITY_ORDER = {'Crítica': 0, 'Alta': 1, 'Média': 2, 'Baixa': 3}


def within_period(rows, period):
    if period is None:
        return list(rows)
    start, end = period
    return [r for r in rows if start <= datetime.fromisoformat(r['timestamp']) <= end]


def search_text(row, query):
    return query.strip().casefold() in ' '.join(str(v) for v in row.values() if v is not None).casefold()


def event_results(rows, *, query='', ip='', hosts=(), user='', kinds=('failure', 'success', 'other')):
    return [e for e in rows if search_text(e, query) and ip.strip() in (e['ip'] or '')
            and (not hosts or e['host'] in hosts) and user.strip().casefold() in (e['username'] or '').casefold()
            and e['kind'] in kinds]


def alert_results(rows, *, query='', ip='', host='', statuses=(), severities=(), rules=(), classifications=(), archived=False, order='Prioridade'):
    result = [a for a in rows if search_text(a, query) and ip.strip() in a['ip']
              and host.strip().casefold() in a['host'].casefold()
              and a['status'] in statuses and a['severity'] in severities and a['rule'] in rules
              and a['classification'] in classifications and (a['active'] or archived)]
    if order == 'Mais antigos':
        return sorted(result, key=lambda a: (a['timestamp'], a['id']))
    if order == 'Mais recentes':
        return sorted(result, key=lambda a: (a['timestamp'], a['id']), reverse=True)
    return sorted(result, key=lambda a: (a['status'] == 'Encerrado', SEVERITY_ORDER.get(a['severity'], 9),
                                       -datetime.fromisoformat(a['timestamp']).timestamp(), a['id']))


def contextual_events(event, rows):
    """Relação observável por IP/host em ±5 min, sem afirmar causalidade."""
    if not event['ip']:
        return []
    instant = datetime.fromisoformat(event['timestamp'])
    return [e for e in rows if e['id'] != event['id'] and e['ip'] == event['ip'] and e['host'] == event['host']
            and abs(datetime.fromisoformat(e['timestamp']) - instant) <= timedelta(minutes=5)]


def operational_summary(events, alerts):
    current = [a for a in alerts if a['active']]
    opened = [a for a in current if a['status'] != 'Encerrado']
    return {
        'events': len(events), 'open': len(opened),
        'analysis': sum(a['status'] == 'Em análise' for a in current),
        'critical': sum(a['severity'] == 'Crítica' for a in opened),
        'escalated': sum(a['status'] == 'Escalonado' for a in current),
        'severity': dict(Counter(a['severity'] for a in opened)),
        'rules': dict(Counter(a['rule'] for a in current)),
    }


def detection_reason(metadata, evidence):
    detection = metadata.get('detection')
    if not detection:
        return 'Registro legado: condição detalhada indisponível. Consulte as linhas preservadas.'
    failures = [e for e in evidence if e['kind'] == 'failure']
    users = {e['username'] for e in failures if e['username']}
    scope = 'IP + host + usuário' if 'username' in detection['group_by'] else 'IP + host'
    reason = f"{len(failures)} falhas relacionadas; limiar de {detection['threshold']} em {detection['window_seconds']} s, por {scope}."
    if detection['event'] == 'success':
        reason += ' Disparo em autenticação bem-sucedida da mesma conta.'
    if 'distinct_users' in detection:
        reason += f" {len(users)} contas distintas; mínimo de {detection['distinct_users']}."
    return reason + ' Padrão suspeito, sujeito à validação de contexto.'
