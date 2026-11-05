"""Filtros, prioridade e contexto exibidos, sem mutação dos registros de origem."""
from copy import deepcopy
from datetime import datetime, timezone

from soc_one.catalog import RULES
from soc_one.demo import DemoWorkspace
from soc_one.storage import STATUSES, CLASSIFICATIONS
from soc_one.viewmodels import (
    alert_results, event_results, within_period, contextual_events,
    operational_summary, detection_reason,
)


def event(key, timestamp='2026-11-03T10:00:00+00:00', **overrides):
    return dict(id=key, timestamp=timestamp, ip='192.0.2.1', host='host-a',
                username='alice', kind='failure', raw='Failed password for alice') | overrides


def alert(key, **overrides):
    return dict(id=key, timestamp='2026-11-03T10:00:00+00:00', ip='192.0.2.1', host='host-a',
                status='Novo', severity='Alta', rule='SSH-001', classification='Não classificado', active=1) | overrides


def filter_alerts(rows, **overrides):
    options = dict(statuses=STATUSES, classifications=CLASSIFICATIONS, severities=['Alta', 'Crítica'], rules=list(RULES))
    return alert_results(rows, **(options | overrides))


def test_literal_search_combines_filters_without_mutation():
    rows = [event('a'), event('b', username='bob'), event('c', kind='success'),
            event('d', host='host-b'), event('e', ip='198.51.100.1'), event('f', ip=None)]
    previous = deepcopy(rows)
    assert [r['id'] for r in event_results(rows, query='FAILED PASSWORD', user='Ali', hosts=['host-a'], ip='192.', kinds=['failure'])] == ['a']
    assert event_results(rows, query='alice OR bob') == []
    assert event_results(rows, kinds=[]) == []
    assert rows == previous


def test_period_inclusive_utc_and_empty_result():
    instant = datetime(2026, 11, 3, 10, tzinfo=timezone.utc)
    rows = [event('a'), event('b', '2026-11-03T07:00:00-03:00'), event('c', '2026-11-03T10:00:01+00:00')]
    assert [r['id'] for r in within_period(rows, (instant, instant))] == ['a', 'b']
    assert within_period([], (instant, instant)) == []
    assert within_period(rows, None) == rows


def test_alert_priority_filters_and_historical_toggle():
    rows = [alert('closed', severity='Crítica', status='Encerrado'), alert('high'),
            alert('critical', severity='Crítica'), alert('historical', active=0),
            alert('old', timestamp='2026-11-03T09:00:00+00:00')]
    before = deepcopy(rows)
    assert [a['id'] for a in filter_alerts(rows)] == ['critical', 'high', 'old', 'closed']
    assert len(filter_alerts(rows, archived=True)) == 5
    assert filter_alerts(rows, statuses=[]) == []
    assert filter_alerts(rows, query='CRITICAL', host='HOST-A', ip='192.', severities=['Crítica'])[0]['id'] == 'critical'
    assert filter_alerts(rows, order='Mais antigos')[0]['id'] == 'old'
    assert filter_alerts(rows, order='Mais recentes')[-1]['id'] == 'old'
    assert rows == before


def test_related_events_require_ip_host_and_time_window():
    selected = event('selected')
    rows = [selected, event('edge', '2026-11-03T10:05:00+00:00'),
            event('before', '2026-11-03T09:55:00+00:00'), event('late', '2026-11-03T10:05:01+00:00'),
            event('otherhost', host='host-b'), event('otherip', ip='198.51.100.1')]
    assert [e['id'] for e in contextual_events(selected, rows)] == ['edge', 'before']
    assert contextual_events(event('none', ip=None), rows) == []


def test_metrics_use_only_active_and_open_records():
    rows = [alert('new', severity='Crítica'), alert('closed', severity='Crítica', status='Encerrado'),
            alert('analysis', status='Em análise'), alert('escalated', status='Escalonado'),
            alert('archived', active=0, severity='Crítica')]
    summary = operational_summary([event('a')], rows)
    assert summary == dict(events=1, open=3, analysis=1, critical=1, escalated=1,
                           severity={'Crítica': 1, 'Alta': 2}, rules={'SSH-001': 4})
    assert operational_summary([], [])['open'] == 0


def test_detection_reason_uses_observed_evidence_and_preserved_metadata():
    evidence = [event('a'), event('b', username='bob'), event('c', username='charlie')]
    metadata = deepcopy(RULES['SSH-003'])
    metadata['detection']['threshold'] = 7
    reason = detection_reason(metadata, evidence)
    assert '3 falhas relacionadas' in reason
    assert 'limiar de 7' in reason
    assert '3 contas distintas' in reason
    assert 'condição detalhada indisponível' in detection_reason({}, evidence)


def test_current_evidence_preserves_saved_report_snapshot(tmp_path):
    store, _ = DemoWorkspace(tmp_path).open('suspicious_login')
    key = store.alerts()[0]['id']
    store.save_report(key, {'analise': 'Cópia antes da chegada tardia'})
    before = store.report(key)
    raw = 'Nov  3 11:01:30 auth-server sshd[810]: Failed password for deploy from 203.0.113.30 port 44001 ssh2'
    # Reutiliza a identidade do host/conta do cenário para acrescentar uma evidência real.
    original = before['dados_objetivos']['eventos'][0]
    raw = raw.replace('auth-server', original['host']).replace('deploy', original['username']).replace('203.0.113.30', original['ip'])
    stamp = datetime.fromisoformat(original['timestamp'])
    raw = raw.replace('11:01:30', stamp.strftime('%H:%M:%S'))
    store.import_text(raw, 2026, source='chegada-tardia.log')
    current = store.evidence(key)
    saved = store.report(key)
    assert len(current['eventos']) == len(before['evidencias']) + 1
    assert any(s['source'] == 'chegada-tardia.log' for s in current['fontes'])
    assert saved['dados_objetivos'] == before['dados_objetivos']
    assert saved['investigacao'] == before['investigacao']
    assert not saved['documento']['dados_objetivos_atualizados']
