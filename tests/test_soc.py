from datetime import datetime, timedelta, timezone
from pathlib import Path
import json
import pytest
from soc_one.parser import parse_line, parse_text
from soc_one.rules import detect
from soc_one.storage import Store, markdown_report


def line(second=0, kind='Failed password', ip='198.51.100.1', user='ana'):
    stamp = (datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=second)).isoformat()
    return f'{stamp} lab sshd[1]: {kind} for {user} from {ip} port 1234 ssh2'


def events(seconds):
    return [parse_line(line(s), 2026) for s in seconds]


def test_parser_normalizes():
    event = parse_line('Nov  3 09:00:00 lab sshd[2]: Failed password for invalid user root from 2001:db8::1 port 22 ssh2', 2026, -3)
    assert (event.timestamp.hour, event.ip, event.username, event.kind) == (12, '2001:db8::1', 'root', 'failure')


@pytest.mark.parametrize('raw', ['garbage', line(ip='999.1.2.3'), 'Feb 30 00:00:00 lab sshd: hello', line().replace('00:00:00', '25:00:00')])
def test_invalid(raw):
    assert parse_line(raw, 2026) is None


def test_normal_and_publickey():
    assert parse_line(line(kind='Accepted publickey'), 2026).kind == 'success'
    assert parse_line('Nov 3 09:00:00 lab CRON[1]: normal', 2026).kind == 'other'
    assert parse_text('\ninvalid\n' + line(), 2026)[1] == 1


@pytest.mark.parametrize('seconds,expected', [([0, 60, 120, 180, 300], 1), ([0, 60, 120, 180, 301], 0), ([0, 1, 2, 3], 0)])
def test_window(seconds, expected):
    assert len(detect(events(seconds))) == expected
    assert detect(events(seconds)) == detect(list(reversed(events(seconds))))


@pytest.mark.parametrize('success,expected', [(300, 1), (301, 0)])
def test_success_window(success, expected):
    sequence = events([0, 1, 2]) + [parse_line(line(success, 'Accepted password'), 2026)]
    assert len(detect(sequence)) == expected


def test_no_cross_ip_correlation():
    sequence = events([0, 1, 2, 3]) + [parse_line(line(4, ip='192.0.2.1'), 2026)]
    assert detect(sequence) == []
    assert detect([parse_line(line(5, 'Accepted password'), 2026)] + events([6, 7, 8])) == []


def test_persistence_dedup_and_late_events(tmp_path):
    path = tmp_path / 'test.db'
    store = Store(path)
    success = line(60, 'Accepted password')
    store.import_text(success, 2026)
    result = store.import_text('\n'.join(line(s) for s in [0, 1, 2]), 2026)
    assert result['novos_alertas'] == 1
    alert = store.alerts()[0]
    store.triage(alert['id'], 'Encerrado', 'Usuário validou a atividade', 'Senha digitada incorretamente')
    assert store.import_text(success, 2026)['inseridos'] == 0
    reopened = Store(path)
    assert reopened.alerts()[0]['status'] == 'Encerrado'
    assert len(reopened.report(alert['id'])['evidencias']) == 4
    assert 'Encerrado' in markdown_report(reopened.report(alert['id']))
    assert json.loads(json.dumps(reopened.report(alert['id'])))['alerta']['notes']
    with pytest.raises(ValueError):
        store.triage(alert['id'], 'Encerrado', '', ' ')
    with pytest.raises(ValueError):
        store.triage(alert['id'], 'inválido', '', '')
    with pytest.raises(ValueError):
        store.triage('missing', 'Novo', '', '')


def test_demo(tmp_path):
    store = Store(tmp_path / 'demo.db')
    demo = Path('samples/demo.log').read_text()
    result = store.import_text(demo, 2026)
    assert result == {'inseridos': 16, 'ignorados': 1, 'repetidos': 0, 'novos_alertas': 3}
    assert store.import_text(demo, 2026)['novos_alertas'] == 0
    assert len(store.events()) == 16
    assert len(store.alerts()) == 3


def test_late_evidence_preserves_triage(tmp_path):
    store = Store(tmp_path / 'late.db')
    store.import_text('\n'.join(line(s) for s in [0, 10, 20]) + '\n' + line(60, 'Accepted password'), 2026)
    key = store.alerts()[0]['id']
    store.triage(key, 'Em análise', 'Validar origem', '')
    store.import_text(line(30), 2026)
    assert len(store.report(key)['evidencias']) == 5
    assert store.alerts()[0]['notes'] == 'Validar origem'
