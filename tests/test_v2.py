import hashlib
import json
import sqlite3
from dataclasses import asdict
from pathlib import Path

import pytest

from soc_one.analytics import metrics
from soc_one.catalog import RULES
from soc_one.parser import parse_line
from soc_one.reports import REPORT_FIELDS, markdown_report
from soc_one.rules import detect
from soc_one.storage import Store
from test_soc import events, line


def seed(store):
    store.import_text('\n'.join(line(s) for s in [0, 10, 20]) + '\n' + line(60, 'Accepted password'), 2026, source='auth.log')
    return store.alerts()[0]['id']


def test_host_and_user_isolation():
    assert detect(events([0, 1, 2, 3]) + [parse_line(line(4).replace(' lab ', ' other '), 2026)]) == []
    assert detect(events([0, 1, 2]) + [parse_line(line(4, 'Accepted password', user='bob'), 2026)]) == []
    assert detect(events([0, 1, 2]) + [parse_line(line(4, 'Accepted password').replace(' lab ', ' other '), 2026)]) == []


@pytest.mark.parametrize('last,users,expected', [
    (300, ['ana', 'ana', 'bob', 'bob', 'carol'], True),
    (301, ['ana', 'ana', 'bob', 'bob', 'carol'], False),
    (300, ['ana', 'ana', 'bob', 'bob', 'bob'], False),
])
def test_multiuser_window(last, users, expected):
    sequence = [parse_line(line(s, user=user), 2026) for s, user in zip([0, 10, 20, 30, last], users)]
    alerts = detect(sequence)
    assert any(a.rule == 'SSH-003' for a in alerts) is expected
    assert alerts == detect(list(reversed(sequence)))
    assert alerts == detect(sequence * 2)


def test_same_second_and_separate_occurrences():
    failures = [parse_line(line(0, user=u), 2026) for u in ['a', 'b', 'c', 'd', 'e', 'f']]
    alerts = detect(failures)
    assert len([a for a in alerts if a.rule == 'SSH-001']) == 2
    sequence = events([0, 1, 2]) + [parse_line(line(2, 'Accepted password'), 2026)]
    assert [a.rule for a in detect(sequence)] == ['SSH-002']


def test_catalog_matches_engine_and_no_unfounded_spraying():
    for rule in RULES.values():
        assert all(key in rule for key in ('id', 'title', 'status', 'description', 'logsource', 'detection', 'level', 'tags', 'falsepositives', 'references'))
    assert 'attack.t1110.003' not in RULES['SSH-003']['tags']


def test_multiuser_demo_and_import_order(tmp_path):
    text = Path('samples/multiuser.log').read_text()
    sequential, reversed_store = Store(tmp_path / 'a.db'), Store(tmp_path / 'b.db')
    assert sequential.import_text(text, 2026)['novos_alertas'] == 2
    for raw in reversed(text.splitlines()):
        reversed_store.import_text(raw, 2026)
    assert {a['id'] for a in sequential.alerts()} == {a['id'] for a in reversed_store.alerts()}
    assert {a['evidence'] for a in sequential.alerts()} == {a['evidence'] for a in reversed_store.alerts()}
    history_count = sum(len(sequential.history(a['id'])) for a in sequential.alerts())
    sequential.import_text(text, 2026)
    assert sum(len(sequential.history(a['id'])) for a in sequential.alerts()) == history_count


def test_triage_history_and_concurrency(tmp_path):
    store = Store(tmp_path / 'soc.db')
    key = seed(store)
    store.triage(key, 'Em análise', 'Validar origem', '', 'Inconclusivo', expected_version=0)
    store.triage(key, 'Escalonado', 'Origem não reconhecida', '', 'Verdadeiro positivo', expected_version=1)
    store.triage(key, 'Encerrado', 'Revisão N2 recebida', 'Registro do exercício', 'Falso positivo', expected_version=2)
    history = store.history(key)
    assert [h['depois']['status'] for h in history if h['action'] == 'triagem'] == ['Em análise', 'Escalonado', 'Encerrado']
    assert history[-1]['antes']['classification'] == 'Verdadeiro positivo'
    assert history[-1]['depois']['classification'] == 'Falso positivo'
    assert history[-1]['actor'] == 'Analista local'
    with pytest.raises(ValueError, match='outra sessão'):
        store.triage(key, 'Novo', '', '', expected_version=0)
    with pytest.raises(ValueError, match='Classificação'):
        store.triage(key, 'Novo', '', '', 'inventada')
    assert len(store.history(key)) == len(history)
    assert Store(tmp_path / 'soc.db').alerts()[0]['notes'] == 'Revisão N2 recebida'


def test_playbook_roundtrip_and_history(tmp_path):
    store = Store(tmp_path / 'soc.db')
    key = seed(store)
    assert not any(s['concluida'] for s in store.playbook(key)['etapas'])
    store.save_playbook(key, ['validate', 'context'], expected_version=0)
    assert sum(s['concluida'] for s in Store(tmp_path / 'soc.db').playbook(key)['etapas']) == 2
    store.save_playbook(key, ['context'], expected_version=1)
    assert store.playbook(key)['version'] == 2
    before = len(store.history(key))
    store.save_playbook(key, ['context'], expected_version=2)
    assert len(store.history(key)) == before
    with pytest.raises(ValueError, match='outra sessão'):
        store.save_playbook(key, [], expected_version=1)
    with pytest.raises(ValueError, match='inválida'):
        store.save_playbook(key, ['invalid'])
    assert store.history(key)[-1]['action'] == 'playbook'


def test_report_manual_snapshot_provenance_and_history(tmp_path):
    store = Store(tmp_path / 'soc.db')
    key = seed(store)
    empty = store.report(key)
    assert set(empty['investigacao']) == set(REPORT_FIELDS)
    assert not any(empty['investigacao'].values())
    assert empty['documento']['version'] == 0
    fields = {key: f'Conteúdo manual: {title}' for key, title in REPORT_FIELDS.items()}
    store.save_report(key, fields, expected_version=0)
    saved = store.report(key)
    assert saved['investigacao'] == fields
    assert len(saved['dados_objetivos']['fontes']) == 4
    assert {s['source'] for s in saved['dados_objetivos']['fontes']} == {'auth.log'}
    assert {s['line'] for s in saved['dados_objetivos']['fontes']} == {1, 2, 3, 4}
    assert saved['dados_objetivos']['fontes_ausentes'] == []
    store.import_text(line(30), 2026, source='late.log')
    stale = store.report(key)
    assert len(stale['evidencias']) == 4
    assert not stale['documento']['dados_objetivos_atualizados']
    store.save_report(key, {'analise': 'Análise revisada'}, expected_version=1)
    reloaded = Store(tmp_path / 'soc.db').report(key)
    assert len(reloaded['evidencias']) == 5
    assert reloaded['documento']['version'] == 2
    assert reloaded['investigacao']['acoes'] == fields['acoes']
    assert reloaded['documento']['dados_objetivos_atualizados']
    assert len([h for h in reloaded['historico'] if h['action'] == 'relatório']) == 2
    assert 'Análise revisada' in markdown_report(reloaded)
    assert 'late.log' in markdown_report(reloaded)
    assert json.loads(json.dumps(reloaded))['investigacao'] == reloaded['investigacao']
    with pytest.raises(ValueError, match='outra sessão'):
        store.save_report(key, {'conclusao': 'stale'}, expected_version=1)
    with pytest.raises(ValueError, match='inválidos'):
        store.save_report(key, {'inventado': 'x'})
    with pytest.raises(ValueError, match='inválidos'):
        store.save_report(key, {'analise': 42})


def test_source_fingerprint_and_no_duplicate_sources(tmp_path):
    store = Store(tmp_path / 'soc.db')
    text = '\n'.join(line(s) for s in [0, 1, 2]) + '\n' + line(60, 'Accepted password')
    store.import_text(text, 2026, -3, source='/private/path/auth.log')
    key = store.alerts()[0]['id']
    store.import_text(text, 2026, -3, source='/private/path/auth.log')
    sources = store.report(key)['dados_objetivos']['fontes']
    assert len(sources) == 4
    assert {s['digest'] for s in sources} == {hashlib.sha256(text.encode()).hexdigest()}
    assert {s['source'] for s in sources} == {'auth.log'}
    assert {s['utc_offset'] for s in sources} == {-3}


def test_legacy_migration_preserves_invalidated_incident(tmp_path):
    path = tmp_path / 'legacy.db'
    sequence = events([0, 1, 2]) + [parse_line(line(60, 'Accepted password', user='bob'), 2026)]
    key = hashlib.sha256(f'SSH-002|{sequence[-1].id}'.encode()).hexdigest()
    with sqlite3.connect(path) as db:
        db.executescript('''
            CREATE TABLE events(id TEXT PRIMARY KEY,timestamp TEXT,host TEXT,ip TEXT,username TEXT,service TEXT,kind TEXT,raw TEXT);
            CREATE TABLE alerts(id TEXT PRIMARY KEY,rule TEXT,severity TEXT,ip TEXT,timestamp TEXT,evidence TEXT);
            CREATE TABLE incidents(alert_id TEXT PRIMARY KEY REFERENCES alerts(id),status TEXT NOT NULL DEFAULT 'Novo',notes TEXT NOT NULL DEFAULT '',justification TEXT NOT NULL DEFAULT '',updated_at TEXT);
        ''')
        for event in sequence:
            record = asdict(event) | {'timestamp': event.timestamp.isoformat()}
            db.execute('INSERT INTO events VALUES (:id,:timestamp,:host,:ip,:username,:service,:kind,:raw)', record)
        db.execute('INSERT INTO alerts VALUES (?,?,?,?,?,?)', (key, 'SSH-002', 'Crítica', sequence[-1].ip, sequence[-1].timestamp.isoformat(), json.dumps([e.id for e in sequence])))
        db.execute('INSERT INTO incidents VALUES (?,?,?,?,?)', (key, 'Encerrado', 'Nota legada', 'Justificativa legada', '2026-01-02T00:00:00+00:00'))
    store = Store(path)
    alert = store.alerts()[0]
    assert alert['active'] == 0
    assert alert['status'] == 'Encerrado'
    assert alert['notes'] == 'Nota legada'
    assert alert['justification'] == 'Justificativa legada'
    assert len(store.report(key)['evidencias']) == 4
    assert len(store.report(key)['dados_objetivos']['fontes_ausentes']) == 4
    assert [h['action'] for h in store.history(key)] == ['migração_v1', 'detecção_arquivada']
    assert len(Store(path).history(key)) == 2
    with store.connection() as db:
        assert db.execute('PRAGMA user_version').fetchone()[0] == 2
        assert db.execute('PRAGMA foreign_key_check').fetchall() == []


def test_metrics_use_saved_state(tmp_path):
    store = Store(tmp_path / 'soc.db')
    assert metrics([])['taxa_encerramento'] == 0
    key = seed(store)
    assert metrics(store.alerts())['triados'] == 0
    store.triage(key, 'Escalonado', 'Verificar', '', 'Inconclusivo')
    summary = metrics(store.alerts())
    assert summary['triados'] == summary['escalonados'] == 1
    assert summary['classificacao'] == {'Inconclusivo': 1}
    store.triage(key, 'Encerrado', 'Atividade validada', 'Teste autorizado', 'Falso positivo')
    summary = metrics(store.alerts())
    assert summary['taxa_encerramento'] == 100
    assert summary['abertos'] == 0
    assert summary['classificacao'] == {'Falso positivo': 1}
    archived = store.alerts()[0] | {'active': 0}
    assert metrics([archived])['historicos'] == 1
    assert metrics([archived])['total'] == 0


@pytest.mark.parametrize('operation', ['report', 'playbook', 'history', 'save_report', 'save_playbook'])
def test_missing_incident_rejected(tmp_path, operation):
    store = Store(tmp_path / 'empty.db')
    arguments = {'save_report': ({},), 'save_playbook': ([],)}.get(operation, ())
    with pytest.raises(ValueError, match='não encontrado'):
        getattr(store, operation)('missing', *arguments)
