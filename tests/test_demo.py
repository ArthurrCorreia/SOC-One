import json
from pathlib import Path
import pytest
from soc_one.demo import DemoWorkspace, SCENARIOS
from soc_one.reports import markdown_report
from soc_one.storage import Store


@pytest.mark.parametrize('scenario,events,alerts', [
    ('overview', 16, 3), ('normal', 3, 0), ('brute_force', 5, 1),
    ('suspicious_login', 4, 1), ('false_positive', 4, 1), ('multiuser', 5, 2),
])
def test_scenarios_load_once(tmp_path, scenario, events, alerts):
    manager = DemoWorkspace(tmp_path / 'demo')
    store, token = manager.open(scenario)
    assert len(store.events()) == events
    assert len(store.alerts()) == alerts
    reopened, same_token = manager.open(scenario)
    assert token == same_token
    assert len(reopened.events()) == events
    assert len(reopened.alerts()) == alerts
    for alert in store.alerts():
        report = store.report(alert['id'])
        assert report['ambiente']['tipo'] == 'simulado'
        assert report['alerta']['classification'] == 'Não classificado'
        assert not any(report['investigacao'].values())
        assert 'simulado' in markdown_report(report)
        assert json.loads(json.dumps(report))['ambiente']['cenario'] == scenario


def test_reset_preserves_local_and_other_scenarios(tmp_path):
    manager = DemoWorkspace(tmp_path / 'demo')
    store, token = manager.open('false_positive')
    key = store.alerts()[0]['id']
    store.triage(key, 'Encerrado', 'Exercício', 'Confirmação no enunciado', 'Falso positivo')
    store.save_playbook(key, ['validate'])
    store.save_report(key, {'analise': 'Texto simulado'})
    local = Store(tmp_path / 'local.db')
    text = (Path(__file__).resolve().parents[1] / 'samples/false_positive.log').read_text()
    local.import_text(text, 2026)
    local.save_report(key, {'analise': 'Texto local'})
    local_before = Path(local.path).read_bytes()
    other, _ = manager.open('brute_force')
    other.save_report(other.alerts()[0]['id'], {'analise': 'Outro cenário'})
    other_before = Path(other.path).read_bytes()
    with pytest.raises(ValueError, match='Confirme'):
        manager.reset('false_positive', expected_generation=token)
    assert store.report(key)['investigacao']['analise'] == 'Texto simulado'
    manager.reset('false_positive', confirmed=True, expected_generation=token)
    fresh, new_token = manager.open('false_positive')
    assert new_token != token
    assert len(fresh.events()) == 4
    assert fresh.report(key)['alerta']['status'] == 'Novo'
    assert fresh.report(key)['investigacao']['analise'] == ''
    assert fresh.playbook(key)['version'] == 0
    assert len(fresh.history(key)) == 1  # somente a nova detecção
    assert Path(local.path).read_bytes() == local_before
    assert Path(other.path).read_bytes() == other_before
    with pytest.raises(ValueError, match='outra sessão'):
        manager.reset('false_positive', confirmed=True, expected_generation=token)


def test_reset_is_atomic_on_detection_failure(tmp_path, monkeypatch):
    manager = DemoWorkspace(tmp_path)
    store, token = manager.open('brute_force')
    key = store.alerts()[0]['id']
    store.save_report(key, {'conclusao': 'Preservar se ocorrer erro'})
    def fail(*args, **kwargs):
        raise RuntimeError('falha simulada')
    monkeypatch.setattr(Store, '_import_text', fail)
    with pytest.raises(RuntimeError):
        manager.reset('brute_force', confirmed=True, expected_generation=token)
    assert store.report(key)['investigacao']['conclusao'] == 'Preservar se ocorrer erro'
    assert len(store.events()) == 5


def test_reset_refuses_unidentified_database_and_invalid_scenario(tmp_path):
    manager = DemoWorkspace(tmp_path)
    local = Store(tmp_path / 'overview.db')
    local.import_text('Nov 3 09:00:00 host CRON[1]: normal', 2026)
    before = Path(local.path).read_bytes()
    with pytest.raises(ValueError, match='sem identificação'):
        manager.open('overview')
    assert Path(local.path).read_bytes() == before
    with pytest.raises(ValueError, match='desconhecido'):
        manager.open('../soc_one')
    with pytest.raises(ValueError):
        manager.reset('overview', confirmed=True, expected_generation='anything')
    assert Path(local.path).read_bytes() == before


def test_public_example_uses_temporary_data(tmp_path):
    from examples.generate_report import generate
    report = generate(tmp_path / 'examples')
    assert report['ambiente']['tipo'] == 'simulado'
    assert report['alerta']['classification'] == 'Falso positivo'
    assert 'EXEMPLO FICTÍCIO' in report['investigacao']['descricao']
    assert 'Nenhum contato, bloqueio ou contenção real' in report['investigacao']['acoes']
    assert len(report['evidencias']) == 4
    assert json.loads((tmp_path / 'examples/incidente_ficticio.json').read_text()) == report
    assert (tmp_path / 'examples/incidente_ficticio.md').read_text() == markdown_report(report)
    assert not list(tmp_path.rglob('*.db'))
