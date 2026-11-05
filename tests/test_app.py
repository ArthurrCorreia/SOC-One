from pathlib import Path
import re
from streamlit.testing.v1 import AppTest
from soc_one.demo import DemoWorkspace
from soc_one.storage import Store

APP = Path(__file__).resolve().parents[1] / 'app.py'


def element(elements, label):
    return next(item for item in elements if item.label == label)


def navigate(at, page):
    element(at.radio, 'Navegação').set_value(page).run()
    assert not at.exception


def counters(at):
    body = next(e.proto.body for e in at.get('html') if 'class="soc-metrics"' in e.proto.body)
    return [int(v) for v in re.findall(r'<strong>(\d+)</strong>', body)]


def demo_store(scenario='overview'):
    return DemoWorkspace().open(scenario)[0]


def test_dashboard_demo_and_triage(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    at = AppTest.from_file(str(APP), default_timeout=30).run()
    assert not at.exception
    assert counters(at) == [16, 3, 0, 2, 0]
    assert not Path('data/soc_one.db').exists()
    navigate(at, 'Incidents')
    element(at.selectbox, 'Status da investigação').select('Encerrado')
    element(at.button, 'Salvar triagem').click().run()
    assert at.error
    element(at.text_area, 'Justificativa de encerramento').set_value('Atividade legítima validada no exercício')
    element(at.button, 'Salvar triagem').click().run()
    assert not at.exception
    navigate(at, 'Overview')
    assert counters(at) == [16, 2, 0, 1, 0]
    at.run()
    assert counters(at) == [16, 2, 0, 1, 0]


def test_report_playbook_filters_and_reload(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    at = AppTest.from_file(str(APP), default_timeout=30).run()
    element(at.selectbox, 'Cenário simulado').select('multiuser').run()
    assert not at.exception
    assert counters(at) == [5, 2, 0, 0, 0]
    navigate(at, 'Incidents')
    element(at.multiselect, 'Regras').set_value(['SSH-003']).run()
    selected = element(at.selectbox, 'Abrir alerta').value
    element(at.selectbox, 'Classificação').select('Inconclusivo')
    element(at.selectbox, 'Status da investigação').select('Escalonado')
    element(at.button, 'Salvar triagem').click().run()
    assert not at.exception
    assert demo_store('multiuser').report(selected)['alerta']['classification'] == 'Inconclusivo'
    next(c for c in at.checkbox if c.label.startswith('N1 · Validar horários')).check()
    element(at.button, 'Salvar playbook').click().run()
    assert demo_store('multiuser').playbook(selected)['etapas'][0]['concluida']
    navigate(at, 'Reports')
    element(at.text_area, 'Descrição do ocorrido').set_value('Falhas contra três contas observadas nos logs.')
    element(at.text_area, 'Análise').set_value('Origem ainda não validada.')
    element(at.button, 'Salvar relatório').click().run()
    assert not at.exception
    saved = demo_store('multiuser').report(selected)
    assert saved['investigacao']['analise'] == 'Origem ainda não validada.'
    assert saved['investigacao']['acoes'] == ''
    assert len(at.get('download_button')) == 2
    reloaded = AppTest.from_file(str(APP), default_timeout=30).run()
    element(reloaded.selectbox, 'Cenário simulado').select('multiuser').run()
    navigate(reloaded, 'Reports')
    element(reloaded.multiselect, 'Regras').set_value(['SSH-003']).run()
    assert element(reloaded.text_area, 'Análise').value == 'Origem ainda não validada.'
    navigate(reloaded, 'Incidents')
    element(reloaded.multiselect, 'Regras').set_value(['SSH-003']).run()
    assert next(c for c in reloaded.checkbox if c.label.startswith('N1 · Validar horários')).value
    element(reloaded.multiselect, 'Classificações').set_value(['Falso positivo']).run()
    assert not reloaded.exception
    assert any('Nenhum alerta' in item.value for item in reloaded.info)


def test_concurrent_ui_edit_requires_reload(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    at = AppTest.from_file(str(APP), default_timeout=30).run()
    navigate(at, 'Reports')
    key = element(at.selectbox, 'Abrir alerta').value
    demo_store().save_report(key, {'analise': 'Salvo por outra sessão'}, expected_version=0)
    element(at.text_area, 'Análise').set_value('Texto desatualizado')
    element(at.button, 'Salvar relatório').click().run()
    assert any('outra sessão' in e.value for e in at.error)
    assert demo_store().report(key)['investigacao']['analise'] == 'Salvo por outra sessão'
    element(at.button, 'Recarregar investigação').click().run()
    assert not at.exception
    assert element(at.text_area, 'Análise').value == 'Salvo por outra sessão'


def test_demo_reset_confirmation_and_local_isolation(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    # Mesmo evento/alerta existe nos dois ambientes; o reset não pode atingir o local.
    local = Store()
    local.import_text((APP.parent / 'samples/demo.log').read_text(), 2026)
    key = local.alerts()[0]['id']
    local.save_report(key, {'analise': 'Investigação local preservada'})
    at = AppTest.from_file(str(APP), default_timeout=30).run()
    demo_store().save_report(key, {'analise': 'Investigação simulada'})
    assert element(at.button, 'Reiniciar demonstração').disabled
    element(at.checkbox, 'Confirmo apagar a investigação deste cenário').check().run()
    element(at.button, 'Reiniciar demonstração').click().run()
    assert not at.exception
    assert demo_store().report(key)['investigacao']['analise'] == ''
    assert local.report(key)['investigacao']['analise'] == 'Investigação local preservada'
    assert element(at.button, 'Reiniciar demonstração').disabled
    element(at.selectbox, 'Origem dos dados').select('Dados locais').run()
    assert not at.exception
    assert len(at.get('file_uploader')) == 1
    assert not any(b.label == 'Reiniciar demonstração' for b in at.button)
    navigate(at, 'Reports')
    assert element(at.text_area, 'Análise').value == 'Investigação local preservada'


def test_normal_scenario_empty_alerts_and_workspace_drafts(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    at = AppTest.from_file(str(APP), default_timeout=30).run()
    navigate(at, 'Reports')
    element(at.text_area, 'Análise').set_value('Rascunho não salvo')
    element(at.selectbox, 'Cenário simulado').select('normal').run()
    navigate(at, 'Overview')
    assert counters(at) == [3, 0, 0, 0, 0]
    navigate(at, 'Incidents')
    assert any('Nenhum alerta' in i.value for i in at.info)
    navigate(at, 'Event Explorer')
    assert len(at.dataframe[0].value) == 3
    element(at.text_input, 'IP ou parte do IP').set_value('203.0.113.255').run()
    assert any('Nenhum evento' in i.value for i in at.info)
    element(at.selectbox, 'Cenário simulado').select('overview').run()
    navigate(at, 'Reports')
    assert element(at.text_area, 'Análise').value == ''


def test_all_pages_handoff_notes_and_combined_filters(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    at = AppTest.from_file(str(APP), default_timeout=30).run()
    navigate(at, 'Detection Rules')
    assert len(at.dataframe[0].value) == 3
    element(at.selectbox, 'Consultar regra').select('SSH-003').run()
    assert any('Contas distintas: pelo menos 3' in t.value for t in at.text)
    navigate(at, 'Event Explorer')
    element(at.text_input, 'Pesquisar texto nos eventos').set_value('Accepted')
    element(at.text_input, 'IP ou parte do IP').set_value('203.0.113.30').run()
    assert len(at.dataframe[0].value) == 1
    assert at.dataframe[0].value['kind'].tolist() == ['Sucesso']
    element(at.button, 'Pesquisar este IP na fila').click().run()
    assert element(at.radio, 'Navegação').value == 'Alert Queue'
    assert len(at.dataframe[0].value) == 1
    selected = element(at.selectbox, 'Abrir alerta').value
    element(at.button, 'Continuar em Incidents').click().run()
    assert element(at.selectbox, 'Abrir alerta').value == selected
    assert [t.label for t in at.tabs][:6] == ['Overview', 'Evidence', 'Timeline', 'Playbook', 'Notes', 'Report']
    element(at.text_area, 'Notas da investigação').set_value('Validar origem com responsável pelo host.')
    element(at.button, 'Salvar notas').click().run()
    assert not at.exception
    assert element(at.text_area, 'Observações do analista').value == 'Validar origem com responsável pelo host.'
    element(at.selectbox, 'Status da investigação').select('Em análise')
    element(at.button, 'Salvar triagem').click().run()
    assert not at.exception
    assert demo_store().report(selected)['alerta']['notes'] == 'Validar origem com responsável pelo host.'
    element(at.button, 'Abrir relatórios').click().run()
    assert element(at.selectbox, 'Abrir alerta').value == selected
    element(at.checkbox, 'Somente relatórios salvos').check().run()
    assert any('Nenhum relatório salvo' in i.value for i in at.info)
    navigate(at, 'Overview')
    assert counters(at) == [16, 3, 1, 2, 0]


def test_period_scope_does_not_trim_incident_evidence(tmp_path, monkeypatch):
    from datetime import date, time
    monkeypatch.chdir(tmp_path)
    at = AppTest.from_file(str(APP), default_timeout=30).run()
    element(at.selectbox, 'Período de análise').select('Personalizado').run()
    element(at.date_input, 'Intervalo de datas UTC').set_value((date(2026, 11, 3), date(2026, 11, 3)))
    element(at.time_input, 'Horário inicial UTC').set_value(time(11, 3))
    element(at.time_input, 'Horário final UTC').set_value(time(11, 3)).run()
    assert counters(at) == [1, 1, 0, 1, 0]
    navigate(at, 'Incidents')
    assert len(at.dataframe[0].value) == 1
    # O sucesso está no período; as três falhas anteriores continuam como evidência.
    assert len(at.dataframe[1].value) == 4
    assert len(demo_store().events()) == 16
    element(at.time_input, 'Horário inicial UTC').set_value(time(12)).run()
    assert at.error
    assert not at.dataframe
    assert not at.exception


def test_triage_does_not_reset_concurrent_report_protection(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    at = AppTest.from_file(str(APP), default_timeout=30).run()
    navigate(at, 'Incidents')
    selected = element(at.selectbox, 'Abrir alerta').value
    demo_store().save_report(selected, {'analise': 'Versão externa'}, expected_version=0)
    element(at.selectbox, 'Status da investigação').select('Em análise')
    element(at.button, 'Salvar triagem').click().run()
    element(at.text_area, 'Análise').set_value('Rascunho anterior')
    element(at.button, 'Salvar relatório').click().run()
    assert any('outra sessão' in e.value for e in at.error)
    assert demo_store().report(selected)['investigacao']['analise'] == 'Versão externa'


def test_explicit_case_handoff_overrides_destination_filters(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    at = AppTest.from_file(str(APP), default_timeout=30).run()
    navigate(at, 'Incidents')
    element(at.text_input, 'IP do incidente').set_value('192.0.2.40').run()
    navigate(at, 'Alert Queue')
    element(at.multiselect, 'Regras').set_value(['SSH-001']).run()
    selected = element(at.selectbox, 'Abrir alerta').value
    element(at.button, 'Continuar em Incidents').click().run()
    assert element(at.selectbox, 'Abrir alerta').value == selected
    navigate(at, 'Alert Queue')
    assert element(at.multiselect, 'Regras').value == ['SSH-001']
    assert len(at.dataframe[0].value) == 1
    element(at.multiselect, 'Regras').set_value(['SSH-002']).run()
    assert element(at.selectbox, 'Abrir alerta').value != selected
    assert not at.exception


def test_all_demo_scenarios_in_operational_pages(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    at = AppTest.from_file(str(APP), default_timeout=30).run()
    for scenario, events, alerts in [('overview', 16, 3), ('normal', 3, 0), ('brute_force', 5, 1),
                                     ('suspicious_login', 4, 1), ('false_positive', 4, 1), ('multiuser', 5, 2)]:
        element(at.selectbox, 'Cenário simulado').select(scenario).run()
        navigate(at, 'Overview')
        assert counters(at)[:2] == [events, alerts]
        navigate(at, 'Event Explorer')
        assert len(at.dataframe[0].value) == events
        navigate(at, 'Alert Queue')
        if alerts:
            assert len(at.dataframe[0].value) == alerts
            assert element(at.selectbox, 'Classificação').value == 'Não classificado'
        else:
            assert any('Nenhum alerta' in i.value for i in at.info)


def test_contextual_header_uses_visible_case_including_archived(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    at = AppTest.from_file(str(APP), default_timeout=30).run()
    store = demo_store()
    archived = next(a['id'] for a in store.alerts() if a['rule'] == 'SSH-001')
    with store.connection() as db:
        db.execute('UPDATE alerts SET active=0 WHERE id=?', (archived,))
    navigate(at, 'Reports')
    element(at.checkbox, 'Incluir detecções históricas').check().run()
    element(at.multiselect, 'Regras').set_value(['SSH-001']).run()
    assert element(at.selectbox, 'Abrir alerta').value == archived
    element(at.button, 'Investigar caso').click().run()
    assert element(at.selectbox, 'Abrir alerta').value == archived
    assert any('Detecção histórica' in i.value for i in at.info)
    assert not at.exception
