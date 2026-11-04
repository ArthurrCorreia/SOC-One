from pathlib import Path
from streamlit.testing.v1 import AppTest
from soc_one.demo import DemoWorkspace
from soc_one.storage import Store

APP = Path(__file__).resolve().parents[1] / 'app.py'


def element(elements, label):
    return next(item for item in elements if item.label == label)


def navigate(at, page):
    element(at.radio, 'Navegação').set_value(page).run()
    assert not at.exception


def demo_store(scenario='overview'):
    return DemoWorkspace().open(scenario)[0]


def test_dashboard_demo_and_triage(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    at = AppTest.from_file(str(APP), default_timeout=30).run()
    assert not at.exception
    assert [m.value for m in at.metric][:3] == ['16', '3', '3']
    assert not Path('data/soc_one.db').exists()
    navigate(at, 'Alertas e incidentes')
    element(at.selectbox, 'Status da investigação').select('Encerrado')
    element(at.button, 'Salvar triagem').click().run()
    assert at.error
    element(at.text_area, 'Justificativa de encerramento').set_value('Atividade legítima validada no exercício')
    element(at.button, 'Salvar triagem').click().run()
    assert not at.exception
    navigate(at, 'Visão geral')
    assert [m.value for m in at.metric][:3] == ['16', '3', '2']
    at.run()
    assert [m.value for m in at.metric][:3] == ['16', '3', '2']


def test_report_playbook_filters_and_reload(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    at = AppTest.from_file(str(APP), default_timeout=30).run()
    element(at.selectbox, 'Cenário simulado').select('multiuser').run()
    assert not at.exception
    assert [m.value for m in at.metric][:3] == ['5', '2', '2']
    navigate(at, 'Alertas e incidentes')
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
    navigate(at, 'Relatórios')
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
    navigate(reloaded, 'Relatórios')
    element(reloaded.multiselect, 'Regras').set_value(['SSH-003']).run()
    assert element(reloaded.text_area, 'Análise').value == 'Origem ainda não validada.'
    navigate(reloaded, 'Alertas e incidentes')
    assert next(c for c in reloaded.checkbox if c.label.startswith('N1 · Validar horários')).value
    element(reloaded.multiselect, 'Classificações').set_value(['Falso positivo']).run()
    assert not reloaded.exception
    assert any('Nenhum alerta' in item.value for item in reloaded.info)


def test_concurrent_ui_edit_requires_reload(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    at = AppTest.from_file(str(APP), default_timeout=30).run()
    navigate(at, 'Relatórios')
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
    element(at.radio, 'Origem dos dados').set_value('Dados locais').run()
    assert not at.exception
    assert len(at.get('file_uploader')) == 1
    assert not any(b.label == 'Reiniciar demonstração' for b in at.button)
    navigate(at, 'Relatórios')
    assert element(at.text_area, 'Análise').value == 'Investigação local preservada'


def test_normal_scenario_empty_alerts_and_workspace_drafts(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    at = AppTest.from_file(str(APP), default_timeout=30).run()
    navigate(at, 'Relatórios')
    element(at.text_area, 'Análise').set_value('Rascunho não salvo')
    element(at.selectbox, 'Cenário simulado').select('normal').run()
    assert [m.value for m in at.metric][:3] == ['3', '0', '0']
    navigate(at, 'Alertas e incidentes')
    assert any('Nenhum alerta' in i.value for i in at.info)
    navigate(at, 'Eventos')
    assert len(at.dataframe[0].value) == 3
    element(at.text_input, 'IP ou parte do IP').set_value('203.0.113.255').run()
    assert any('Nenhum evento' in i.value for i in at.info)
    element(at.selectbox, 'Cenário simulado').select('overview').run()
    navigate(at, 'Relatórios')
    assert element(at.text_area, 'Análise').value == ''
