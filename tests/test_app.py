from pathlib import Path
from streamlit.testing.v1 import AppTest


def test_dashboard_demo_and_triage(tmp_path, monkeypatch):
    app = Path(__file__).resolve().parents[1] / 'app.py'
    monkeypatch.chdir(tmp_path)
    at = AppTest.from_file(str(app), default_timeout=30).run()
    assert not at.exception
    next(b for b in at.button if b.label == 'Carregar demonstração').click().run()
    assert not at.exception
    assert [m.value for m in at.metric][:3] == ['16', '3', '3']
    next(s for s in at.selectbox if s.label == 'Status da investigação').select('Encerrado')
    next(b for b in at.button if b.label == 'Salvar triagem').click().run()
    assert at.error
    next(t for t in at.text_area if t.label == 'Justificativa de encerramento').set_value('Atividade legítima validada no exercício')
    next(b for b in at.button if b.label == 'Salvar triagem').click().run()
    assert not at.exception
    assert [m.value for m in at.metric][:3] == ['16', '3', '2']
    next(b for b in at.button if b.label == 'Carregar demonstração').click().run()
    assert [m.value for m in at.metric][:3] == ['16', '3', '2']


def test_report_playbook_filters_and_reload(tmp_path, monkeypatch):
    from soc_one.storage import Store

    app = Path(__file__).resolve().parents[1] / 'app.py'
    monkeypatch.chdir(tmp_path)
    at = AppTest.from_file(str(app), default_timeout=30).run()
    next(b for b in at.button if b.label == 'Carregar cenário multiusuário').click().run()
    assert not at.exception
    assert [m.value for m in at.metric][:3] == ['5', '2', '2']
    next(s for s in at.multiselect if s.label == 'Regras').set_value(['SSH-003']).run()
    selected = next(s for s in at.selectbox if s.label == 'Abrir alerta').value
    next(s for s in at.selectbox if s.label == 'Classificação').select('Inconclusivo')
    next(s for s in at.selectbox if s.label == 'Status da investigação').select('Escalonado')
    next(b for b in at.button if b.label == 'Salvar triagem').click().run()
    assert not at.exception
    assert Store().report(selected)['alerta']['classification'] == 'Inconclusivo'
    next(c for c in at.checkbox if c.label.startswith('N1 · Validar horários')).check()
    next(b for b in at.button if b.label == 'Salvar playbook').click().run()
    assert not at.exception
    assert Store().playbook(selected)['etapas'][0]['concluida']
    next(t for t in at.text_area if t.label == 'Descrição do ocorrido').set_value('Falhas contra três contas observadas nos logs.')
    next(t for t in at.text_area if t.label == 'Análise').set_value('Origem ainda não validada.')
    next(b for b in at.button if b.label == 'Salvar relatório').click().run()
    assert not at.exception
    saved = Store().report(selected)
    assert saved['investigacao']['analise'] == 'Origem ainda não validada.'
    assert saved['investigacao']['acoes'] == ''
    # Nova sessão consulta o conteúdo persistido, sem depender do estado dos widgets.
    reloaded = AppTest.from_file(str(app), default_timeout=30).run()
    next(s for s in reloaded.multiselect if s.label == 'Regras').set_value(['SSH-003']).run()
    assert next(t for t in reloaded.text_area if t.label == 'Análise').value == 'Origem ainda não validada.'
    assert next(c for c in reloaded.checkbox if c.label.startswith('N1 · Validar horários')).value
    next(s for s in reloaded.multiselect if s.label == 'Classificações').set_value(['Falso positivo']).run()
    assert not reloaded.exception
    assert any('Nenhum alerta' in item.value for item in reloaded.info)


def test_concurrent_ui_edit_requires_reload(tmp_path, monkeypatch):
    from soc_one.storage import Store

    app = Path(__file__).resolve().parents[1] / 'app.py'
    monkeypatch.chdir(tmp_path)
    at = AppTest.from_file(str(app), default_timeout=30).run()
    next(b for b in at.button if b.label == 'Carregar demonstração').click().run()
    key = next(s for s in at.selectbox if s.label == 'Abrir alerta').value
    Store().save_report(key, {'analise': 'Salvo por outra sessão'}, expected_version=0)
    next(t for t in at.text_area if t.label == 'Análise').set_value('Texto desatualizado')
    next(b for b in at.button if b.label == 'Salvar relatório').click().run()
    assert any('outra sessão' in e.value for e in at.error)
    assert Store().report(key)['investigacao']['analise'] == 'Salvo por outra sessão'
    next(b for b in at.button if b.label == 'Recarregar investigação').click().run()
    assert not at.exception
    assert next(t for t in at.text_area if t.label == 'Análise').value == 'Salvo por outra sessão'
