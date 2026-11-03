"""Componentes Streamlit para investigação, sem lógica de detecção."""
import json
import pandas as pd
import streamlit as st
from .reports import REPORT_FIELDS, markdown_report
from .storage import STATUSES, CLASSIFICATIONS


def count_chart(counts, label):
    if not counts:
        st.caption('Sem dados para exibir.')
        return
    frame = pd.DataFrame([{label: key, 'Quantidade': value} for key, value in counts.items()])
    st.vega_lite_chart(frame, {
        'mark': {'type': 'bar', 'color': '#38bdf8'},
        'encoding': {'x': {'field': label, 'type': 'nominal', 'axis': {'labelAngle': 0}},
                     'y': {'field': 'Quantidade', 'type': 'quantitative', 'axis': {'tickMinStep': 1}},
                     'tooltip': [{'field': label}, {'field': 'Quantidade'}]},
    }, width='stretch')


def filter_dates(rows, key, title):
    if not rows:
        return rows
    dates = [pd.Timestamp(row['timestamp']).date() for row in rows]
    period = st.date_input(title, value=(min(dates), max(dates)), key=key)
    if len(period) != 2:
        st.caption('Selecione as duas datas do intervalo.')
        return []
    return [row for row, day in zip(rows, dates) if period[0] <= day <= period[1]]


def render_investigation(store, alert):
    selected = alert['id']
    prefix = f'investigation-{selected}-'
    if st.button('Recarregar investigação', key=prefix + 'reload'):
        for key in list(st.session_state):
            if key.startswith(prefix) and key != prefix + 'reload':
                del st.session_state[key]
        st.rerun()
    report = store.report(selected)
    st.subheader(report['regra'].get('title', alert['rule']))
    st.caption(f"{alert['host']} · {alert['ip']} · {alert['timestamp']} · ID {selected}")
    if not alert['active']:
        st.info('Registro histórico: não atende à correlação atual. Triagem e documentos foram preservados.')
    st.warning('Alerta indica suspeita. A classificação e a conclusão exigem validação pelo analista.')
    tags = report['regra'].get('tags', [])
    st.caption('MITRE ATT&CK (hipóteses): ' + ', '.join(tags))
    evidence_ids = set(json.loads(alert['evidence']))
    st.write('Evidências da correlação atual')
    st.dataframe([e for e in store.events() if e['id'] in evidence_ids], width='stretch', hide_index=True)
    with st.expander('Metadados da regra'):
        st.json(report['regra'])
    st.session_state.setdefault(prefix + 'triage-version', alert['version'])
    with st.form(prefix + 'triage'):
        status = st.selectbox('Status da investigação', STATUSES, index=STATUSES.index(alert['status']), key=prefix + 'status')
        classification = st.selectbox('Classificação', CLASSIFICATIONS, index=CLASSIFICATIONS.index(alert['classification']), key=prefix + 'class')
        notes = st.text_area('Observações do analista', value=alert['notes'], key=prefix + 'notes')
        reason = st.text_area('Justificativa de encerramento', value=alert['justification'], key=prefix + 'reason')
        if st.form_submit_button('Salvar triagem'):
            try:
                store.triage(selected, status, notes, reason, classification, st.session_state[prefix + 'triage-version'])
                del st.session_state[prefix + 'triage-version']
                st.rerun()
            except ValueError as exc:
                st.error(str(exc))
    st.subheader('Playbook de investigação')
    playbook = report['playbook']
    completed_count = sum(step['concluida'] for step in playbook['etapas'])
    st.caption(f"{completed_count}/{len(playbook['etapas'])} etapas registradas. Checklist manual; não executa ações.")
    st.session_state.setdefault(prefix + 'playbook-version', playbook['version'])
    with st.form(prefix + 'playbook'):
        completed = [step['id'] for step in playbook['etapas']
                     if st.checkbox(step['procedimento'], value=step['concluida'], key=prefix + 'step-' + step['id'])]
        if st.form_submit_button('Salvar playbook'):
            try:
                store.save_playbook(selected, completed, st.session_state[prefix + 'playbook-version'])
                del st.session_state[prefix + 'playbook-version']
                st.rerun()
            except ValueError as exc:
                st.error(str(exc))
    st.subheader('Relatório de investigação')
    document = report['documento']
    st.caption(f"Versão salva: {document['version']} · Atualizado em: {document['salvo_em'] or 'Ainda não salvo'}")
    if not document['dados_objetivos_atualizados']:
        st.warning('Há dados objetivos novos. Revise a investigação e salve o relatório para atualizar a cópia das evidências. O texto manual será preservado.')
    with st.expander('Dados objetivos e origem — cópia do relatório'):
        st.json(report['dados_objetivos'])
    st.caption('Os campos abaixo são manuais. Registre apenas fatos verificados e indique as fontes; campos vazios permanecem não informados. A linha do tempo dos eventos é incluída automaticamente na exportação.')
    st.session_state.setdefault(prefix + 'report-version', document['version'])
    with st.form(prefix + 'report'):
        fields = {key: st.text_area(label, value=report['investigacao'][key], key=prefix + 'field-' + key)
                  for key, label in REPORT_FIELDS.items()}
        if st.form_submit_button('Salvar relatório'):
            try:
                store.save_report(selected, fields, st.session_state[prefix + 'report-version'])
                del st.session_state[prefix + 'report-version']
                st.rerun()
            except ValueError as exc:
                st.error(str(exc))
    st.caption('A exportação inclui a narrativa salva. Alterações ainda não salvas no formulário não são exportadas.')
    st.download_button('Exportar JSON', json.dumps(report, indent=2, ensure_ascii=False), f'soc-one-{selected[:12]}.json', 'application/json')
    st.download_button('Exportar Markdown', markdown_report(report), f'soc-one-{selected[:12]}.md', 'text/markdown')
    with st.expander('Histórico de alterações'):
        for entry in reversed(report['historico']):
            st.text(f"#{entry['id']} · {entry['timestamp']} · {entry['actor']} · {entry['action']}")
            st.json({'antes': entry['antes'], 'depois': entry['depois']}, expanded=False)
