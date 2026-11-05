"""Área contínua de investigação: fatos, evidências, decisão e documentação."""
import json
import streamlit as st
from .reports import REPORT_FIELDS, markdown_report
from .storage import STATUSES, CLASSIFICATIONS
from .ui_components import badges, table
from .viewmodels import detection_reason


def clear_versions(prefix, scopes):
    for scope in scopes:
        st.session_state.pop(prefix + scope + '-version', None)


def show_evidence(events, sources=()):
    if not events:
        st.info('Nenhuma evidência disponível neste registro.')
        return
    table(events, ('timestamp', 'ip', 'host', 'username', 'kind'), max_rows=8)
    with st.expander('Registros brutos e proveniência'):
        for event in events:
            st.caption(f"{event['id']} · {event['timestamp']}")
            st.code(event['raw'], language=None)
            origins = [s for s in sources if s['event_id'] == event['id']]
            if origins:
                st.json(origins, expanded=False)
            else:
                st.caption('Origem de importação não disponível neste conjunto de evidências.')


def render_triage(store, alert, prefix):
    st.session_state.setdefault(prefix + 'triage-version', alert['version'])
    with st.form(prefix + 'triage'):
        left, right = st.columns(2)
        with left:
            status = st.selectbox('Status da investigação', STATUSES, index=STATUSES.index(alert['status']), key=prefix + 'status')
        with right:
            classification = st.selectbox('Classificação', CLASSIFICATIONS, index=CLASSIFICATIONS.index(alert['classification']), key=prefix + 'class')
        notes = st.text_area('Observações do analista', value=alert['notes'], key=prefix + 'notes', height=90)
        reason = st.text_area('Justificativa de encerramento', value=alert['justification'], key=prefix + 'reason', height=70,
                              help='Obrigatória para encerrar. Registre o contexto que sustenta a decisão.')
        if st.form_submit_button('Salvar triagem', type='primary'):
            try:
                store.triage(alert['id'], status, notes, reason, classification, st.session_state[prefix + 'triage-version'])
                clear_versions(prefix, ('triage', 'notes'))
                st.session_state.pop(prefix + 'notes-editor', None)
                st.rerun()
            except ValueError as exc:
                st.error(str(exc))


def render_playbook(store, selected, prefix, playbook):
    completed_count = sum(step['concluida'] for step in playbook['etapas'])
    st.caption(f"{completed_count}/{len(playbook['etapas'])} etapas registradas · checklist manual; não executa ações.")
    st.session_state.setdefault(prefix + 'playbook-version', playbook['version'])
    with st.form(prefix + 'playbook'):
        completed = [step['id'] for step in playbook['etapas']
                     if st.checkbox(step['procedimento'], value=step['concluida'], key=prefix + 'step-' + step['id'])]
        if st.form_submit_button('Salvar playbook', type='primary'):
            try:
                store.save_playbook(selected, completed, st.session_state[prefix + 'playbook-version'])
                clear_versions(prefix, ('playbook',))
                st.rerun()
            except ValueError as exc:
                st.error(str(exc))


def render_report(store, selected, prefix, report):
    document = report['documento']
    st.caption(f"Documento v{document['version']} · {document['salvo_em'] or 'Ainda não salvo'} · narrativa manual")
    if not document['dados_objetivos_atualizados']:
        st.warning('Há evidências novas na correlação. Revise a investigação e salve para atualizar a cópia do relatório; a narrativa será preservada.')
    objective, editor, preview = st.tabs(['Dados objetivos', 'Editar investigação', 'Prévia salva'])
    with objective:
        facts = report['dados_objetivos']
        st.caption('Cópia da última gravação, ou dados atuais se o documento ainda não foi salvo.')
        left, right = st.columns(2)
        with left:
            st.text('IPs: ' + ', '.join(facts['ips']))
            st.text('Hosts: ' + ', '.join(facts['hosts']))
        with right:
            st.text('Contas: ' + ', '.join(facts['usuarios']))
            st.text(f"{len(facts['eventos'])} eventos de evidência")
        st.markdown('**Evidências**')
        show_evidence(facts['eventos'], facts['fontes'])
        with st.expander('Linha do tempo objetiva e metadados'):
            table(facts['linha_do_tempo'], ('timestamp', 'host', 'ip', 'username', 'kind'))
            st.json({'ambiente': report.get('ambiente'), 'regra': report['regra'], 'fontes_ausentes': facts['fontes_ausentes']}, expanded=False)
    with editor:
        st.caption('Salve antes de trocar de página. Campos vazios permanecem não informados; nenhuma ação ou conclusão é gerada automaticamente.')
        st.session_state.setdefault(prefix + 'report-version', document['version'])
        with st.form(prefix + 'report'):
            values = report['investigacao']
            fields = {}
            for section, keys in [
                ('Contexto e linha do tempo', ('descricao', 'linha_do_tempo')),
                ('Evidências e indicadores adicionais', ('evidencias_adicionais', 'indicadores')),
                ('Análise do incidente', ('impacto', 'analise')),
                ('Ações e conclusão', ('acoes', 'conclusao')),
            ]:
                st.markdown(f'**{section}**')
                columns = st.columns(2)
                for col, key in zip(columns, keys):
                    with col:
                        fields[key] = st.text_area(REPORT_FIELDS[key], value=values[key], key=prefix + 'field-' + key, height=105)
            if st.form_submit_button('Salvar relatório', type='primary'):
                try:
                    store.save_report(selected, fields, st.session_state[prefix + 'report-version'])
                    clear_versions(prefix, ('report',))
                    st.rerun()
                except ValueError as exc:
                    st.error(str(exc))
    with preview:
        with st.container(height=450, border=True):
            st.markdown(markdown_report(report))
    # Exporta exclusivamente os valores salvos, nunca o rascunho de widgets.
    st.caption('Exportação: narrativa salva + cópia das evidências; triagem, playbook e histórico no estado atual.')
    left, right, _ = st.columns([1, 1, 2])
    with left:
        st.download_button('Exportar Markdown', markdown_report(report), f'soc-one-{selected[:12]}.md', 'text/markdown', width='stretch')
    with right:
        st.download_button('Exportar JSON', json.dumps(report, indent=2, ensure_ascii=False), f'soc-one-{selected[:12]}.json', 'application/json', width='stretch')


def render_history(report):
    history = report['historico']
    st.caption(f'{len(history)} alterações registradas · horários UTC · identidade local não autenticada')
    if history:
        table([{'timestamp': e['timestamp'], 'Operação': e['action'], 'Responsável': e['actor']} for e in reversed(history)],
              ('timestamp', 'Operação', 'Responsável'), max_rows=6)
        with st.expander('Valores anteriores e posteriores'):
            for entry in reversed(history):
                st.text(f"#{entry['id']} · {entry['timestamp']} · {entry['action']}")
                st.json({'antes': entry['antes'], 'depois': entry['depois']}, expanded=False)


def render_investigation(store, alert, *, report_only=False):
    selected = alert['id']
    prefix = f'investigation-{selected}-'
    report = store.report(selected)
    metadata = json.loads(alert['metadata']) or {'id': alert['rule']}
    current_facts = store.evidence(selected)
    evidence = current_facts['eventos']
    with st.container(border=True):
        title, action = st.columns([4, 1])
        with title:
            st.subheader(f"{selected[:10]} · {metadata.get('title', alert['rule'])}")
        with action:
            if st.button('Recarregar investigação', key=prefix + 'reload', help='Descarta rascunhos e lê a versão atual salva.'):
                for key in list(st.session_state):
                    if key.startswith(prefix) and key != prefix + 'reload':
                        del st.session_state[key]
                st.rerun()
        badges(alert['severity'], alert['status'], alert['classification'])
        st.caption(f"{alert['rule']} · {alert['ip']} → {alert['host']} · {len(evidence)} evidências · {alert['timestamp']} UTC")
        if not alert['active']:
            st.info('Detecção histórica: não atende à correlação atual; registros anteriores preservados.')
        if report_only:
            render_report(store, selected, prefix, report)
            return
        overview, proofs, timeline, playbook, notes, document = st.tabs(['Overview', 'Evidence', 'Timeline', 'Playbook', 'Notes', 'Report'])
        with overview:
            left, right = st.columns([3, 2])
            with left:
                st.markdown('**Motivo da detecção**')
                st.write(detection_reason(metadata, evidence))
                st.caption(metadata.get('description', 'Descrição legada não disponível.'))
                st.markdown('**Entidades observadas**')
                st.text('IPs: ' + ', '.join(sorted({e['ip'] for e in evidence if e['ip']})))
                st.text('Hosts: ' + ', '.join(sorted({e['host'] for e in evidence})))
                st.text('Contas: ' + ', '.join(sorted({e['username'] for e in evidence if e['username']})))
            with right:
                st.markdown('**MITRE ATT&CK · hipóteses**')
                st.text(', '.join(tag.replace('attack.', '').upper() for tag in metadata.get('tags', [])) or 'Não informado no registro legado')
                for url in metadata.get('references', []):
                    # Apenas catálogo oficial persistido, não URLs extraídas dos logs.
                    if url.startswith('https://attack.mitre.org/techniques/'):
                        st.link_button(url.rstrip('/').split('/')[-1], url)
                with st.expander('Identificador e condição completos'):
                    st.code(selected, language=None)
                    st.json(metadata, expanded=False)
            st.markdown('**Decisão de triagem**')
            render_triage(store, alert, prefix)
        with proofs:
            st.caption('Evidências completas do alerta, inclusive quando anteriores ao período selecionado na fila.')
            show_evidence(evidence, current_facts['fontes'])
        with timeline:
            st.markdown('**Linha do tempo dos eventos · UTC**')
            table(evidence, ('timestamp', 'ip', 'host', 'username', 'kind'))
            st.markdown('**Atividade da investigação**')
            render_history(report)
        with playbook:
            render_playbook(store, selected, prefix, report['playbook'])
        with notes:
            st.caption('Observações da triagem e justificativa de encerramento. A alteração também fica no histórico.')
            st.session_state.setdefault(prefix + 'notes-version', alert['version'])
            with st.form(prefix + 'notes-form'):
                new_notes = st.text_area('Notas da investigação', value=alert['notes'], key=prefix + 'notes-editor', height=130)
                if st.form_submit_button('Salvar notas'):
                    try:
                        store.triage(selected, alert['status'], new_notes, alert['justification'], alert['classification'], st.session_state[prefix + 'notes-version'])
                        clear_versions(prefix, ('triage', 'notes'))
                        # Sincroniza o segundo editor após uma alteração feita nesta sessão.
                        st.session_state.pop(prefix + 'notes', None)
                        st.rerun()
                    except ValueError as exc:
                        st.error(str(exc))
            st.text('Justificativa salva: ' + (alert['justification'] or 'Não informada'))
            render_history(report)
        with document:
            render_report(store, selected, prefix, report)
