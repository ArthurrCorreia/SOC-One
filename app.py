"""Dashboard local. Execução recomendada: bash run.sh."""
from datetime import datetime
import pandas as pd
import streamlit as st
from soc_one.analytics import metrics
from soc_one.catalog import RULES
from soc_one.demo import DemoWorkspace, SCENARIOS
from soc_one.storage import Store, STATUSES, CLASSIFICATIONS
from soc_one.ui import count_chart, filter_dates, render_investigation


def switch_workspace(token):
    """Não reaproveita rascunhos ou versões de widgets entre bancos/cenários."""
    if st.session_state.get('workspace') != token:
        for key in list(st.session_state):
            if key not in ('mode', 'scenario'):
                del st.session_state[key]
        st.session_state['workspace'] = token


def import_feedback(result):
    st.success(f"{result['inseridos']} eventos novos · {result['novos_alertas']} alertas novos · "
               f"{result['repetidos']} repetidos · {result['ignorados']} linhas inválidas ignoradas.")


st.set_page_config(page_title='SOC-One | Central de triagem', page_icon='🛡️', layout='wide')
st.title('SOC-One')
st.caption('LABORATÓRIO SOC N1 · Detecção, investigação e documentação de autenticação SSH')
with st.sidebar:
    st.header('Ambiente de trabalho')
    mode = st.radio('Origem dos dados', ['Demonstração', 'Dados locais'], key='mode')
    st.caption('Trocar de ambiente ou cenário descarta apenas edições ainda não salvas nos formulários.')
    if mode == 'Demonstração':
        scenario = st.selectbox('Cenário simulado', list(SCENARIOS), format_func=lambda key: SCENARIOS[key]['title'], key='scenario')
        manager = DemoWorkspace()
        try:
            store, generation = manager.open(scenario)
        except (ValueError, OSError) as exc:
            st.error(str(exc))
            st.stop()
        switch_workspace(('demo', scenario, generation))
        st.caption('Carga automática. Cada cenário mantém sua própria investigação.')
        with st.expander('Reiniciar este cenário'):
            st.warning('Apaga triagem, playbooks, relatórios e histórico deste cenário simulado, e recarrega os logs fictícios. Os dados locais e os outros cenários serão preservados.')
            confirmed = st.checkbox('Confirmo apagar a investigação deste cenário', key='reset-confirm')
            if st.button('Reiniciar demonstração', disabled=not confirmed):
                try:
                    manager.reset(scenario, confirmed=confirmed, expected_generation=generation)
                    st.rerun()
                except ValueError as exc:
                    st.error(str(exc))
    else:
        store = Store()
        switch_workspace(('local',))
        st.header('Importar logs autorizados')
        st.caption('UTF-8 · até 5 MB · nenhum log do sistema é lido automaticamente.')
        year = st.number_input('Ano dos logs sem ano', 1970, 2100, datetime.now().year)
        offset = st.number_input('Deslocamento UTC dos logs sem fuso (horas)', -12, 14, 0)
        st.caption('Separe arquivos que atravessem a virada do ano. Os horários são exibidos em UTC.')
        upload = st.file_uploader('Arquivo de autenticação', type=['log', 'txt'])
        if st.button('Importar arquivo', disabled=upload is None):
            try:
                if upload.size > 5 * 1024 * 1024:
                    raise ValueError('O arquivo excede 5 MB.')
                import_feedback(store.import_text(upload.getvalue().decode('utf-8-sig'), int(year), int(offset), upload.name))
            except (UnicodeError, ValueError) as exc:
                st.error(str(exc))
    st.divider()
    st.caption('Execução local · sem IA ou serviços externos\n\nNenhuma ação de contenção é automática.')

if mode == 'Demonstração':
    st.info(f"DADOS SIMULADOS · {SCENARIOS[scenario]['title']} · {SCENARIOS[scenario]['expected']}")
    st.caption(SCENARIOS[scenario]['guide'])
else:
    st.info('DADOS LOCAIS / IMPORTADOS · Persistência independente da demonstração. Bancos antigos podem conter exemplos carregados em versões anteriores.')

page = st.radio('Navegação', ['Visão geral', 'Eventos', 'Alertas e incidentes', 'Relatórios'], horizontal=True, key='page')
events, alerts = store.events(), store.alerts()
summary = metrics(alerts)
if page == 'Visão geral':
    cols = st.columns(3)
    cols[0].metric('Eventos coletados', len(events))
    cols[1].metric('Alertas detectados', summary['total'])
    cols[2].metric('Incidentes em aberto', summary['abertos'])
    cols = st.columns(3)
    cols[0].metric('Com triagem registrada', summary['triados'])
    cols[1].metric('Escalonados', summary['escalonados'])
    cols[2].metric('Taxa de encerramento', f"{summary['taxa_encerramento']:.1f}%")
    st.caption(f"Indicadores deste ambiente, sem filtro de período. {summary['historicos']} detecções históricas preservadas. Um registro de incidente não confirma comprometimento.")
    st.markdown('**Como começar:** consulte os eventos, abra um alerta, salve a triagem e o playbook; depois documente e exporte em **Relatórios**.')
    if events:
        chart_events = filter_dates(events, 'chart-period', 'Período do gráfico (UTC)')
        st.subheader('Eventos por minuto · UTC')
        if chart_events:
            frame = pd.DataFrame(chart_events)
            frame['minuto'] = pd.to_datetime(frame['timestamp'], utc=True).dt.floor('min')
            series = frame.groupby('minuto').size().rename('Eventos').reset_index()
            st.vega_lite_chart(series, {'mark': {'type': 'bar', 'color': '#38bdf8'},
                'encoding': {'x': {'field': 'minuto', 'type': 'temporal', 'scale': {'type': 'utc'}, 'title': 'UTC'},
                             'y': {'field': 'Eventos', 'type': 'quantitative'},
                             'tooltip': [{'field': 'minuto', 'type': 'temporal'}, {'field': 'Eventos'}]}}, width='stretch')
        else:
            st.info('Nenhum evento no intervalo selecionado.')
        left, right = st.columns(2)
        with left:
            st.subheader('Severidade dos alertas')
            count_chart(summary['severidade'], 'Severidade')
            st.subheader('Status da triagem')
            count_chart(summary['status'], 'Status')
        with right:
            st.subheader('Classificação dos incidentes')
            count_chart(summary['classificacao'], 'Classificação')
            st.subheader('IPs com mais falhas · período do gráfico')
            failures = pd.Series([e['ip'] for e in chart_events if e['kind'] == 'failure'], dtype='str').value_counts().head(10)
            count_chart(failures.to_dict(), 'IP')
    else:
        st.info('Nenhum evento neste ambiente. Importe um arquivo autorizado na barra lateral ou selecione Demonstração para experimentar.')
elif page == 'Eventos':
    st.subheader('Pesquisa de eventos')
    ip_filter = st.text_input('IP ou parte do IP')
    user_filter = st.text_input('Usuário ou parte do usuário')
    hosts = st.multiselect('Hosts', sorted({e['host'] for e in events}))
    kinds = st.multiselect('Tipos', ['failure', 'success', 'other'], default=['failure', 'success', 'other'])
    filtered = [e for e in events if e['kind'] in kinds and ip_filter in (e['ip'] or '')
                and user_filter in (e['username'] or '') and (not hosts or e['host'] in hosts)]
    filtered = filter_dates(filtered, 'event-period', 'Período dos eventos (UTC)')
    if filtered:
        st.dataframe([{k: e[k] for k in ('timestamp', 'host', 'ip', 'username', 'service', 'kind')} for e in filtered], width='stretch', hide_index=True)
        with st.expander('Consultar linha original'):
            by_id = {e['id']: e for e in filtered}
            selected_event = st.selectbox('Evento', list(by_id), format_func=lambda key: f"{by_id[key]['timestamp']} · {by_id[key]['host']} · {by_id[key]['kind']} · {key[:8]}")
            st.caption(selected_event)
            st.code(by_id[selected_event]['raw'], language=None)
    else:
        st.info('Nenhum evento para os filtros selecionados.')
    st.caption(f'{len(filtered)} eventos encontrados. failure = falha; success = sucesso; other = evento normal/outro.')
else:
    report_page = page == 'Relatórios'
    st.subheader('Relatórios de investigação' if report_page else 'Fila de alertas e incidentes')
    st.caption('Selecione um registro para editar a narrativa salva e exportar as evidências.' if report_page else 'Filtre a fila, consulte as evidências e registre a decisão do analista.')
    with st.expander('Filtros da fila'):
        statuses = st.multiselect('Status', STATUSES, default=list(STATUSES))
        severity = st.multiselect('Severidade', ['Alta', 'Crítica'], default=['Alta', 'Crítica'])
        classes = st.multiselect('Classificações', CLASSIFICATIONS, default=list(CLASSIFICATIONS))
        rule_filter = st.multiselect('Regras', list(RULES), default=list(RULES))
        queue_ip = st.text_input('IP do incidente')
        queue_host = st.text_input('Host do incidente')
        include_archived = st.checkbox('Incluir detecções históricas')
    queue = [a for a in alerts if a['status'] in statuses and a['severity'] in severity
             and a['classification'] in classes and a['rule'] in rule_filter
             and queue_ip in a['ip'] and queue_host in a['host'] and (a['active'] or include_archived)]
    queue = filter_dates(queue, 'incident-period', 'Período dos alertas (UTC)')
    if queue:
        st.dataframe([{k: a[k] for k in ('rule', 'severity', 'host', 'ip', 'timestamp', 'status', 'classification')} for a in queue], width='stretch', hide_index=True)
        by_id = {a['id']: a for a in queue}
        selected = st.selectbox('Abrir alerta', list(by_id), format_func=lambda key: f"{by_id[key]['rule']} · {by_id[key]['host']} · {by_id[key]['ip']} · {by_id[key]['timestamp']}", key='selected-alert')
        render_investigation(store, by_id[selected], report_only=report_page)
    else:
        st.info('Nenhum alerta para os filtros selecionados. Cenários de atividade normal podem não gerar alertas.')
