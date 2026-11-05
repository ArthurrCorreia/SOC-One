"""Console operacional local. Inicialização: bash run.sh."""
from datetime import datetime, time, timezone
import streamlit as st
from soc_one.demo import DemoWorkspace, SCENARIOS
from soc_one.storage import Store
from soc_one.ui_components import theme, heading, period_text
from soc_one.viewmodels import within_period
from soc_one.ui_pages import overview, event_explorer, investigation_page, detection_rules, jump_current, preserve_filters

PAGES = {
    'Overview': 'Prioridades e atividade do período selecionado',
    'Event Explorer': 'Pesquisa de logs, campos extraídos e relações observáveis',
    'Alert Queue': 'Fila de detecções para investigação e triagem',
    'Incidents': 'Acompanhamento do caso, evidências e decisões do analista',
    'Detection Rules': 'Condições implementadas, cobertura e referências',
    'Reports': 'Documentação manual, revisão de evidências e exportação',
}


def switch_workspace(token):
    if st.session_state.get('workspace') != token:
        for key in list(st.session_state):
            if key not in ('mode', 'scenario', 'page'):
                del st.session_state[key]
        st.session_state['workspace'] = token


st.set_page_config(page_title='SOC-One | Operations', layout='wide', initial_sidebar_state='expanded')
preserve_filters()
theme()
with st.sidebar:
    st.html('<div class="soc-brand">SOC-One<small>SECURITY OPERATIONS · LOCAL</small></div>')
    page = st.radio('Navegação', list(PAGES), key='page', label_visibility='collapsed')
    st.divider()
    mode = st.selectbox('Origem dos dados', ['Demonstração', 'Dados locais'], key='mode')
    if mode == 'Demonstração':
        scenario = st.selectbox('Cenário simulado', list(SCENARIOS), format_func=lambda key: SCENARIOS[key]['title'], key='scenario')
        manager = DemoWorkspace()
        try:
            store, generation = manager.open(scenario)
        except (ValueError, OSError) as exc:
            st.error(str(exc))
            st.stop()
        switch_workspace(('demo', scenario, generation))
        environment = 'SIMULADO · ' + SCENARIOS[scenario]['title']
        with st.expander('Contexto do cenário'):
            st.caption(SCENARIOS[scenario]['guide'])
            st.caption('Resultado inicial: ' + SCENARIOS[scenario]['expected'])
        with st.expander('Reiniciar demonstração'):
            st.warning('Apaga somente a investigação deste cenário e recarrega os logs fictícios. Dados locais e outros cenários são preservados.')
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
        environment = 'LOCAL · Dados importados'
        with st.expander('Importar logs autorizados'):
            st.caption('UTF-8 · até 5 MB · sem coleta automática. Bancos antigos podem conter exemplos já importados.')
            year = st.number_input('Ano dos logs sem ano', 1970, 2100, datetime.now().year)
            offset = st.number_input('Deslocamento UTC dos logs sem fuso (horas)', -12, 14, 0)
            st.caption('Separe arquivos que atravessem a virada do ano.')
            upload = st.file_uploader('Arquivo de autenticação', type=['log', 'txt'])
            if st.button('Importar arquivo', disabled=upload is None):
                try:
                    if upload.size > 5 * 1024 * 1024:
                        raise ValueError('O arquivo excede 5 MB.')
                    result = store.import_text(upload.getvalue().decode('utf-8-sig'), int(year), int(offset), upload.name)
                    st.success(f"{result['inseridos']} eventos novos · {result['novos_alertas']} alertas novos · {result['repetidos']} repetidos · {result['ignorados']} linhas inválidas.")
                except (UnicodeError, ValueError) as exc:
                    st.error(str(exc))
    events, alerts = store.events(), store.alerts()
    st.divider()
    period_mode = st.selectbox('Período de análise', ['Todo o histórico', 'Personalizado'], key='period-mode')
    period = None
    valid_period = True
    if period_mode == 'Personalizado':
        dates = [datetime.fromisoformat(e['timestamp']).date() for e in events]
        today = datetime.now(timezone.utc).date()
        date_range = st.date_input('Intervalo de datas UTC', value=(min(dates) if dates else today, max(dates) if dates else today), key='period-dates')
        start_time = st.time_input('Horário inicial UTC', value=time.min, key='period-start')
        end_time = st.time_input('Horário final UTC', value=time(23, 59, 59), key='period-end')
        if len(date_range) != 2:
            valid_period = False
        else:
            period = (datetime.combine(date_range[0], start_time, timezone.utc), datetime.combine(date_range[1], end_time, timezone.utc))
            valid_period = period[0] <= period[1]
        if not valid_period:
            st.error('Informe um intervalo completo com início anterior ou igual ao fim.')
    st.caption('Salve rascunhos antes de trocar de página ou ambiente. As alterações salvas ficam no SQLite.')

period_label = period_text(period, events) if valid_period else 'Intervalo incompleto ou inválido'
title_col, action_col = st.columns([5, 1], vertical_alignment='center')
with title_col:
    heading(page, PAGES[page], environment, period_label)
with action_col:
    actions = {
        'Overview': ('Abrir fila', 'Alert Queue'),
        'Event Explorer': ('Ver alertas', 'Alert Queue'),
        'Alert Queue': ('Explorar eventos', 'Event Explorer'),
        'Incidents': ('Abrir relatórios', 'Reports'),
        'Detection Rules': ('Consultar fila', 'Alert Queue'),
        'Reports': ('Investigar caso', 'Incidents'),
    }
    label, destination = actions[page]
    st.button(label, on_click=jump_current, args=(destination,), width='stretch')
if not valid_period:
    st.info('A consulta aguarda um intervalo válido. Nenhum registro foi alterado.')
    st.stop()
scoped_events = within_period(events, period)
scoped_alerts = within_period(alerts, period)
if page == 'Overview':
    overview(scoped_events, scoped_alerts)
elif page == 'Event Explorer':
    event_explorer(scoped_events, events)
elif page == 'Detection Rules':
    detection_rules(scoped_alerts)
else:
    investigation_page(store, scoped_alerts, page)
