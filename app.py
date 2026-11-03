"""Execute na raiz do projeto: streamlit run app.py."""
from datetime import datetime
from pathlib import Path
import pandas as pd
import streamlit as st
from soc_one.analytics import metrics
from soc_one.catalog import RULES
from soc_one.storage import Store, STATUSES, CLASSIFICATIONS
from soc_one.ui import count_chart, filter_dates, render_investigation

st.set_page_config(page_title='SOC-One | Central de triagem', page_icon='🛡️', layout='wide')
store = Store()
st.title('SOC-One')
st.caption('LABORATÓRIO SOC N1 · Detecção, investigação e documentação de autenticação SSH')
with st.sidebar:
    st.header('Coleta de eventos')
    st.caption('Importe somente logs simulados ou autorizados. Limite: 5 MB, UTF-8.')
    year = st.number_input('Ano dos logs sem ano', 1970, 2100, datetime.now().year)
    offset = st.number_input('Deslocamento UTC dos logs sem fuso (horas)', -12, 14, 0)
    st.caption('Arquivos que atravessam a virada do ano devem ser separados. Horários exibidos em UTC.')
    upload = st.file_uploader('Arquivo de autenticação', type=['log', 'txt'])
    if st.button('Importar arquivo', disabled=upload is None):
        try:
            if upload.size > 5 * 1024 * 1024:
                raise ValueError('O arquivo excede 5 MB.')
            result = store.import_text(upload.getvalue().decode('utf-8-sig'), int(year), int(offset), upload.name)
            st.success(str(result))
        except (UnicodeError, ValueError) as exc:
            st.error(str(exc))
    if st.button('Carregar demonstração'):
        sample = Path(__file__).parent / 'samples/demo.log'
        st.success(str(store.import_text(sample.read_text(encoding='utf-8'), 2026, source=sample.name)))
    if st.button('Carregar cenário multiusuário'):
        sample = Path(__file__).parent / 'samples/multiuser.log'
        st.success(str(store.import_text(sample.read_text(encoding='utf-8'), 2026, source=sample.name)))
    st.divider()
    st.caption('SSH-001 · ≥5 falhas / 5 min\n\nSSH-002 · sucesso após ≥3 falhas da mesma conta / 5 min\n\nSSH-003 · ≥5 falhas contra ≥3 contas / 5 min')
    st.info('Correlação por IP e host. Nenhuma ação de contenção é automática.')

events, alerts = store.events(), store.alerts()
summary = metrics(alerts)
cols = st.columns(3)
cols[0].metric('Eventos coletados', len(events))
cols[1].metric('Alertas detectados', summary['total'])
cols[2].metric('Incidentes em aberto', summary['abertos'])
cols = st.columns(3)
cols[0].metric('Com triagem registrada', summary['triados'])
cols[1].metric('Escalonados', summary['escalonados'])
cols[2].metric('Taxa de encerramento', f"{summary['taxa_encerramento']:.1f}%")
st.caption(f"Indicadores globais das detecções atuais. {summary['historicos']} registros históricos preservados. Cada alerta possui um registro de acompanhamento; não representa confirmação de incidente.")
overview, event_tab, alert_tab = st.tabs(['Visão geral', 'Eventos', 'Investigação'])
with overview:
    if events:
        chart_events = filter_dates(events, 'chart-period', 'Período do gráfico (UTC)')
        st.subheader('Eventos por minuto · UTC')
        if chart_events:
            frame = pd.DataFrame(chart_events)
            # Agrupamento esparso evita criar milhões de minutos vazios em logs de anos distintos.
            frame['minuto'] = pd.to_datetime(frame['timestamp'], utc=True).dt.floor('min')
            series = frame.groupby('minuto').size().rename('Eventos').reset_index()
            st.vega_lite_chart(series, {'mark': {'type': 'bar', 'color': '#38bdf8'},
                'encoding': {'x': {'field': 'minuto', 'type': 'temporal', 'scale': {'type': 'utc'}, 'title': 'UTC'},
                             'y': {'field': 'Eventos', 'type': 'quantitative'},
                             'tooltip': [{'field': 'minuto', 'type': 'temporal'}, {'field': 'Eventos'}]}}, width='stretch')
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
        st.info('Carregue a demonstração ou importe um arquivo para começar.')
with event_tab:
    st.subheader('Pesquisa de eventos')
    ip_filter = st.text_input('IP ou parte do IP')
    user_filter = st.text_input('Usuário ou parte do usuário')
    hosts = st.multiselect('Hosts', sorted({e['host'] for e in events}))
    kinds = st.multiselect('Tipos', ['failure', 'success', 'other'], default=['failure', 'success', 'other'])
    filtered = [e for e in events if e['kind'] in kinds and ip_filter in (e['ip'] or '')
                and user_filter in (e['username'] or '') and (not hosts or e['host'] in hosts)]
    filtered = filter_dates(filtered, 'event-period', 'Período dos eventos (UTC)')
    st.dataframe(filtered, width='stretch', hide_index=True)
    st.caption(f'{len(filtered)} eventos encontrados. failure = falha; success = sucesso; other = evento normal/outro.')
with alert_tab:
    st.subheader('Fila de investigação')
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
    st.dataframe([{k: a[k] for k in ('rule', 'severity', 'host', 'ip', 'timestamp', 'status', 'classification', 'active')} for a in queue], width='stretch', hide_index=True)
    if queue:
        by_id = {a['id']: a for a in queue}
        selected = st.selectbox('Abrir alerta', list(by_id), format_func=lambda key: f"{by_id[key]['rule']} · {by_id[key]['host']} · {by_id[key]['ip']} · {by_id[key]['timestamp']}")
        render_investigation(store, by_id[selected])
    else:
        st.info('Nenhum alerta para os filtros selecionados.')
