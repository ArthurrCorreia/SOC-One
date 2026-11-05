"""Componentes nativos e HTML próprio, sem seletores internos do Streamlit."""
from hashlib import sha256
from html import escape
from datetime import datetime
import pandas as pd
import streamlit as st

COLORS = {'Crítica': '#f2a6a6', 'Alta': '#e5bd7a', 'Média': '#c9cc86', 'Baixa': '#91bac8'}
LABELS = {'id': 'ID', 'rule': 'Regra', 'severity': 'Severidade', 'ip': 'IP de origem', 'host': 'Host',
          'timestamp': 'Horário UTC', 'status': 'Status', 'classification': 'Classificação',
          'username': 'Usuário', 'kind': 'Tipo', 'service': 'Serviço', 'updated_at': 'Última alteração UTC'}


def theme():
    # Apenas classes próprias deste aplicativo. Nenhum atributo interno de widgets.
    st.html('''<style>
    .soc-heading{display:flex;justify-content:space-between;align-items:center;gap:1rem;border-bottom:1px solid #343e4b;padding:0 0 .8rem;margin-bottom:.2rem;flex-wrap:wrap}
    .soc-heading h1{font:600 1.6rem/1.3 sans-serif;margin:0;color:#e6eaf0}
    .soc-heading p{font:400 .88rem/1.5 sans-serif;margin:.25rem 0 0;color:#adb7c5}
    .soc-context{font:500 .8rem/1.7 sans-serif;color:#b9c4d2;text-align:right}
    .soc-brand{font:650 1.3rem/1.3 sans-serif;color:#e6eaf0;letter-spacing:.04em;padding-bottom:.2rem}
    .soc-brand small{display:block;font:400 .75rem/1.8 sans-serif;color:#9eacbd;letter-spacing:.04em}
    .soc-badges{display:flex;align-items:center;gap:.5rem;flex-wrap:wrap;margin:.15rem 0 .6rem}
    .soc-badge{font:500 .8rem/1.4 sans-serif;border:1px solid #46515f;border-radius:3px;padding:.2rem .45rem;color:#d8dee8}
    .soc-critical{color:#f2a6a6;border-color:#805556;background:#302126}
    .soc-high{color:#e5bd7a;border-color:#77603d;background:#2b2620}
    .soc-metric{border-top:2px solid #5f819f;border-bottom:1px solid #343e4b;padding:.55rem 0 .65rem;min-width:115px}
    .soc-metric span{display:block;color:#b7c1cf;font:400 .82rem/1.4 sans-serif}
    .soc-metric strong{display:block;color:#eef1f5;font:600 1.8rem/1.3 sans-serif;padding-top:.2rem}
    .soc-metrics{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:1rem;margin:.5rem 0 1rem}
    @media(max-width:1000px){.soc-metrics{grid-template-columns:repeat(3,minmax(0,1fr))}.soc-context{text-align:left}}
    @media(max-width:600px){.soc-metrics{grid-template-columns:repeat(2,minmax(0,1fr))}}
    </style>''')


def heading(title, description, environment, period_label):
    st.html(f'<header class="soc-heading"><div><h1>{escape(title)}</h1><p>{escape(description)}</p></div>'
            f'<div class="soc-context">{escape(environment)}<br>{escape(period_label)}<br>Dados estáticos · atualização por importação</div></header>')


def badges(severity, status, classification):
    kind = 'soc-critical' if severity == 'Crítica' else 'soc-high' if severity == 'Alta' else ''
    st.html('<div class="soc-badges">' + ''.join(
        f'<span class="soc-badge {css}">{escape(label)}</span>'
        for label, css in [(severity, kind), (status, ''), (classification, '')]) + '</div>')


def metric_strip(summary):
    labels = [('events', 'Eventos'), ('open', 'Alertas abertos'), ('analysis', 'Em análise'),
              ('critical', 'Críticos abertos'), ('escalated', 'Escalonados')]
    st.html('<div class="soc-metrics">' + ''.join(
        f'<div class="soc-metric"><span>{label}</span><strong>{summary[key]}</strong></div>' for key, label in labels) + '</div>')


def multi_filter(label, options, key, **kwargs):
    """Inicializa todos selecionados sem conflitar com filtros retidos na sessão."""
    st.session_state.setdefault(key, list(options))
    return st.multiselect(label, options, key=key, **kwargs)


def table(rows, fields, *, key=None, selectable=False, callback=None, max_rows=10):
    frame = pd.DataFrame([{k: r.get(k) for k in fields} for r in rows], columns=fields)
    config = {key: st.column_config.TextColumn(LABELS.get(key, key)) for key in fields}
    if 'id' in frame:
        frame['id'] = frame['id'].str[:10]
        config['id'] = st.column_config.TextColumn('ID', help='Identificador abreviado. O ID completo fica nos detalhes.', width='small')
    if 'timestamp' in frame:
        frame['timestamp'] = pd.to_datetime(frame['timestamp'], utc=True)
        config['timestamp'] = st.column_config.DatetimeColumn('Horário UTC', format='DD/MM HH:mm:ss', width='small')
    if 'kind' in frame:
        frame['kind'] = frame['kind'].map({'failure': 'Falha', 'success': 'Sucesso', 'other': 'Outro'}).fillna(frame['kind'])
    display = frame
    if 'severity' in frame:
        display = frame.style.map(lambda v: f'color: {COLORS.get(v, "#d8dee8")}; font-weight: 600', subset=['severity'])
    return st.dataframe(display, hide_index=True, width='stretch', row_height=30,
                        height=min(len(rows), max_rows) * 30 + 38, column_config=config, key=key,
                        on_select=callback if selectable else 'ignore', selection_mode='single-row')


def selectable_table(rows, fields, namespace, *, shared_key=None, label='Abrir alerta'):
    """Índices da tabela sempre vinculados à mesma sequência filtrada de IDs."""
    ids = [r['id'] for r in rows]
    key = namespace + '-selected'
    if st.session_state.get(key) not in ids:
        preferred = st.session_state.get(shared_key) if shared_key else None
        st.session_state[key] = preferred if preferred in ids else ids[0]
    fingerprint = sha256('|'.join(ids).encode()).hexdigest()[:12]
    table_key = f'{namespace}-table-{fingerprint}'

    def select_row():
        selection = st.session_state[table_key]['selection']['rows']
        if selection and selection[0] < len(ids):
            st.session_state[key] = ids[selection[0]]
            if shared_key:
                st.session_state[shared_key] = st.session_state[key]

    table(rows, fields, key=table_key, selectable=True, callback=select_row)
    by_id = {r['id']: r for r in rows}
    def select_control():
        if shared_key:
            st.session_state[shared_key] = st.session_state[key]
    selected = st.selectbox(label, ids, key=key, on_change=select_control,
                            format_func=lambda value: f"{value[:10]} · {by_id[value].get('rule', by_id[value].get('kind', ''))} · {by_id[value].get('ip') or 'sem IP'} · {by_id[value]['timestamp'][:19].replace('T', ' ')} UTC")
    if shared_key:
        st.session_state[shared_key] = selected
    return by_id[selected]


def event_series(events):
    if not events:
        st.caption('Nenhum evento no período selecionado.')
        return
    frame = pd.DataFrame(events)
    frame['minuto'] = pd.to_datetime(frame['timestamp'], utc=True).dt.floor('min')
    series = frame.groupby('minuto').size().rename('Eventos').reset_index()
    series['Horário UTC'] = series['minuto'].dt.strftime('%d/%m/%Y %H:%M UTC')
    tick_format = '%d/%m %H:%M' if series['minuto'].dt.date.nunique() > 1 else '%H:%M'
    st.vega_lite_chart(series, {'height': 155, 'mark': {'type': 'bar', 'color': '#819bb4'},
        'encoding': {'x': {'field': 'minuto', 'type': 'temporal', 'scale': {'type': 'utc'}, 'title': 'UTC', 'axis': {'format': tick_format, 'tickCount': 6}},
                     'y': {'field': 'Eventos', 'type': 'quantitative', 'axis': {'tickMinStep': 1}},
                     'tooltip': [{'field': 'Horário UTC', 'type': 'nominal'}, {'field': 'Eventos'}]}}, width='stretch')


def period_text(period, rows):
    if period is not None:
        start, end = period
    elif rows:
        start = min(datetime.fromisoformat(r['timestamp']) for r in rows)
        end = max(datetime.fromisoformat(r['timestamp']) for r in rows)
    else:
        return 'UTC · nenhum evento disponível'
    return f'{start:%d/%m/%Y %H:%M} → {end:%d/%m/%Y %H:%M} UTC'
