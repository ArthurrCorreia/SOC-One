"""Páginas operacionais compostas a partir dos registros e componentes comuns."""
from collections import Counter
import streamlit as st
from .analytics import metrics
from .catalog import RULES
from .storage import STATUSES, CLASSIFICATIONS
from .ui_components import table, selectable_table, event_series, metric_strip, multi_filter
from .ui import render_investigation
from .viewmodels import event_results, alert_results, contextual_events, operational_summary

ALERT_FIELDS = ('id', 'rule', 'severity', 'ip', 'host', 'timestamp', 'status', 'classification')
EVENT_FIELDS = ('timestamp', 'ip', 'host', 'username', 'kind')


def preserve_filters():
    """Desvincula filtros da limpeza de widgets ocultos ao trocar de seção."""
    keys = [f'{page}-{field}' for page in ('Alert Queue', 'Incidents', 'Reports')
            for field in ('query', 'ip', 'host', 'statuses', 'severity', 'rules', 'classes', 'archived', 'order', 'selected')]
    keys += ['event-' + field for field in ('query', 'ip', 'user', 'hosts', 'kinds', 'order')]
    keys += ['events-selected', 'reports-only-saved']
    for key in keys:
        if key in st.session_state:
            st.session_state[key] = st.session_state[key]


def jump(page, alert_id=None, **state):
    st.session_state['page'] = page
    if alert_id:
        st.session_state['current-alert'] = alert_id
        # O destino pode ter uma seleção anterior: a ação explícita tem precedência.
        st.session_state.pop(page + '-selected', None)
        if page in ('Incidents', 'Reports'):
            # Uma ação para abrir um caso não pode escolher outro devido a filtros antigos.
            # Os filtros da fila de origem continuam preservados.
            for field in ('query', 'ip', 'host', 'statuses', 'severity', 'rules', 'classes'):
                st.session_state.pop(page + '-' + field, None)
            st.session_state[page + '-archived'] = True
            st.session_state.pop('reports-only-saved', None)
    st.session_state.update(state)


def jump_current(page):
    # O cabeçalho é renderizado antes da seleção da tabela; lê o ID no clique.
    jump(page, st.session_state.get('current-alert'))


def overview(events, alerts):
    summary = operational_summary(events, alerts)
    metric_strip(summary)
    left, right = st.columns([3, 2])
    with left:
        with st.container(border=True):
            st.markdown('**Atividade de autenticação**')
            event_series(events)
    with right:
        with st.container(border=True):
            st.markdown('**Alertas abertos por severidade**')
            rows = [{'severity': severity, 'Abertos': summary['severity'].get(severity, 0)} for severity in ('Crítica', 'Alta')]
            table(rows, ('severity', 'Abertos'))
            st.caption('Contagens do período. Crítico não equivale a comprometimento confirmado.')
    left, right = st.columns([2, 3])
    with left:
        st.markdown('**Detecções mais frequentes**')
        rows = [{'Regra': r, 'Detecções': count, 'Descrição': RULES.get(r, {}).get('title', r)}
                for r, count in sorted(summary['rules'].items(), key=lambda x: (-x[1], x[0]))]
        if rows:
            table(rows, ('Regra', 'Detecções', 'Descrição'))
        else:
            st.caption('Nenhuma detecção no período.')
        st.button('Abrir Alert Queue', on_click=jump, args=('Alert Queue',), width='stretch')
    with right:
        st.markdown('**Incidentes recentes que exigem atenção**')
        current = [a for a in alerts if a['active'] and a['status'] != 'Encerrado']
        current = sorted(current, key=lambda a: (a['timestamp'], a['id']), reverse=True)[:5]
        if current:
            table(current, ('id', 'severity', 'ip', 'status', 'timestamp'))
            st.button('Investigar em Incidents', on_click=jump, args=('Incidents', current[0]['id']))
        else:
            st.caption('Nenhum incidente aberto no período. Consulte a fila para revisar os encerrados.')
    if not events:
        st.info('Nenhum evento no período. Ajuste o intervalo ou importe logs em Dados locais.')
    with st.expander('Indicadores de triagem e classificação'):
        stats = metrics(alerts)
        st.caption(f"{stats['total']} detecções atuais · {stats['triados']} com triagem registrada · {stats['encerrados']} encerradas · taxa de encerramento {stats['taxa_encerramento']:.1f}% · {stats['historicos']} históricas")
        left, middle, right = st.columns(3)
        with left:
            table([{'Status': k, 'Total': v} for k, v in stats['status'].items()], ('Status', 'Total'))
        with middle:
            table([{'Classificação': k, 'Total': v} for k, v in stats['classificacao'].items()], ('Classificação', 'Total'))
        with right:
            failures = Counter(e['ip'] for e in events if e['kind'] == 'failure' and e['ip'])
            table([{'ip': ip, 'Falhas': count} for ip, count in failures.most_common(10)], ('ip', 'Falhas'))


def event_explorer(events, all_events):
    query, ip, user = st.columns([3, 2, 2])
    with query:
        text = st.text_input('Pesquisar texto nos eventos', placeholder='Texto literal, usuário, IP ou trecho do log', key='event-query')
    with ip:
        origin = st.text_input('IP ou parte do IP', key='event-ip')
    with user:
        username = st.text_input('Usuário ou parte do usuário', key='event-user')
    hosts_col, kinds_col, sort_col = st.columns([2, 2, 1])
    with hosts_col:
        hosts = st.multiselect('Hosts', sorted({e['host'] for e in all_events}), key='event-hosts')
    with kinds_col:
        kinds = multi_filter('Tipos', ['failure', 'success', 'other'], key='event-kinds',
                               format_func=lambda value: {'failure': 'Falha', 'success': 'Sucesso', 'other': 'Outro'}[value])
    with sort_col:
        order = st.selectbox('Ordem dos eventos', ['Mais recentes', 'Mais antigos'], key='event-order')
    rows = event_results(events, query=text, ip=origin, user=username, hosts=hosts, kinds=kinds)
    rows = sorted(rows, key=lambda e: (e['timestamp'], e['id']), reverse=order == 'Mais recentes')
    st.caption(f'{len(rows)} de {len(events)} eventos no período · filtros combinados por E · pesquisa textual literal, sem linguagem de consultas')
    if not rows:
        st.info('Nenhum evento para os filtros selecionados.')
        return
    event = selectable_table(rows, EVENT_FIELDS, 'events', label='Evento')
    with st.container(border=True):
        st.markdown('**Registro selecionado · campos extraídos pelo parser**')
        table([event], ('timestamp', 'service', 'ip', 'host', 'username', 'kind'))
        st.caption('ID completo: ' + event['id'])
        st.code(event['raw'], language=None)
        related = contextual_events(event, all_events)
        with st.expander(f'Relações observáveis · {len(related)} outros eventos'):
            st.caption('Mesmo IP e host, até cinco minutos antes ou depois. Considera todo o histórico deste ambiente; não comprova causalidade.')
            if related:
                table(related, EVENT_FIELDS)
            else:
                st.caption('Nenhum outro evento relacionado por esses critérios.')
        st.button('Pesquisar este IP na fila', disabled=not event['ip'], on_click=jump,
                  args=('Alert Queue',), kwargs={'Alert Queue-ip': event['ip'] or ''})


def queue_filters(alerts, page):
    query_col, ip_col, order_col = st.columns([3, 2, 2])
    with query_col:
        query = st.text_input('Pesquisar alertas', key=page + '-query', placeholder='ID, regra, host ou texto das observações')
    with ip_col:
        ip = st.text_input('IP do incidente', key=page + '-ip')
    with order_col:
        order = st.selectbox('Ordenação', ['Prioridade', 'Mais recentes', 'Mais antigos'], key=page + '-order')
    severities, states, rules = st.columns([1, 2, 2])
    with severities:
        severity = multi_filter('Severidade', ['Alta', 'Crítica'], key=page + '-severity')
    with states:
        statuses = multi_filter('Status', STATUSES, key=page + '-statuses')
    with rules:
        rule_filter = multi_filter('Regras', list(RULES), key=page + '-rules')
    with st.expander('Filtros adicionais'):
        left, right = st.columns(2)
        with left:
            classes = multi_filter('Classificações', CLASSIFICATIONS, key=page + '-classes')
        with right:
            host = st.text_input('Host do incidente', key=page + '-host')
        archived = st.checkbox('Incluir detecções históricas', key=page + '-archived')
    return alert_results(alerts, query=query, ip=ip, host=host, statuses=statuses,
                         severities=severity, rules=rule_filter, classifications=classes, archived=archived, order=order)


def investigation_page(store, alerts, page):
    if page == 'Reports':
        with st.expander('Filtrar documentos'):
            rows = queue_filters(alerts, page)
    else:
        rows = queue_filters(alerts, page)
    if not rows:
        st.info('Nenhum alerta para os filtros selecionados. Atividade normal pode não gerar detecções.')
        return
    if page == 'Reports':
        # A existência de uma versão salva vem do SQLite, nunca de um estado fictício.
        report_states = {a['id']: store.report(a['id'])['documento'] for a in rows}
        only_saved = st.checkbox('Somente relatórios salvos', key='reports-only-saved')
        if only_saved:
            rows = [a for a in rows if report_states[a['id']]['version'] > 0]
        if not rows:
            st.info('Nenhum relatório salvo para este filtro. Desmarque a opção para criar um documento a partir de um alerta.')
            return
        rows = [a | {'Documento': 'v' + str(report_states[a['id']]['version']) if report_states[a['id']]['version'] else 'Não salvo'} for a in rows]
        fields = ('id', 'rule', 'ip', 'status', 'classification', 'Documento')
    else:
        fields = ALERT_FIELDS
    st.caption(f'{len(rows)} registros · clique na linha ou use o seletor · cabeçalhos permitem ordenação na tabela')
    alert = selectable_table(rows, fields, page, shared_key='current-alert')
    if page == 'Alert Queue':
        st.button('Continuar em Incidents', on_click=jump, args=('Incidents', alert['id']))
    elif page == 'Incidents':
        st.caption('Cada incidente corresponde a um alerta neste laboratório. A fila e o período permanecem visíveis durante a investigação.')
    render_investigation(store, alert, report_only=page == 'Reports')


def detection_rules(alerts):
    counts = Counter(a['rule'] for a in alerts if a['active'])
    rows = [{'rule': key, 'Título': r['title'], 'severity': r['severity'], 'Revisão': r['revision'],
             'Detecções no período': counts.get(key, 0)} for key, r in RULES.items()]
    table(rows, ('rule', 'Título', 'severity', 'Revisão', 'Detecções no período'))
    selected = st.selectbox('Consultar regra', list(RULES), key='rule-detail', format_func=lambda key: f"{key} · {RULES[key]['title']}")
    rule = RULES[selected]
    with st.container(border=True):
        left, right = st.columns([3, 2])
        definition = rule['detection']
        with left:
            st.subheader(rule['title'])
            st.write(rule['description'])
            st.markdown('**Condição implementada**')
            st.text(f"Limiar: {definition['threshold']} falhas · janela inclusiva: {definition['window_seconds']} s")
            st.text('Agrupamento: ' + ' + '.join(definition['group_by']))
            if definition['event'] == 'success':
                st.text('Evento disparador: autenticação bem-sucedida após falhas da mesma conta.')
            if 'distinct_users' in definition:
                st.text(f"Contas distintas: pelo menos {definition['distinct_users']}")
        with right:
            st.markdown('**Falsos positivos conhecidos**')
            for value in rule['falsepositives']:
                st.text('• ' + value)
            st.caption('MITRE ATT&CK: ' + ', '.join(t.replace('attack.', '').upper() for t in rule['tags']))
        with st.expander('Metadados completos e referências'):
            st.json(rule)
    st.caption('Catálogo de consulta. Metadados inspirados no Sigma; não há editor de regras nem execução Sigma. Nenhuma regra foi alterada por esta tela.')
