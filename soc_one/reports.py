"""Relatórios: dados observados com proveniência e narrativa exclusivamente manual."""
import json

REPORT_FIELDS = {
    'descricao': 'Descrição do ocorrido',
    'linha_do_tempo': 'Linha do tempo da investigação',
    'evidencias_adicionais': 'Evidências adicionais e suas fontes',
    'indicadores': 'Indicadores adicionais e suas fontes',
    'impacto': 'Impacto observado',
    'analise': 'Análise',
    'acoes': 'Ações realizadas',
    'conclusao': 'Conclusão',
}


def objective_data(events, sources):
    return {
        'origem': 'Campos extraídos dos eventos abaixo; não constituem avaliação do analista.',
        'inicio_utc': events[0]['timestamp'] if events else None,
        'fim_utc': events[-1]['timestamp'] if events else None,
        'ips': sorted({e['ip'] for e in events if e['ip']}),
        'hosts': sorted({e['host'] for e in events}),
        'usuarios': sorted({e['username'] for e in events if e['username']}),
        'linha_do_tempo': [
            {k: e[k] for k in ('id', 'timestamp', 'host', 'ip', 'username', 'kind')} for e in events
        ],
        'eventos': events,
        'fontes': sources,
    }


def markdown_report(report):
    """Texto externo permanece em blocos literais para evitar interpretação de Markdown."""
    def block(value):
        if not isinstance(value, str):
            value = json.dumps(value, indent=2, ensure_ascii=False)
        return '\n'.join('    ' + line for line in (value or 'Não informado.').splitlines())

    alert, document = report['alerta'], report['documento']
    facts = report['dados_objetivos']
    parts = ['# SOC-One — Relatório de investigação', report['aviso'],
             '## Ambiente dos dados', block(report.get('ambiente', {'tipo': 'não informado'}))]
    parts += ['## Identificação e estado atual']
    for title, value in [
        ('Identificador', alert['id']), ('Regra', alert['rule']),
        ('Severidade', alert['severity']), ('Status', alert['status']),
        ('Classificação', alert['classification']), ('Host', alert['host']),
        ('IP de origem', alert['ip']), ('Evento disparador (UTC)', alert['timestamp']),
        ('Observações de triagem', alert['notes']), ('Justificativa de encerramento', alert['justification']),
    ]:
        parts += [f'### {title}', block(value)]
    parts += ['## Controle do documento',
              f"Versão: {document['version']}. Narrativa preenchida manualmente pelo analista.",
              'Salvo em (UTC):', block(document['salvo_em'] or 'Ainda não salvo.'),
              'Exportado em (UTC):', block(document['exportado_em']),
              ('Os dados objetivos correspondem à correlação atual.' if document['dados_objetivos_atualizados']
               else 'ATENÇÃO: existem dados objetivos mais recentes; esta exportação preserva a cópia salva.'),
              document['estado_operacional'],
              '## Regra e referências ATT&CK', block(report['regra']),
              '## Resumo dos dados objetivos',
              'Intervalo dos eventos (UTC):', block({'inicio': facts['inicio_utc'], 'fim': facts['fim_utc']}),
              'IPs, hosts e contas extraídos dos eventos:',
              block({key: facts[key] for key in ('ips', 'hosts', 'usuarios')}),
              '## Linha do tempo dos eventos', block(facts['linha_do_tempo']),
              '## Investigação manual',
              'Ausência de conteúdo significa não informado. Ações e conclusões não são geradas automaticamente.']
    for key, title in REPORT_FIELDS.items():
        parts += [f'### {title}', block(report['investigacao'].get(key, ''))]
    parts += ['## Playbook — estado atual']
    for step in report['playbook']['etapas']:
        parts += [f"- [{'x' if step['concluida'] else ' '}] {step['procedimento']}"]
    parts += ['## Evidências e proveniência',
              'Linhas dos logs e IDs de eventos:', block(facts['eventos']),
              'Origem de importação (nome informado, linha, SHA-256 do texto UTF-8 e parâmetros):', block(facts['fontes']),
              'Eventos legados sem origem de importação registrada:', block(facts['fontes_ausentes']),
              '## Histórico de alterações', block(report['historico'])]
    return '\n\n'.join(parts) + '\n'
