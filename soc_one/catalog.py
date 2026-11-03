"""Catálogo local inspirado nos metadados Sigma, sem compatibilidade de execução Sigma."""
RULES = {
    'SSH-001': {
        'id': 'SSH-001', 'title': 'Possível brute force SSH', 'revision': 2,
        'status': 'experimental', 'description': 'Falhas repetidas na mesma origem e destino.',
        'logsource': {'product': 'linux', 'service': 'sshd'},
        'detection': {'event': 'failure', 'group_by': ['ip', 'host'], 'window_seconds': 300, 'threshold': 5},
        'level': 'high', 'severity': 'Alta', 'tags': ['attack.t1110'],
        'falsepositives': ['Erros de senha', 'Automação com credencial desatualizada', 'NAT compartilhado'],
        'references': ['https://attack.mitre.org/techniques/T1110/'],
    },
    'SSH-002': {
        'id': 'SSH-002', 'title': 'Sucesso após falhas para a mesma conta', 'revision': 2,
        'status': 'experimental', 'description': 'Possível uso indevido de conta; não confirma comprometimento.',
        'logsource': {'product': 'linux', 'service': 'sshd'},
        'detection': {'event': 'success', 'group_by': ['ip', 'host', 'username'], 'window_seconds': 300, 'threshold': 3},
        'level': 'critical', 'severity': 'Crítica', 'tags': ['attack.t1110', 'attack.t1078'],
        'falsepositives': ['Usuário legítimo corrigindo senha', 'Automação corrigida'],
        'references': ['https://attack.mitre.org/techniques/T1110/', 'https://attack.mitre.org/techniques/T1078/'],
    },
    'SSH-003': {
        'id': 'SSH-003', 'title': 'Tentativas SSH contra múltiplos usuários', 'revision': 1,
        'status': 'experimental', 'description': 'Falhas contra contas distintas; não comprova password spraying.',
        'logsource': {'product': 'linux', 'service': 'sshd'},
        'detection': {'event': 'failure', 'group_by': ['ip', 'host'], 'window_seconds': 300, 'threshold': 5, 'distinct_users': 3},
        'level': 'high', 'severity': 'Alta', 'tags': ['attack.t1110'],
        'falsepositives': ['Bastion compartilhado', 'Validação autorizada de contas'],
        'references': ['https://attack.mitre.org/techniques/T1110/'],
    },
}
