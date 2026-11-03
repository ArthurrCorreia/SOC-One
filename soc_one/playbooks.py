"""Procedimentos manuais; marcar uma etapa não executa ações na rede."""
COMMON_START = (
    ('validate', 'N1 · Validar horários UTC, origem, host e integridade das linhas de evidência.'),
    ('context', 'N1 · Consultar inventário e atividade autorizada; registrar a fonte da confirmação.'),
)
COMMON_END = (
    ('assess', 'N1 · Registrar evidências, classificação e lacunas; justificar encerramento ou escalonamento.'),
    ('handoff', 'N1 → N2 · Se houver suspeita não esclarecida, registrar escopo, IPs, contas, horários e motivo; encaminhar conforme procedimento local. Se não aplicável, justificar nas observações.'),
    ('n2', 'N2 · Após escalonamento, validar a hipótese com fontes adicionais e decidir contenção autorizada. Registrar retorno ou não aplicabilidade; nenhuma ação é automática.'),
)
PLAYBOOKS = {
    'SSH-001': COMMON_START + (
        ('attempts', 'N1 · Conferir frequência das falhas e verificar automações com credenciais desatualizadas.'),
        ('successes', 'N1 · Pesquisar sucessos relacionados no host e registrar o resultado da busca.'),
    ) + COMMON_END,
    'SSH-002': COMMON_START + (
        ('account', 'N1 · Validar com o responsável se a conta, a origem e o sucesso são reconhecidos.'),
        ('activity', 'N1 · Solicitar registros da sessão ao N2 se houver atividade não reconhecida; não presumir execução de comandos.'),
    ) + COMMON_END,
    'SSH-003': COMMON_START + (
        ('users', 'N1 · Enumerar contas atingidas e conferir se a origem é NAT, bastion ou teste autorizado.'),
        ('scope', 'N1 · Pesquisar sucessos dessas contas e registrar hosts e horários para delimitar o escopo.'),
    ) + COMMON_END,
}
