# SOC-One

Laboratório local de Mini SIEM para detecção e investigação de eventos de autenticação SSH. O projeto implementa um fluxo de trabalho SOC N1: coleta de logs, correlação temporal, priorização de alertas, triagem, aplicação de playbooks e documentação de incidentes.

**Tecnologias:** Python, Streamlit, SQLite, pandas e pytest. O processamento ocorre localmente, sem IA, APIs externas, Docker ou serviços pagos.

## Funcionalidades

- Importação de arquivos syslog/auth.log em UTF-8, com normalização para UTC, validação de IPv4/IPv6 e contabilização de linhas inválidas.
- Detecção de brute force SSH, sucesso após falhas da mesma conta e tentativas contra múltiplos usuários.
- Metadados de regras inspirados no Sigma e referências a técnicas MITRE ATT&CK.
- Correlação determinística, tratamento de eventos fora de ordem e deduplicação por evento e regra.
- Incidentes com status, classificação, observações, justificativa de encerramento e histórico de alterações.
- Playbooks específicos por regra, com etapas manuais de investigação e encaminhamento N1/N2.
- Relatórios editáveis com narrativa manual, dados objetivos rastreáveis e exportação Markdown/JSON.
- Indicadores de triagem, severidade e classificação; filtros por período, IP, host, usuário, regra e estado da investigação.
- Persistência SQLite e migração aditiva de bancos da primeira versão.

Cada alerta origina um registro de acompanhamento. A quantidade de incidentes **não indica a quantidade de comprometimentos confirmados**. A classificação depende da investigação manual.

## Instalação

Requisitos: Python 3.11 ou superior, `pip` e suporte a `venv`. No Ubuntu, o pacote `python3-venv` fornece o ambiente virtual.

Na raiz do repositório:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

A interface fica disponível em `http://127.0.0.1:8501`. A configuração restringe o servidor ao endereço local e desabilita a coleta de estatísticas de uso do Streamlit. O banco é criado em `data/soc_one.db`; não há acesso automático a logs do sistema nem necessidade de permissões de root.

## Demonstração e importação

**Carregar demonstração** importa 16 eventos válidos, ignora uma linha inválida e gera três alertas. O cenário contém atividade normal, cinco falhas consecutivas, sucesso após falhas e um caso compatível com erros legítimos de digitação. Esse último contexto é apenas uma hipótese de exercício e não é inserido como conclusão.

**Carregar cenário multiusuário** importa cinco falhas contra três contas, gerando uma ocorrência SSH-001 e uma SSH-003. Esses alertas representam hipóteses diferentes sobre a mesma sequência. A carga dos dois arquivos totaliza 21 eventos e cinco alertas. A repetição da carga não duplica registros.

A importação aceita arquivos `.log` ou `.txt` em UTF-8 de até 5 MB. Para logs sem ano ou fuso, os parâmetros de ano e deslocamento UTC são informados no formulário. Logs ISO 8601 com fuso mantêm seu instante original. Arquivos RFC3164 que atravessam a virada do ano devem ser separados antes da importação.

O parser reconhece `Failed password`, `Accepted password` e `Accepted publickey` de `sshd`, incluindo `invalid user`. Outros eventos com cabeçalho válido são classificados como `other`. O formato suportado é um subconjunto de syslog/auth.log; não inclui todos os formatos de PAM ou journald.

## Regras e correlação

| Regra | Condição em janela inclusiva de 300 segundos | Agrupamento | Severidade | Referência ATT&CK |
| --- | --- | --- | --- | --- |
| SSH-001 | Pelo menos cinco falhas | IP + host | Alta | T1110 — Brute Force |
| SSH-002 | Sucesso após pelo menos três falhas da mesma conta | IP + host + usuário | Crítica | T1110 e T1078 — Valid Accounts |
| SSH-003 | Pelo menos cinco falhas contra três ou mais usuários distintos | IP + host | Alta | T1110 — Brute Force |

Uma falha às 10:00 participa da janela de 10:05, mas não de 10:05:01. Os eventos são ordenados por horário antes da detecção. Falhas e sucessos no mesmo instante são avaliados com falhas primeiro; a resolução do log não permite comprovar sua ordem real.

As referências ATT&CK indicam hipóteses analíticas. SSH-002 não comprova uso indevido da conta. SSH-003 não confirma *password spraying*, pois os logs não revelam as senhas testadas. NAT, bastions, automações e erros de senha permanecem fontes de falsos positivos.

O catálogo `soc_one/catalog.py` contém identificador, título, revisão, estado experimental, descrição, origem de logs, condições, severidade, tags, falsos positivos e referências. O formato é **inspirado no Sigma**, mas não constitui regras Sigma executáveis ou exportáveis para outros SIEMs.

### Deduplicação e eventos tardios

Eventos são identificados pelo hash do timestamp UTC e da linha sem espaços nas extremidades. Linhas idênticas no mesmo instante são consideradas duplicatas; representações textuais diferentes podem gerar eventos distintos.

Cada ocorrência é identificada pela combinação de regra e evento disparador. Uma sequência de seis falhas dentro da janela gera duas ocorrências SSH-001. Não há agrupamento dessas ocorrências em um único incidente. O processamento deduplica inclusive entradas repetidas na chamada direta do motor.

A importação reavalia os eventos persistidos em ordem temporal. Eventos tardios podem criar alertas e atualizar evidências de alertas existentes, preservando classificação, observações, playbook e relatório. Mudanças na correlação são registradas no histórico.

## Gestão de incidentes e playbooks

Na aba **Investigação**, a fila pode ser filtrada por status, severidade, classificação, regra, IP, host e período. A seleção de um alerta apresenta as evidências, o identificador, os metadados da regra e os formulários de acompanhamento.

Status disponíveis: **Novo**, **Em análise**, **Escalonado** e **Encerrado**. O encerramento exige justificativa. A classificação é independente do status: **Não classificado**, **Verdadeiro positivo**, **Falso positivo** ou **Inconclusivo**. Nenhuma classificação é atribuída automaticamente pelo motor.

Cada regra oferece um checklist com validação de evidências, consulta de contexto, investigação específica e encaminhamento N1/N2. As etapas concluídas são persistidas; alterações, inclusive desmarcações, ficam no histórico. Uma etapa não aplicável pode ser registrada com justificativa nas observações. O checklist não executa contenção, bloqueios ou comunicações externas.

O histórico registra horário UTC, operação e valores anteriores e posteriores para triagem, playbook, relatório e correlação. Operações manuais são atribuídas a **Analista local**, sem autenticação de identidade. A aplicação não oferece exclusão ou edição do histórico, mas o arquivo SQLite continua modificável por quem tem acesso ao sistema operacional.

Há controle de versão para evitar sobrescritas entre sessões nos formulários de triagem, playbook e relatório. Um conflito exige recarregar a investigação; o estado mais recente é preservado.

## Relatórios de investigação

O formulário permite editar, salvar e consultar:

- Descrição do ocorrido e linha do tempo da investigação.
- Evidências adicionais e indicadores, com suas fontes.
- Impacto observado e análise.
- Ações realizadas e conclusão.

Todos esses campos começam vazios. O sistema não inventa narrativa, impacto, ações, evidências adicionais ou conclusões.

Os dados objetivos são preenchidos a partir dos eventos: intervalo UTC, IPs, hosts, contas, linha do tempo, IDs e linhas de log. A proveniência registra nome do arquivo informado na importação, número da linha, SHA-256 do texto decodificado em UTF-8 e parâmetros de interpretação. Esse hash não equivale necessariamente ao hash dos bytes originais do arquivo, por exemplo quando existe BOM. O nome do arquivo não comprova autenticidade da origem.

Ao salvar, o relatório recebe uma versão e uma cópia dos dados objetivos. Evidências recebidas posteriormente não sobrescrevem essa cópia nem a narrativa; a interface sinaliza que há dados novos. Uma nova gravação atualiza a cópia e preserva os campos manuais não alterados. O histórico mantém os valores anteriores.

A exportação Markdown/JSON inclui a narrativa salva e sua cópia de evidências, além do estado atual da triagem, playbook e histórico, identificados como tal. Antes da primeira gravação, a exportação contém os dados atuais e campos manuais vazios. Texto ainda não salvo no formulário não é exportado.

## Indicadores e filtros

Os indicadores globais consideram somente detecções que atendem às regras atuais:

- Quantidade de eventos, alertas e incidentes não encerrados.
- Incidentes com alteração de triagem registrada e quantidade de escalonados.
- Taxa de encerramento: encerrados divididos pelo total de detecções atuais.
- Distribuições por severidade, status e classificação, incluindo os ainda não classificados.

O período do gráfico controla a série de eventos por minuto e os IPs com mais falhas. Os filtros das abas de eventos e investigação operam de forma independente. Registros históricos arquivados ficam disponíveis mediante filtro e não compõem as métricas operacionais.

## Arquitetura

```text
Arquivo autorizado
    → parser → eventos normalizados + proveniência
    → motor de correlação + catálogo de regras
    → SQLite: alertas, incidentes, histórico, playbooks e relatórios
    → Streamlit: investigação manual e exportação Markdown/JSON
```

| Componente | Responsabilidade |
| --- | --- |
| `soc_one/models.py` | Modelos de eventos e alertas |
| `soc_one/parser.py` | Parsing, validação e normalização UTC |
| `soc_one/catalog.py` | Metadados e parâmetros das regras |
| `soc_one/rules.py` | Correlação temporal determinística |
| `soc_one/migrations.py` | Evolução aditiva do esquema SQLite |
| `soc_one/storage.py` | Transações, histórico, proveniência e controle de versões |
| `soc_one/playbooks.py` | Procedimentos de investigação N1/N2 |
| `soc_one/reports.py` | Dados objetivos e exportação Markdown |
| `soc_one/analytics.py` | Métricas operacionais |
| `soc_one/ui.py` | Componentes de investigação e gráficos |
| `app.py` | Dashboard e fluxo de importação |
| `samples/` | Logs fictícios para demonstração |
| `tests/` | Testes do núcleo, migração e interface |

## Atualização de bancos da primeira versão

A migração ocorre automaticamente ao abrir o banco. É recomendável manter uma cópia de segurança de `data/soc_one.db` com a aplicação parada antes da atualização.

Tabelas e colunas são adicionadas em transação. Eventos, observações e justificativas existentes são preservados. O estado encontrado no banco legado recebe um registro de migração; alterações anteriores à existência do histórico não são reconstruídas.

Alertas legados são reavaliados pela nova correlação por host e conta. Os que deixarem de atender às regras são marcados como históricos, sem remoção de incidentes ou evidências. Eventos legados sem proveniência de importação são identificados explicitamente como tal. A reimportação do arquivo correspondente pode complementar a proveniência.

## Testes e validação

```bash
python -m pytest -q
python -m compileall -q app.py soc_one
python -m pip check
```

A suíte verifica parsing, limites temporais, ordenação, isolamento entre hosts e contas, múltiplos usuários, deduplicação, persistência, migração, histórico, classificação, playbooks, concorrência de edição, relatórios e proveniência. Streamlit AppTest exercita os formulários em bancos temporários.

Os resultados efetivamente executados e os limites de verificação estão em [docs/VALIDATION.md](docs/VALIDATION.md).

## Limitações

O SOC-One é um laboratório educacional, não um SIEM de produção. O histórico é reprocessado em memória a cada importação, com persistência local adequada a conjuntos pequenos. Não há coleta contínua, retenção automática, paginação, autenticação multiusuário, trilha inviolável, criptografia do banco ou resposta automática.

As correlações consideram a origem IP e o hostname presente no log, sem resolução de aliases ou comprovação de causalidade. A deduplicação pode colapsar eventos realmente distintos com linhas idênticas no mesmo instante. Ocorrências sucessivas de uma regra não são agregadas em um único caso.

Relatórios e logs podem conter informações sensíveis. O `.gitignore` exclui o banco, ambiente virtual, credenciais e logs externos; somente os dados fictícios de `samples/` devem ser versionados. A aplicação não identifica automaticamente dados sensíveis em exportações.

## Referências

- [MITRE ATT&CK — Brute Force (T1110)](https://attack.mitre.org/techniques/T1110/).
- [MITRE ATT&CK — Valid Accounts (T1078)](https://attack.mitre.org/techniques/T1078/).
- [Sigma Rules Specification](https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html).

Repositório: [ArthurrCorreia/SOC-One](https://github.com/ArthurrCorreia/SOC-One).
