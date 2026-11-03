# Validação — evolução do SOC-One

Verificação realizada em 3 de novembro de 2026.

## Ambiente e resultados

- Python 3.14.4, Streamlit 1.66.1, pandas 3.1.0 e pytest 9.2.0.
- `python -m pytest -q`: **36 testes aprovados** na suíte completa.
- `python -m compileall -q app.py soc_one`: concluído sem erros.
- `python -m pip check`: nenhuma dependência incompatível.
- Demonstração original: 16 eventos válidos, uma linha inválida e três alertas.
- Cenário multiusuário: cinco eventos, uma ocorrência SSH-001 e uma SSH-003.

## Cobertura executada

- Parser: normalização UTC, IPv6, sucesso por chave pública, eventos normais e rejeição de linhas inválidas.
- Regras: janela inclusiva de 300 segundos, exclusão em 301 segundos, isolamento entre IPs, hosts e contas, empates temporais e múltiplos usuários.
- Deduplicação: reimportação de arquivos, eventos repetidos no motor e estabilidade das ocorrências em importações fora de ordem.
- Persistência: atualização de evidências sem perda da triagem, justificativa obrigatória de encerramento e rejeição de valores inválidos.
- Histórico: alterações de status e classificação com valores anteriores e posteriores, ausência de entradas redundantes em gravações sem mudança.
- Playbooks: conclusão, desmarcação, persistência, histórico e rejeição de etapas inexistentes.
- Relatórios: narrativa inicialmente vazia, edição parcial, versões, cópia das evidências, sinalização de dados novos e exportação Markdown/JSON.
- Proveniência: nome informado do arquivo, linha, hash do texto UTF-8, parâmetros de interpretação e deduplicação das origens.
- Migração: banco com esquema da versão anterior, preservação de notas e justificativas, arquivamento de detecção que não atende à nova correlação, reabertura idempotente e integridade de chaves estrangeiras.
- Concorrência: rejeição de versões desatualizadas em triagem, playbook e relatório.
- Indicadores: valores calculados a partir de estados persistidos, tratamento de banco vazio e exclusão de detecções históricas.
- Streamlit AppTest: demonstrações, encerramento com validação, classificação, escalonamento, checklist, relatório, filtros, reabertura em nova sessão e conflito de edição com recarga.

## Revisão

O estado Git foi inspecionado antes das alterações. O repositório ainda não possuía commits; os arquivos do MVP foram preservados como base da evolução. A comparação com uma cópia anterior permitiu revisar as mudanças antes do primeiro commit. O commit inclui somente código, configuração, documentação, testes e logs fictícios.

Os gráficos usam especificações Vega-Lite e agrupamento esparso por minuto. Os avisos de depreciação `DataFrame.reset_index(inplace=True)` emitidos anteriormente pelo caminho de gráficos do Streamlit deixaram de aparecer na suíte. O agrupamento não materializa minutos vazios entre datas distantes.

## Limites da verificação

A interface foi validada com Streamlit AppTest, sem inspeção visual em navegador. Não foram realizados testes de carga, auditoria de segurança de produção ou validação em outras versões de Python. A migração foi exercitada em banco legado temporário; nenhum banco pessoal foi utilizado como evidência de teste. O histórico é persistente, mas não é inviolável nem autentica a identidade do analista.
