#!/usr/bin/env bash
# Pode ser chamado de qualquer diretório, sem ativação manual do venv.
set -euo pipefail
if (( EUID == 0 )); then
    echo 'Erro: execute como usuário comum, sem sudo ou root.' >&2
    exit 1
fi
soc_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd -- "$soc_root"
if [[ ! -f .venv/pyvenv.cfg || ! -x .venv/bin/python ]]; then
    echo 'Ambiente virtual não encontrado. Execute: bash setup.sh' >&2
    exit 1
fi
if ! .venv/bin/python -c 'import sys; import streamlit, pandas; sys.exit(sys.prefix == sys.base_prefix or sys.version_info < (3, 11))' >/dev/null 2>&1; then
    echo 'Ambiente ou dependências incompatíveis. Execute: bash setup.sh' >&2
    exit 1
fi
# Flags de rede fixas mantêm a execução restrita à máquina local.
exec .venv/bin/python -m streamlit run app.py --server.address=127.0.0.1 --server.headless=true --browser.gatherUsageStats=false
