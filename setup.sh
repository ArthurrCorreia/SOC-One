#!/usr/bin/env bash
# Instalação local: bash setup.sh [--dev]
set -euo pipefail

if (( EUID == 0 )); then
    echo 'Erro: execute como usuário comum, sem sudo ou root.' >&2
    exit 1
fi
soc_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd -- "$soc_root"
requirements='requirements.txt'
case "${1:-}" in
    '') ;;
    --dev) requirements='requirements-dev.txt' ;;
    *) echo 'Uso: bash setup.sh [--dev]' >&2; exit 2 ;;
esac
if (( $# > 1 )); then
    echo 'Uso: bash setup.sh [--dev]' >&2
    exit 2
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo 'Erro: Python 3.11 ou superior não encontrado. Instale Python e python3-venv pelo gerenciador do Linux.' >&2
    exit 1
fi
if ! python3 -c 'import sys; sys.exit(sys.version_info < (3, 11))'; then
    echo 'Erro: é necessário Python 3.11 ou superior.' >&2
    exit 1
fi
if [[ ! -w "$soc_root" ]]; then
    echo 'Erro: a pasta do projeto não permite escrita para este usuário.' >&2
    exit 1
fi
if [[ -e .venv && ! -f .venv/pyvenv.cfg ]]; then
    echo 'Erro: .venv já existe e não é um ambiente virtual reconhecido. Mova a pasta manualmente antes de continuar.' >&2
    exit 1
fi
if [[ ! -d .venv ]]; then
    if ! python3 -m venv .venv; then
        echo 'Erro ao criar o ambiente virtual. Verifique o pacote python3-venv, permissões e espaço em disco.' >&2
        exit 1
    fi
fi
if ! .venv/bin/python -c 'import sys; sys.exit(sys.prefix == sys.base_prefix or sys.version_info < (3, 11))'; then
    echo 'Erro: ambiente .venv inválido ou incompatível. Recrie-o manualmente com Python 3.11+.' >&2
    exit 1
fi
if ! .venv/bin/python -m pip --version >/dev/null 2>&1; then
    echo 'Erro: pip ausente no ambiente. Recrie .venv após instalar o suporte a venv/ensurepip.' >&2
    exit 1
fi
if ! .venv/bin/python -m pip install --disable-pip-version-check -r "$requirements"; then
    echo 'Falha ao instalar dependências. Verifique conexão, proxy, certificados, versão do Python e espaço em disco. Não use sudo.' >&2
    exit 1
fi
.venv/bin/python -m pip check
printf '\nInstalação concluída. Para iniciar: bash run.sh\n'
