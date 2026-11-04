"""Contratos dos scripts; instalação real é validada separadamente em venv limpo."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def checkout(tmp_path):
    target = tmp_path / 'projeto com espaços'
    target.mkdir()
    for name in ('setup.sh', 'run.sh', 'requirements.txt', 'requirements-dev.txt'):
        shutil.copyfile(ROOT / name, target / name)
        (target / name).chmod(0o644)  # Invocação por bash não depende de +x.
    return target


def test_scripts_have_valid_bash_syntax():
    subprocess.run(['bash', '-n', str(ROOT / 'setup.sh'), str(ROOT / 'run.sh')], check=True)


def test_run_without_venv_has_actionable_error(tmp_path):
    target = checkout(tmp_path)
    result = subprocess.run(['bash', str(target / 'run.sh')], cwd=tmp_path, capture_output=True, text=True)
    assert result.returncode == 1
    assert 'bash setup.sh' in result.stderr if os.geteuid() != 0 else 'sem sudo' in result.stderr


def test_setup_rejects_invalid_argument(tmp_path):
    target = checkout(tmp_path)
    result = subprocess.run(['bash', str(target / 'setup.sh'), '--unknown'], capture_output=True, text=True)
    if os.geteuid() == 0:
        assert 'sem sudo' in result.stderr
    else:
        assert result.returncode == 2
        assert 'Uso:' in result.stderr
    assert not (target / '.venv').exists()


def test_run_resolves_checkout_and_loopback(tmp_path):
    if os.geteuid() == 0:
        return  # Os scripts recusam root antes de executar qualquer dependência.
    target = checkout(tmp_path)
    venv = target / '.venv'
    (venv / 'bin').mkdir(parents=True)
    (venv / 'pyvenv.cfg').write_text('test fixture')
    fake_python = venv / 'bin/python'
    fake_python.write_text(f'#!{sys.executable}\nimport json, os, sys\nfrom pathlib import Path\n'
                          'if sys.argv[1] != "-c":\n'
                          '    Path("invocation.json").write_text(json.dumps({"cwd": os.getcwd(), "args": sys.argv[1:]}))\n')
    fake_python.chmod(0o755)
    result = subprocess.run(['bash', str(target / 'run.sh')], cwd=tmp_path, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    invocation = json.loads((target / 'invocation.json').read_text())
    assert invocation['cwd'] == str(target)
    assert invocation['args'][:4] == ['-m', 'streamlit', 'run', 'app.py']
    assert '--server.address=127.0.0.1' in invocation['args']
