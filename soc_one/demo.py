"""Cenários fictícios em bancos exclusivos; reset transacional e confirmado."""
from pathlib import Path
from uuid import uuid4
from .storage import Store

SAMPLES = Path(__file__).resolve().parents[1] / 'samples'
SCENARIOS = {
    'overview': {'title': 'Visão completa', 'file': 'demo.log',
                 'guide': 'Explore atividade normal, falhas repetidas e sucessos suspeitos. Compare evidências antes de classificar.',
                 'expected': '16 eventos · 3 alertas · 1 linha inválida ignorada'},
    'normal': {'title': 'Atividade normal', 'file': 'normal.log',
               'guide': 'Um login com chave e atividades normais não devem gerar alerta. Consulte os eventos.',
               'expected': '3 eventos · nenhum alerta'},
    'brute_force': {'title': 'Brute force SSH', 'file': 'brute_force.log',
                    'guide': 'Cinco falhas em cinco minutos. Confira origem, destino e intervalo; registre o que ainda precisa ser verificado.',
                    'expected': '5 eventos · 1 alerta SSH-001'},
    'suspicious_login': {'title': 'Autenticação suspeita', 'file': 'suspicious_login.log',
                         'guide': 'Três falhas seguidas de sucesso para deploy. O log não confirma comprometimento; o playbook orienta a validação.',
                         'expected': '4 eventos · 1 alerta SSH-002'},
    'false_positive': {'title': 'Falso positivo (exercício)', 'file': 'false_positive.log',
                       'guide': 'Contexto fictício do exercício: a usuária confirma erros de digitação após trocar a senha. Esse contexto não vem do log. Registre a fonte como enunciado do cenário antes de classificar.',
                       'expected': '4 eventos · 1 alerta SSH-002; classificação permanece manual'},
    'multiuser': {'title': 'Tentativas contra múltiplos usuários', 'file': 'multiuser.log',
                  'guide': 'Cinco falhas contra três contas. SSH-001 e SSH-003 representam hipóteses distintas sobre a mesma sequência.',
                  'expected': '5 eventos · 2 alertas'},
}


class DemoWorkspace:
    def __init__(self, root='data/demos'):
        self.root = Path(root)

    def open(self, scenario):
        if scenario not in SCENARIOS:
            raise ValueError('Cenário desconhecido.')
        definition = SCENARIOS[scenario]
        path = self.root / f'{scenario}.db'
        if path.is_symlink() or self.root.is_symlink():
            raise ValueError('A demonstração não aceita banco ou diretório simbólico.')
        existed = path.exists()
        store = Store(path, context={'tipo': 'simulado', 'cenario': scenario,
                                    'descricao': definition['title'] + ' — dados inteiramente fictícios.'})
        with store.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            marker = db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='demo_identity'").fetchone()
            if not marker:
                if existed:
                    raise ValueError('Banco sem identificação de demonstração. Nenhum dado será removido.')
                db.execute('CREATE TABLE demo_identity (id INTEGER PRIMARY KEY CHECK(id=1), scenario TEXT NOT NULL, generation TEXT NOT NULL)')
                db.execute('INSERT INTO demo_identity VALUES (1,?,?)', (scenario, uuid4().hex))
                store._import_text(db, self._text(scenario), 2026, source=definition['file'])
            identity = db.execute('SELECT * FROM demo_identity WHERE id=1').fetchone()
            if identity is None or identity['scenario'] != scenario:
                raise ValueError('Identificação de demonstração incompatível.')
            generation = identity['generation']
        return store, generation

    @staticmethod
    def _text(scenario):
        return (SAMPLES / SCENARIOS[scenario]['file']).read_text(encoding='utf-8')

    def reset(self, scenario, *, confirmed=False, expected_generation):
        if confirmed is not True:
            raise ValueError('Confirme explicitamente a exclusão da investigação deste cenário.')
        store, _ = self.open(scenario)
        text = self._text(scenario)
        with store.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            generation = db.execute('SELECT generation FROM demo_identity WHERE id=1').fetchone()[0]
            if generation != expected_generation:
                raise ValueError('O cenário já foi reiniciado em outra sessão. Recarregue antes de confirmar.')
            # Somente o banco identificado do cenário; nenhum caminho é recebido da interface.
            for table in ('history', 'reports', 'playbook_state', 'incidents', 'event_sources', 'alerts', 'events'):
                db.execute(f'DELETE FROM {table}')
            store._import_text(db, text, 2026, source=SCENARIOS[scenario]['file'])
            db.execute('UPDATE demo_identity SET generation=? WHERE id=1', (uuid4().hex,))
