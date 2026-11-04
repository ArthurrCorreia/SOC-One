"""Gera exemplo público usando somente cenário fictício e banco temporário.

Execução a partir da raiz: python -m examples.generate_report
"""
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from soc_one.demo import DemoWorkspace
from soc_one.reports import markdown_report


def generate(output):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(prefix='soc-one-example-') as temporary:
        store, _ = DemoWorkspace(temporary).open('false_positive')
        key = store.alerts()[0]['id']
        store.triage(key, 'Encerrado',
                     'EXEMPLO FICTÍCIO: análise baseada nos logs simulados e no enunciado do cenário.',
                     'Exercício: o enunciado informa erros de digitação reconhecidos pela usuária. Não houve validação com pessoas reais.',
                     'Falso positivo')
        store.save_playbook(key, ['validate', 'context', 'account', 'assess'])
        store.save_report(key, {
            'descricao': 'EXEMPLO FICTÍCIO. Três falhas e um sucesso SSH para maria, no host lab-ssh, a partir de 192.0.2.40.',
            'linha_do_tempo': '12:00–12:01 UTC: três falhas nos logs simulados. 12:02 UTC: autenticação bem-sucedida. A revisão abaixo é uma demonstração manual, sem atividade externa.',
            'evidencias_adicionais': 'Fonte contextual: enunciado do cenário Falso positivo (exercício), em soc_one/demo.py. O enunciado informa erros de digitação após troca de senha; esse fato não é dedutível dos logs.',
            'indicadores': '192.0.2.40, maria e lab-ssh são identificadores fictícios, não indicadores de ameaça confirmados.',
            'impacto': 'Não demonstrado pelas evidências disponíveis. Ausência de dados de sessão impede avaliar ações posteriores.',
            'analise': 'A condição SSH-002 foi atendida. No contexto fictício fornecido pelo exercício, a atividade é legítima; por isso a classificação manual é Falso positivo.',
            'acoes': 'Somente nesta demonstração: revisão das quatro linhas simuladas, leitura do enunciado, preenchimento da triagem e registro de etapas no playbook. Nenhum contato, bloqueio ou contenção real foi realizado.',
            'conclusao': 'Exercício encerrado como falso positivo com base no contexto explicitamente simulado. Este documento não comprova uma investigação ou incidente real.',
        })
        report = store.report(key)
        (output / 'incidente_ficticio.json').write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
        (output / 'incidente_ficticio.md').write_text(markdown_report(report), encoding='utf-8')
    return report


if __name__ == '__main__':
    generate(Path(__file__).resolve().parent)
    print('Exemplos fictícios gerados em examples/. Nenhum banco local foi utilizado.')
