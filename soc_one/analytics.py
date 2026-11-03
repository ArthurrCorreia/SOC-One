"""Indicadores operacionais calculados exclusivamente a partir dos registros."""
from collections import Counter


def metrics(alerts):
    current = [a for a in alerts if a['active']]
    closed = sum(a['status'] == 'Encerrado' for a in current)
    return {
        'total': len(current), 'abertos': len(current) - closed,
        'triados': sum(a['updated_at'] is not None for a in current),
        'encerrados': closed, 'escalonados': sum(a['status'] == 'Escalonado' for a in current),
        'taxa_encerramento': closed / len(current) * 100 if current else 0,
        'historicos': len(alerts) - len(current),
        'status': dict(Counter(a['status'] for a in current)),
        'classificacao': dict(Counter(a['classification'] for a in current)),
        'severidade': dict(Counter(a['severity'] for a in current)),
    }
