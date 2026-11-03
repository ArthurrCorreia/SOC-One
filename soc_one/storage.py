import hashlib
import json
import sqlite3
from contextlib import contextmanager
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from .catalog import RULES
from .migrations import migrate
from .models import Event
from .parser import parse_line
from .playbooks import PLAYBOOKS
from .reports import REPORT_FIELDS, objective_data, markdown_report
from .rules import detect

STATUSES = ('Novo', 'Em análise', 'Escalonado', 'Encerrado')
CLASSIFICATIONS = ('Não classificado', 'Verdadeiro positivo', 'Falso positivo', 'Inconclusivo')


def now():
    return datetime.now(timezone.utc).isoformat()


def encode(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


class Store:
    def __init__(self, path='data/soc_one.db'):
        self.path = str(path)
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as db:
            # DDL e reconciliação compartilham uma transação, inclusive no banco legado.
            db.execute('BEGIN IMMEDIATE')
            if migrate(db):
                for row in db.execute('SELECT * FROM incidents').fetchall():
                    self._history(db, row['alert_id'], 'migração_v1', {}, dict(row), 'Sistema')
                self._reconcile(db)

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.path, timeout=15)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA foreign_keys=ON')
        try:
            with db:
                yield db
        finally:
            db.close()

    @staticmethod
    def _history(db, alert_id, action, before, after, actor='Analista local'):
        db.execute('INSERT INTO history(alert_id,timestamp,actor,action,before_json,after_json) VALUES (?,?,?,?,?,?)',
                   (alert_id, now(), actor, action, encode(before), encode(after)))

    @staticmethod
    def _incident(db, alert_id):
        row = db.execute('SELECT * FROM incidents WHERE alert_id=?', (alert_id,)).fetchone()
        if row is None:
            raise ValueError('Alerta não encontrado.')
        return dict(row)

    def _reconcile(self, db):
        rows = db.execute('SELECT * FROM events').fetchall()
        events = [Event(**(dict(r) | {'timestamp': datetime.fromisoformat(r['timestamp'])})) for r in rows]
        current = {r['id']: dict(r) for r in db.execute('SELECT * FROM alerts')}
        found = set()
        for alert in detect(events):
            record = {'id': alert.id, 'rule': alert.rule, 'severity': alert.severity,
                      'ip': alert.ip, 'timestamp': alert.timestamp.isoformat(),
                      'evidence': encode(alert.evidence), 'host': alert.host,
                      'active': 1, 'metadata': encode(RULES[alert.rule])}
            previous = current.get(alert.id)
            db.execute('''INSERT INTO alerts(id,rule,severity,ip,timestamp,evidence,host,active,metadata)
                VALUES (:id,:rule,:severity,:ip,:timestamp,:evidence,:host,:active,:metadata)
                ON CONFLICT(id) DO UPDATE SET evidence=excluded.evidence,host=excluded.host,
                active=1,metadata=excluded.metadata,severity=excluded.severity''', record)
            db.execute('INSERT OR IGNORE INTO incidents(alert_id) VALUES (?)', (alert.id,))
            if previous != record:
                self._history(db, alert.id, 'detecção' if previous is None else 'correlação_atualizada', previous or {}, record, 'Sistema')
            found.add(alert.id)
        for key, previous in current.items():
            if key not in found and previous['active']:
                db.execute('UPDATE alerts SET active=0 WHERE id=?', (key,))
                self._history(db, key, 'detecção_arquivada', previous, previous | {'active': 0}, 'Sistema')

    def import_text(self, text, year, utc_offset=0, source='Importação manual'):
        parsed, invalid = [], 0
        digest = hashlib.sha256(text.encode('utf-8')).hexdigest()
        for number, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            event = parse_line(line, year, utc_offset)
            if event:
                parsed.append((event, number))
            else:
                invalid += 1
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            before = db.execute('SELECT count(*) FROM events').fetchone()[0]
            before_alerts = db.execute('SELECT count(*) FROM alerts').fetchone()[0]
            for event, number in parsed:
                record = asdict(event)
                record['timestamp'] = event.timestamp.isoformat()
                db.execute('INSERT OR IGNORE INTO events VALUES (:id,:timestamp,:host,:ip,:username,:service,:kind,:raw)', record)
                db.execute('INSERT OR IGNORE INTO event_sources VALUES (?,?,?,?,?,?)',
                           (event.id, digest, Path(source).name, number, year, utc_offset))
            total = db.execute('SELECT count(*) FROM events').fetchone()[0]
            self._reconcile(db)
            count_alerts = db.execute('SELECT count(*) FROM alerts').fetchone()[0]
        return {'inseridos': total - before, 'ignorados': invalid,
                'repetidos': len(parsed) - (total - before), 'novos_alertas': count_alerts - before_alerts}

    def events(self):
        with self.connection() as db:
            return [dict(r) for r in db.execute('SELECT * FROM events ORDER BY timestamp,id')]

    def alerts(self):
        with self.connection() as db:
            return [dict(r) for r in db.execute('''SELECT a.*,i.status,i.notes,i.justification,
                i.updated_at,i.classification,i.version FROM alerts a JOIN incidents i ON a.id=i.alert_id
                ORDER BY timestamp DESC,a.id''')]

    def triage(self, alert_id, status, notes, justification, classification=None, expected_version=None):
        if status not in STATUSES:
            raise ValueError('Status inválido.')
        if status == 'Encerrado' and not justification.strip():
            raise ValueError('Informe a justificativa para encerrar.')
        if classification is not None and classification not in CLASSIFICATIONS:
            raise ValueError('Classificação inválida.')
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            previous = self._incident(db, alert_id)
            if expected_version is not None and previous['version'] != expected_version:
                raise ValueError('O incidente foi alterado em outra sessão. Recarregue antes de salvar.')
            updated = previous | {'status': status, 'notes': notes.strip(), 'justification': justification.strip(),
                                  'classification': classification or previous['classification']}
            if updated == previous:
                return
            updated.update(updated_at=now(), version=previous['version'] + 1)
            db.execute('''UPDATE incidents SET status=:status,notes=:notes,justification=:justification,
                classification=:classification,updated_at=:updated_at,version=:version WHERE alert_id=:alert_id''', updated)
            self._history(db, alert_id, 'triagem', previous, updated)

    def history(self, alert_id):
        with self.connection() as db:
            self._incident(db, alert_id)
            return self._history_rows(db, alert_id)

    @staticmethod
    def _history_rows(db, alert_id):
        return [{k: r[k] for k in ('id', 'alert_id', 'timestamp', 'actor', 'action')}
                | {'antes': json.loads(r['before_json']), 'depois': json.loads(r['after_json'])}
                for r in db.execute('SELECT * FROM history WHERE alert_id=? ORDER BY id', (alert_id,))]

    def playbook(self, alert_id):
        with self.connection() as db:
            self._incident(db, alert_id)
            return self._playbook(db, alert_id)

    @staticmethod
    def _playbook(db, alert_id):
        rule = db.execute('SELECT rule FROM alerts WHERE id=?', (alert_id,)).fetchone()[0]
        row = db.execute('SELECT * FROM playbook_state WHERE alert_id=?', (alert_id,)).fetchone()
        completed = json.loads(row['completed']) if row else []
        return {'version': row['version'] if row else 0, 'updated_at': row['updated_at'] if row else None,
                'etapas': [{'id': key, 'procedimento': text, 'concluida': key in completed}
                           for key, text in PLAYBOOKS.get(rule, ())]}

    def save_playbook(self, alert_id, completed, expected_version=None):
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            self._incident(db, alert_id)
            previous = self._playbook(db, alert_id)
            allowed = {s['id'] for s in previous['etapas']}
            if set(completed) - allowed:
                raise ValueError('Etapa de playbook inválida.')
            if expected_version is not None and expected_version != previous['version']:
                raise ValueError('O playbook foi alterado em outra sessão. Recarregue antes de salvar.')
            old = sorted(s['id'] for s in previous['etapas'] if s['concluida'])
            if old == sorted(set(completed)):
                return
            db.execute('''INSERT INTO playbook_state VALUES (?,?,?,?) ON CONFLICT(alert_id)
                DO UPDATE SET completed=excluded.completed,version=excluded.version,updated_at=excluded.updated_at''',
                       (alert_id, encode(sorted(set(completed))), previous['version'] + 1, now()))
            self._history(db, alert_id, 'playbook', previous, self._playbook(db, alert_id))

    @staticmethod
    def _objective(db, alert_id):
        alert = db.execute('SELECT * FROM alerts WHERE id=?', (alert_id,)).fetchone()
        ids = set(json.loads(alert['evidence']))
        # Conjunto pequeno do laboratório; evita limite de parâmetros SQL em janelas extensas.
        events = [dict(r) for r in db.execute('SELECT * FROM events ORDER BY timestamp,id') if r['id'] in ids]
        sources = [dict(r) for r in db.execute('SELECT * FROM event_sources ORDER BY event_id,digest,source,line') if r['event_id'] in ids]
        facts = objective_data(events, sources)
        facts['regra'] = json.loads(alert['metadata']) or {'id': alert['rule'], 'revision': 'legado v1'}
        facts['fontes_ausentes'] = sorted(ids - {s['event_id'] for s in sources})
        return facts

    def save_report(self, alert_id, fields, expected_version=None):
        if set(fields) - set(REPORT_FIELDS) or any(not isinstance(v, str) for v in fields.values()):
            raise ValueError('Campos de relatório inválidos.')
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            self._incident(db, alert_id)
            row = db.execute('SELECT * FROM reports WHERE alert_id=?', (alert_id,)).fetchone()
            previous = dict(row) if row else {}
            version = row['version'] if row else 0
            if expected_version is not None and expected_version != version:
                raise ValueError('O relatório foi alterado em outra sessão. Recarregue antes de salvar.')
            # Atualizações parciais preservam texto não enviado pelo formulário.
            merged = json.loads(row['fields']) if row else {key: '' for key in REPORT_FIELDS}
            merged.update(fields)
            snapshot = self._objective(db, alert_id)
            if row and encode(merged) == row['fields'] and encode(snapshot) == row['snapshot']:
                return
            updated = {'alert_id': alert_id, 'fields': encode(merged), 'snapshot': encode(snapshot),
                       'version': version + 1, 'updated_at': now()}
            db.execute('''INSERT INTO reports VALUES (:alert_id,:fields,:snapshot,:version,:updated_at)
                ON CONFLICT(alert_id) DO UPDATE SET fields=excluded.fields,snapshot=excluded.snapshot,
                version=excluded.version,updated_at=excluded.updated_at''', updated)
            self._history(db, alert_id, 'relatório', previous, updated)

    def report(self, alert_id):
        with self.connection() as db:
            # Um snapshot de leitura consistente para estado, evidências e histórico.
            db.execute('BEGIN')
            incident = self._incident(db, alert_id)
            alert = dict(db.execute('SELECT * FROM alerts WHERE id=?', (alert_id,)).fetchone())
            alert.pop('evidence')
            alert.pop('metadata')
            alert.update({k: v for k, v in incident.items() if k != 'alert_id'})
            live = self._objective(db, alert_id)
            row = db.execute('SELECT * FROM reports WHERE alert_id=?', (alert_id,)).fetchone()
            snapshot = json.loads(row['snapshot']) if row else live
            return {
                'alerta': alert, 'evidencias': snapshot['eventos'], 'dados_objetivos': snapshot,
                'regra': snapshot['regra'],
                'investigacao': json.loads(row['fields']) if row else {key: '' for key in REPORT_FIELDS},
                'documento': {'version': row['version'] if row else 0,
                              'salvo_em': row['updated_at'] if row else None,
                              'dados_objetivos_atualizados': snapshot == live,
                              'exportado_em': now(),
                              'origem_narrativa': 'Preenchimento manual do analista',
                              'estado_operacional': 'Alerta, triagem, playbook e histórico refletem o estado atual; os dados objetivos são da última gravação do relatório, ou da consulta se não salvo.'},
                'playbook': self._playbook(db, alert_id), 'historico': self._history_rows(db, alert_id),
                'aviso': 'Detecção indica suspeita; a classificação é manual. Dados ausentes não foram inferidos.',
            }
