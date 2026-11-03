"""Migração aditiva do esquema v1; registros existentes não são descartados."""
SCHEMA_VERSION = 2


def migrate(db):
    version = db.execute('PRAGMA user_version').fetchone()[0]
    if version > SCHEMA_VERSION:
        raise ValueError('Banco criado por uma versão mais recente do SOC-One.')
    if version == SCHEMA_VERSION:
        return False
    statements = [
        '''CREATE TABLE IF NOT EXISTS events (
            id TEXT PRIMARY KEY, timestamp TEXT, host TEXT, ip TEXT,
            username TEXT, service TEXT, kind TEXT, raw TEXT)''',
        '''CREATE TABLE IF NOT EXISTS alerts (
            id TEXT PRIMARY KEY, rule TEXT, severity TEXT, ip TEXT,
            timestamp TEXT, evidence TEXT)''',
        '''CREATE TABLE IF NOT EXISTS incidents (
            alert_id TEXT PRIMARY KEY REFERENCES alerts(id),
            status TEXT NOT NULL DEFAULT 'Novo', notes TEXT NOT NULL DEFAULT '',
            justification TEXT NOT NULL DEFAULT '', updated_at TEXT)''',
    ]
    for statement in statements:
        db.execute(statement)
    for table, additions in {
        'alerts': {'host': "TEXT NOT NULL DEFAULT ''", 'active': 'INTEGER NOT NULL DEFAULT 1',
                   'metadata': "TEXT NOT NULL DEFAULT '{}'"},
        'incidents': {'classification': "TEXT NOT NULL DEFAULT 'Não classificado'", 'version': 'INTEGER NOT NULL DEFAULT 0'},
    }.items():
        columns = {r['name'] for r in db.execute(f'PRAGMA table_info({table})')}
        for column, definition in additions.items():
            if column not in columns:
                db.execute(f'ALTER TABLE {table} ADD COLUMN {column} {definition}')
    for statement in [
        '''CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY, alert_id TEXT NOT NULL REFERENCES alerts(id),
            timestamp TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL,
            before_json TEXT NOT NULL, after_json TEXT NOT NULL)''',
        '''CREATE TABLE IF NOT EXISTS playbook_state (
            alert_id TEXT PRIMARY KEY REFERENCES alerts(id), completed TEXT NOT NULL,
            version INTEGER NOT NULL, updated_at TEXT NOT NULL)''',
        '''CREATE TABLE IF NOT EXISTS reports (
            alert_id TEXT PRIMARY KEY REFERENCES alerts(id), fields TEXT NOT NULL,
            snapshot TEXT NOT NULL, version INTEGER NOT NULL, updated_at TEXT NOT NULL)''',
        '''CREATE TABLE IF NOT EXISTS event_sources (
            event_id TEXT NOT NULL REFERENCES events(id), digest TEXT NOT NULL,
            source TEXT NOT NULL, line INTEGER NOT NULL, assumed_year INTEGER NOT NULL,
            utc_offset INTEGER NOT NULL, PRIMARY KEY(event_id,digest,source,line))''',
        'CREATE INDEX IF NOT EXISTS history_alert ON history(alert_id,id)',
    ]:
        db.execute(statement)
    db.execute(f'PRAGMA user_version={SCHEMA_VERSION}')
    return True
