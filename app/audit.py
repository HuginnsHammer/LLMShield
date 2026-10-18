import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

class AuditStore:
    def __init__(self, path: str) -> None:
        self.path = path
        if path != ':memory:':
            Path(path).expanduser().parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.path) as db:
            db.execute('CREATE TABLE IF NOT EXISTS audit_events (id INTEGER PRIMARY KEY, created_at TEXT, request_id TEXT, decision TEXT, provider TEXT, findings_json TEXT)')

    def record(self, request_id: str, decision: str, provider: str, findings: list, request_text: str = '', response_text: str = '') -> int:
        encoded = json.dumps([f.model_dump() for f in findings])
        with sqlite3.connect(self.path) as db:
            cur = db.execute('INSERT INTO audit_events (created_at, request_id, decision, provider, findings_json) VALUES (?, ?, ?, ?, ?)', (datetime.now(timezone.utc).isoformat(), request_id, decision, provider, encoded))
            return int(cur.lastrowid)

    def list_events(self, limit: int = 50) -> list[dict]:
        with sqlite3.connect(self.path) as db:
            db.row_factory = sqlite3.Row
            rows = db.execute('SELECT id, created_at, request_id, decision, provider, findings_json FROM audit_events ORDER BY id DESC LIMIT ?', (max(1, min(limit, 200)),)).fetchall()
        return [{'id': r['id'], 'created_at': r['created_at'], 'request_id': r['request_id'], 'decision': r['decision'], 'provider': r['provider'], 'findings': json.loads(r['findings_json'])} for r in rows]
