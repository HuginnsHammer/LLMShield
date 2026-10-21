import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class AuditStore:
    """Store audit metadata only; never accept or persist prompt/response content."""

    def __init__(self, path: str) -> None:
        self.path = path if path == ":memory:" else str(Path(path).expanduser())
        self._lock = threading.Lock()
        self._memory_db: sqlite3.Connection | None = None
        if self.path == ":memory:":
            self._memory_db = sqlite3.connect(":memory:", check_same_thread=False)
        else:
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        db = self._connection()
        try:
            db.execute("""CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY, created_at TEXT NOT NULL, request_id TEXT NOT NULL,
                decision TEXT NOT NULL, provider TEXT NOT NULL, findings_json TEXT NOT NULL
            )""")
            db.commit()
        finally:
            if db is not self._memory_db:
                db.close()

    def _connection(self) -> sqlite3.Connection:
        if self._memory_db is not None:
            return self._memory_db
        return sqlite3.connect(self.path, timeout=5)

    def record(self, request_id: str, decision: str, provider: str, findings: list) -> int:
        encoded = json.dumps([f.model_dump() if hasattr(f, "model_dump") else f for f in findings])
        with self._lock:
            db = self._connection()
            try:
                cur = db.execute(
                    "INSERT INTO audit_events (created_at, request_id, decision, provider, findings_json) VALUES (?, ?, ?, ?, ?)",
                    (datetime.now(timezone.utc).isoformat(), request_id, decision, provider, encoded),
                )
                db.commit()
                if cur.lastrowid is None:
                    raise RuntimeError("SQLite did not return an audit event ID")
                return cur.lastrowid
            finally:
                if db is not self._memory_db:
                    db.close()

    def list_events(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            db = self._connection()
            try:
                db.row_factory = sqlite3.Row
                rows = db.execute(
                    "SELECT id, created_at, request_id, decision, provider, findings_json FROM audit_events ORDER BY id DESC LIMIT ?",
                    (max(1, min(limit, 200)),),
                ).fetchall()
                return [
                    {"id": r["id"], "created_at": r["created_at"], "request_id": r["request_id"],
                     "decision": r["decision"], "provider": r["provider"], "findings": json.loads(r["findings_json"])}
                    for r in rows
                ]
            finally:
                if db is not self._memory_db:
                    db.close()

    def close(self) -> None:
        if self._memory_db is not None:
            self._memory_db.close()
            self._memory_db = None
