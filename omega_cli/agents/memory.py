"""AgentMemory — SQLite-backed shared memory for cross-agent findings and data."""
from __future__ import annotations

import json
import sqlite3
import datetime
from pathlib import Path
from typing import Any, Optional

MEMORY_DB = Path.home() / ".omega" / "agent_memory.db"


class AgentMemory:
    """Persistent memory store shared across all agents.

    Stores findings, raw data, and cross-references so agents can
    build on each other's work without re-running tools.
    """

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or MEMORY_DB
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path))
        self._conn.row_factory = sqlite3.Row
        self._init_tables()

    def _init_tables(self):
        cur = self._conn.cursor()
        cur.executescript("""
            CREATE TABLE IF NOT EXISTS findings (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                target     TEXT NOT NULL,
                agent      TEXT NOT NULL,
                title      TEXT NOT NULL,
                severity   TEXT NOT NULL,
                description TEXT,
                evidence   TEXT,
                recommendation TEXT,
                tags       TEXT DEFAULT '[]',
                raw_data   TEXT DEFAULT '{}',
                created_at TEXT DEFAULT (datetime('now'))
            );
            CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target);
            CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);

            CREATE TABLE IF NOT EXISTS runs (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                target     TEXT NOT NULL,
                agent      TEXT NOT NULL,
                data       TEXT DEFAULT '{}',
                finding_count INTEGER DEFAULT 0,
                created_at TEXT DEFAULT (datetime('now'))
            );
            CREATE INDEX IF NOT EXISTS idx_runs_target ON runs(target);

            CREATE TABLE IF NOT EXISTS kv (
                key   TEXT PRIMARY KEY,
                value TEXT,
                updated_at TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS targets (
                target     TEXT PRIMARY KEY,
                target_type TEXT DEFAULT 'domain',
                first_seen TEXT DEFAULT (datetime('now')),
                last_seen  TEXT DEFAULT (datetime('now')),
                metadata   TEXT DEFAULT '{}'
            );
            CREATE INDEX IF NOT EXISTS idx_targets_type ON targets(target_type);
        """)
        self._conn.commit()

    def store_finding(self, target: str, agent: str, finding: Any):
        """Store a single finding from an agent."""
        cur = self._conn.cursor()
        cur.execute(
            """INSERT INTO findings (target, agent, title, severity, description,
               evidence, recommendation, tags, raw_data)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                target, agent, finding.title, finding.severity.value,
                finding.description, finding.evidence, finding.recommendation,
                json.dumps(finding.tags), json.dumps(finding.raw_data, default=str),
            ),
        )
        self._conn.commit()
        return cur.lastrowid

    def store_run(self, target: str, agent: str, data: dict, findings: list):
        """Store an agent run with its raw data."""
        cur = self._conn.cursor()
        cur.execute(
            "INSERT INTO runs (target, agent, data, finding_count) VALUES (?, ?, ?, ?)",
            (target, agent, json.dumps(data, default=str)[:50000], len(findings)),
        )
        # Update target record
        cur.execute(
            """INSERT INTO targets (target, last_seen) VALUES (?, datetime('now'))
               ON CONFLICT(target) DO UPDATE SET last_seen = datetime('now')""",
            (target,),
        )
        self._conn.commit()

    def get_findings(self, target: str = "", agent: str = "",
                     severity: str = "", limit: int = 100) -> list[dict]:
        """Query findings with optional filters."""
        query = "SELECT * FROM findings WHERE 1=1"
        params: list = []
        if target:
            query += " AND target = ?"
            params.append(target)
        if agent:
            query += " AND agent = ?"
            params.append(agent)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        rows = self._conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def get_runs(self, target: str = "", agent: str = "", limit: int = 50) -> list[dict]:
        """Query past agent runs."""
        query = "SELECT id, target, agent, finding_count, created_at FROM runs WHERE 1=1"
        params: list = []
        if target:
            query += " AND target = ?"
            params.append(target)
        if agent:
            query += " AND agent = ?"
            params.append(agent)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        rows = self._conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def get_run_data(self, run_id: int) -> dict:
        """Get full raw data from a specific run."""
        row = self._conn.execute("SELECT data FROM runs WHERE id = ?", (run_id,)).fetchone()
        if row:
            return json.loads(row["data"])
        return {}

    def get_targets(self) -> list[dict]:
        """List all known targets."""
        rows = self._conn.execute(
            "SELECT * FROM targets ORDER BY last_seen DESC"
        ).fetchall()
        return [dict(r) for r in rows]

    def search(self, query: str, limit: int = 50) -> list[dict]:
        """Full-text search across findings."""
        rows = self._conn.execute(
            """SELECT * FROM findings
               WHERE title LIKE ? OR description LIKE ? OR evidence LIKE ?
               ORDER BY created_at DESC LIMIT ?""",
            (f"%{query}%", f"%{query}%", f"%{query}%", limit),
        ).fetchall()
        return [dict(r) for r in rows]

    def set_kv(self, key: str, value: Any):
        """Store a key-value pair."""
        self._conn.execute(
            "INSERT OR REPLACE INTO kv (key, value, updated_at) VALUES (?, ?, datetime('now'))",
            (key, json.dumps(value, default=str)),
        )
        self._conn.commit()

    def get_kv(self, key: str, default: Any = None) -> Any:
        """Retrieve a key-value pair."""
        row = self._conn.execute("SELECT value FROM kv WHERE key = ?", (key,)).fetchone()
        if row:
            return json.loads(row["value"])
        return default

    def stats(self) -> dict:
        """Memory statistics."""
        cur = self._conn.cursor()
        targets = cur.execute("SELECT COUNT(*) FROM targets").fetchone()[0]
        findings = cur.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        runs = cur.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
        by_sev = {}
        for row in cur.execute("SELECT severity, COUNT(*) as c FROM findings GROUP BY severity"):
            by_sev[row[0]] = row[1]
        return {
            "targets": targets,
            "findings": findings,
            "runs": runs,
            "by_severity": by_sev,
        }

    def clear(self, target: str = ""):
        """Clear memory, optionally for a specific target."""
        if target:
            self._conn.execute("DELETE FROM findings WHERE target = ?", (target,))
            self._conn.execute("DELETE FROM runs WHERE target = ?", (target,))
            self._conn.execute("DELETE FROM targets WHERE target = ?", (target,))
        else:
            self._conn.execute("DELETE FROM findings")
            self._conn.execute("DELETE FROM runs")
            self._conn.execute("DELETE FROM targets")
            self._conn.execute("DELETE FROM kv")
        self._conn.commit()

    def close(self):
        self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
