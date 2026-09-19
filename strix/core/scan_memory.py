"""Cross-scan vulnerability knowledge base for Strix.

Inspired by NousResearch/hermes-agent's memory system (memory_tool.py +
memory_tool_store.py), reimplemented from scratch using SQLite for Strix's
specific use case: remembering security findings across multiple scan runs
so the agent can say "this domain had SQL injection in a previous scan."

Unlike Hermes's MEMORY.md (flat file, LLM-curated), this store is:
- Structured (typed fields: target, severity, cwe, title, timestamp)
- Indexed by domain/target for fast lookup
- Append-only (findings are never deleted, only marked stale)
- Queryable by the agent via the scan_memory tool

The DB lives at ~/.strix/scan_memory.db by default,
overridable by STRIX_SCAN_MEMORY_DB env var.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)

_DB_PATH: Path | None = None
_lock = threading.Lock()


def _default_db_path() -> Path:
    env = os.environ.get("STRIX_SCAN_MEMORY_DB", "").strip()
    if env:
        return Path(env).expanduser()
    return Path.home() / ".strix" / "scan_memory.db"


def _get_db() -> sqlite3.Connection:
    path = _default_db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    _ensure_schema(conn)
    return conn


def _ensure_schema(conn: sqlite3.Connection) -> None:
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS findings (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            run_name    TEXT NOT NULL,
            target      TEXT NOT NULL,
            domain      TEXT NOT NULL,
            title       TEXT NOT NULL,
            severity    TEXT NOT NULL,
            cvss        REAL,
            cwe         TEXT,
            cve         TEXT,
            endpoint    TEXT,
            description TEXT,
            timestamp   TEXT NOT NULL,
            stale       INTEGER NOT NULL DEFAULT 0
        );

        CREATE INDEX IF NOT EXISTS idx_findings_domain
            ON findings(domain, severity, stale);

        CREATE INDEX IF NOT EXISTS idx_findings_run
            ON findings(run_name);

        CREATE TABLE IF NOT EXISTS run_meta (
            run_name    TEXT PRIMARY KEY,
            target      TEXT,
            scan_start  TEXT,
            scan_end    TEXT,
            finding_count INTEGER DEFAULT 0
        );
    """)
    conn.commit()


def _extract_domain(target: str) -> str:
    """Extract bare hostname from a URL or return target as-is."""
    try:
        from urllib.parse import urlsplit
        host = urlsplit(target).hostname or target
        return host.lower()
    except Exception:
        return target.lower()


def record_findings(
    run_name: str,
    vulnerabilities: list[dict[str, Any]],
    *,
    target: str = "",
    scan_start: str | None = None,
    scan_end: str | None = None,
) -> int:
    """Persist all findings from a completed scan run into the knowledge base.

    Returns the number of rows inserted.
    """
    if not vulnerabilities:
        return 0

    rows: list[tuple] = []
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    for v in vulnerabilities:
        raw_target = str(v.get("target") or v.get("endpoint") or target or "")
        domain = _extract_domain(raw_target or target)
        rows.append((
            run_name,
            raw_target or target,
            domain,
            str(v.get("title") or ""),
            str(v.get("severity") or "info").lower(),
            v.get("cvss"),
            v.get("cwe"),
            v.get("cve"),
            v.get("endpoint"),
            str(v.get("description") or "")[:500],
            str(v.get("timestamp") or now),
        ))

    with _lock:
        conn = _get_db()
        try:
            conn.executemany(
                """INSERT INTO findings
                   (run_name, target, domain, title, severity, cvss, cwe, cve,
                    endpoint, description, timestamp)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                rows,
            )
            conn.execute(
                """INSERT OR REPLACE INTO run_meta
                   (run_name, target, scan_start, scan_end, finding_count)
                   VALUES (?,?,?,?,?)""",
                (run_name, target, scan_start, scan_end, len(rows)),
            )
            conn.commit()
        finally:
            conn.close()

    logger.info("scan_memory: recorded %d findings for run '%s'", len(rows), run_name)
    return len(rows)


def query_domain(domain_or_url: str, *, limit: int = 20) -> list[dict[str, Any]]:
    """Return past findings for a domain, most recent first.

    Useful for the AI agent to say "I've seen SQL injection on this domain before."
    """
    domain = _extract_domain(domain_or_url)
    with _lock:
        conn = _get_db()
        try:
            rows = conn.execute(
                """SELECT run_name, title, severity, cvss, cwe, cve,
                          endpoint, description, timestamp
                   FROM findings
                   WHERE domain = ? AND stale = 0
                   ORDER BY timestamp DESC
                   LIMIT ?""",
                (domain, limit),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()


def search_findings(keyword: str, *, limit: int = 20) -> list[dict[str, Any]]:
    """Full-text search across titles and descriptions in the knowledge base."""
    pattern = f"%{keyword}%"
    with _lock:
        conn = _get_db()
        try:
            rows = conn.execute(
                """SELECT run_name, domain, title, severity, cvss, cwe, cve,
                          endpoint, description, timestamp
                   FROM findings
                   WHERE (title LIKE ? OR description LIKE ? OR cwe LIKE ? OR cve LIKE ?)
                     AND stale = 0
                   ORDER BY cvss DESC NULLS LAST, timestamp DESC
                   LIMIT ?""",
                (pattern, pattern, pattern, pattern, limit),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()


def get_stats() -> dict[str, Any]:
    """Return summary statistics of the knowledge base."""
    with _lock:
        conn = _get_db()
        try:
            total = conn.execute("SELECT COUNT(*) FROM findings WHERE stale=0").fetchone()[0]
            by_sev = {
                row[0]: row[1]
                for row in conn.execute(
                    "SELECT severity, COUNT(*) FROM findings WHERE stale=0 GROUP BY severity"
                ).fetchall()
            }
            runs = conn.execute("SELECT COUNT(*) FROM run_meta").fetchone()[0]
            domains = conn.execute(
                "SELECT COUNT(DISTINCT domain) FROM findings WHERE stale=0"
            ).fetchone()[0]
            return {
                "total_findings": total,
                "runs_tracked": runs,
                "domains_tracked": domains,
                "by_severity": by_sev,
                "db_path": str(_default_db_path()),
            }
        finally:
            conn.close()
