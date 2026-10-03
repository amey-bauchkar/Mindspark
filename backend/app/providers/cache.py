"""
SQLite-backed cache for API responses.
TTL-aware: entries expire after configured seconds.
Thread-safe via connection-per-call pattern.
"""
from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from typing import Any, Iterator

from ..config import get_settings

# TTL constants (seconds)
TTL_VULNS = 6 * 3600      # 6 hours
TTL_KEV = 24 * 3600       # 24 hours
TTL_EPSS = 24 * 3600      # 24 hours
TTL_REGISTRY = 6 * 3600   # 6 hours
TTL_DEPS_DEV = 12 * 3600  # 12 hours
TTL_REPORT = 24 * 3600    # 24 hours (reports)

# Cache keys whose reads are skipped inside `bypass_cache_reads(...)`.
# Writes still happen, so fresh data also refreshes the cache.
_bypass_prefixes: ContextVar[tuple[str, ...]] = ContextVar("warrant_cache_bypass", default=())


def _conn() -> sqlite3.Connection:
    db_path = get_settings().db_path
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with _conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS api_cache (
                cache_key TEXT PRIMARY KEY,
                data      TEXT NOT NULL,
                stored_at REAL NOT NULL,
                ttl       REAL NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                id         TEXT PRIMARY KEY,
                data       TEXT NOT NULL,
                created_at REAL NOT NULL
            )
        """)
        # Reports referenced by Warrant Watch are retained beyond the 24 h TTL.
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(reports)")}
        if "retain" not in columns:
            conn.execute("ALTER TABLE reports ADD COLUMN retain INTEGER NOT NULL DEFAULT 0")
        # Normalised dependency state of each npm analysis (same TTL as reports),
        # so monitoring can be enabled later without re-uploading the lockfile.
        conn.execute("""
            CREATE TABLE IF NOT EXISTS analysis_snapshots (
                report_id  TEXT PRIMARY KEY,
                data       TEXT NOT NULL,
                created_at REAL NOT NULL
            )
        """)
        conn.commit()


@contextmanager
def bypass_cache_reads(prefixes: tuple[str, ...]) -> Iterator[None]:
    """Treat cache entries whose key starts with one of `prefixes` as misses."""
    token = _bypass_prefixes.set(tuple(prefixes))
    try:
        yield
    finally:
        _bypass_prefixes.reset(token)


def cache_get(key: str) -> Any | None:
    if any(key.startswith(p) for p in _bypass_prefixes.get()):
        return None
    with _conn() as conn:
        row = conn.execute(
            "SELECT data, stored_at, ttl FROM api_cache WHERE cache_key = ?", (key,)
        ).fetchone()
        if row is None:
            return None
        if time.time() - row["stored_at"] > row["ttl"]:
            conn.execute("DELETE FROM api_cache WHERE cache_key = ?", (key,))
            conn.commit()
            return None
        return json.loads(row["data"])


def cache_set(key: str, value: Any, ttl: float) -> None:
    with _conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO api_cache (cache_key, data, stored_at, ttl) VALUES (?, ?, ?, ?)",
            (key, json.dumps(value, default=str), time.time(), ttl),
        )
        conn.commit()


def save_report(report_id: str, data: dict, retain: bool = False) -> None:
    """Store a report. An existing retention flag is never cleared by a re-save."""
    with _conn() as conn:
        conn.execute(
            """
            INSERT INTO reports (id, data, created_at, retain) VALUES (?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                data = excluded.data,
                created_at = excluded.created_at,
                retain = MAX(reports.retain, excluded.retain)
            """,
            (report_id, json.dumps(data, default=str), time.time(), 1 if retain else 0),
        )
        conn.commit()


def retain_report(report_id: str) -> bool:
    """Exempt a stored report from TTL expiry. Returns False if it does not exist."""
    with _conn() as conn:
        updated = conn.execute("UPDATE reports SET retain = 1 WHERE id = ?", (report_id,)).rowcount
        conn.commit()
        return updated > 0


def load_report(report_id: str) -> dict | None:
    with _conn() as conn:
        row = conn.execute(
            "SELECT data, created_at, retain FROM reports WHERE id = ?", (report_id,)
        ).fetchone()
        if row is None:
            return None
        if not row["retain"] and time.time() - row["created_at"] > TTL_REPORT:
            conn.execute("DELETE FROM reports WHERE id = ?", (report_id,))
            conn.commit()
            return None
        return json.loads(row["data"])


def save_snapshot(report_id: str, data: dict) -> None:
    with _conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO analysis_snapshots (report_id, data, created_at) VALUES (?, ?, ?)",
            (report_id, json.dumps(data, default=str), time.time()),
        )
        conn.commit()


def load_snapshot(report_id: str) -> dict | None:
    with _conn() as conn:
        row = conn.execute(
            "SELECT data, created_at FROM analysis_snapshots WHERE report_id = ?", (report_id,)
        ).fetchone()
        if row is None or time.time() - row["created_at"] > TTL_REPORT:
            return None
        return json.loads(row["data"])


def purge_expired() -> int:
    now = time.time()
    with _conn() as conn:
        deleted = conn.execute(
            "DELETE FROM api_cache WHERE (stored_at + ttl) < ?", (now,)
        ).rowcount
        old_reports = conn.execute(
            "DELETE FROM reports WHERE retain = 0 AND (created_at + ?) < ?", (TTL_REPORT, now)
        ).rowcount
        conn.execute(
            "DELETE FROM analysis_snapshots WHERE (created_at + ?) < ?", (TTL_REPORT, now)
        )
        conn.commit()
        return deleted + old_reports
