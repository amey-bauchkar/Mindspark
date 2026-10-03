"""
SQLite-backed cache for API responses.
TTL-aware: entries expire after configured seconds.
Thread-safe via connection-per-call pattern.
"""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any

from ..config import get_settings

# TTL constants (seconds)
TTL_VULNS = 6 * 3600      # 6 hours
TTL_KEV = 24 * 3600       # 24 hours
TTL_EPSS = 24 * 3600      # 24 hours
TTL_REGISTRY = 6 * 3600   # 6 hours
TTL_DEPS_DEV = 12 * 3600  # 12 hours
TTL_REPORT = 24 * 3600    # 24 hours (reports)


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
        conn.commit()


def cache_get(key: str) -> Any | None:
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


def save_report(report_id: str, data: dict) -> None:
    with _conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO reports (id, data, created_at) VALUES (?, ?, ?)",
            (report_id, json.dumps(data, default=str), time.time()),
        )
        conn.commit()


def load_report(report_id: str) -> dict | None:
    with _conn() as conn:
        row = conn.execute("SELECT data, created_at FROM reports WHERE id = ?", (report_id,)).fetchone()
        if row is None:
            return None
        if time.time() - row["created_at"] > TTL_REPORT:
            conn.execute("DELETE FROM reports WHERE id = ?", (report_id,))
            conn.commit()
            return None
        return json.loads(row["data"])


def purge_expired() -> int:
    now = time.time()
    with _conn() as conn:
        deleted = conn.execute(
            "DELETE FROM api_cache WHERE (stored_at + ttl) < ?", (now,)
        ).rowcount
        old_reports = conn.execute(
            "DELETE FROM reports WHERE (created_at + ?) < ?", (TTL_REPORT, now)
        ).rowcount
        conn.commit()
        return deleted + old_reports
