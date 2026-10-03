"""
Warrant Watch persistence — SQLite tables alongside the existing report cache.

- watches        monitored projects: exact dependency snapshot, baseline security state,
                 schedule and status. Never expires.
- watch_reports  reports that belong to a watch (baseline + every re-analysis).
- watch_checks   one row per monitoring check, including provider failures.
- watch_events   security-change events. UNIQUE(watch_id, dedupe_key) makes event
                 creation idempotent across retries and restarts.

A check's events and the new baseline are committed in one transaction, guarded by a
compare-and-swap on the watch revision, so a crash or a concurrent check can never
produce the same alert twice.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from typing import Any

from ..providers.cache import _conn

WATCH_STATUSES = ("active", "paused", "disabled")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def ts(dt: datetime) -> str:
    """Fixed-width UTC ISO timestamp so stored values sort lexicographically."""
    return dt.astimezone(timezone.utc).isoformat(timespec="microseconds")


def parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def init_watch_db() -> None:
    with _conn() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS watches (
                id                 TEXT PRIMARY KEY,
                name               TEXT NOT NULL,
                status             TEXT NOT NULL,
                mode               TEXT NOT NULL,
                filename           TEXT NOT NULL,
                baseline_report_id TEXT NOT NULL UNIQUE,
                latest_report_id   TEXT NOT NULL,
                snapshot           TEXT NOT NULL,
                package_count      INTEGER NOT NULL,
                state              TEXT NOT NULL,
                revision           INTEGER NOT NULL DEFAULT 0,
                analyzed_at        TEXT NOT NULL,
                baseline_as_of     TEXT NOT NULL,
                evidence_as_of     TEXT NOT NULL,
                enabled_at         TEXT NOT NULL,
                last_checked_at    TEXT,
                last_check_id      TEXT,
                last_check_status  TEXT,
                last_change_at     TEXT,
                next_check_at      TEXT,
                replay             TEXT,
                updated_at         TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_watches_due ON watches(status, next_check_at);

            CREATE TABLE IF NOT EXISTS watch_reports (
                report_id  TEXT PRIMARY KEY,
                watch_id   TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS watch_checks (
                id              TEXT PRIMARY KEY,
                watch_id        TEXT NOT NULL,
                trigger         TEXT NOT NULL,
                status          TEXT NOT NULL,
                started_at      TEXT NOT NULL,
                finished_at     TEXT NOT NULL,
                evidence_as_of  TEXT NOT NULL,
                summary         TEXT NOT NULL,
                provider_issues TEXT NOT NULL,
                report_id       TEXT,
                events_created  INTEGER NOT NULL DEFAULT 0,
                data            TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_watch_checks ON watch_checks(watch_id, started_at);

            CREATE TABLE IF NOT EXISTS watch_events (
                id              TEXT PRIMARY KEY,
                watch_id        TEXT NOT NULL,
                check_id        TEXT NOT NULL,
                dedupe_key      TEXT NOT NULL,
                subject         TEXT NOT NULL,
                priority        TEXT NOT NULL,
                change_type     TEXT NOT NULL,
                detected_at     TEXT NOT NULL,
                acknowledged_at TEXT,
                data            TEXT NOT NULL,
                UNIQUE (watch_id, dedupe_key)
            );
            CREATE INDEX IF NOT EXISTS idx_watch_events ON watch_events(watch_id, detected_at);
        """)
        conn.commit()


# ─── Rows → dicts ─────────────────────────────────────────────────────────────

def _watch(row: sqlite3.Row | None) -> dict | None:
    if row is None:
        return None
    w = dict(row)
    w["snapshot"] = json.loads(w["snapshot"])
    w["state"] = json.loads(w["state"])
    w["replay"] = json.loads(w["replay"]) if w["replay"] else None
    return w


def _event(row: sqlite3.Row) -> dict:
    ev = json.loads(row["data"])
    ev["acknowledged_at"] = row["acknowledged_at"]
    return ev


def _check(row: sqlite3.Row) -> dict:
    ch = json.loads(row["data"])
    ch["provider_issues"] = json.loads(row["provider_issues"])
    return ch


# ─── Watches ──────────────────────────────────────────────────────────────────

def create_watch(w: dict) -> None:
    with _conn() as conn:
        conn.execute(
            """
            INSERT INTO watches (id, name, status, mode, filename, baseline_report_id, latest_report_id,
                snapshot, package_count, state, revision, analyzed_at, baseline_as_of, evidence_as_of,
                enabled_at, next_check_at, replay, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                w["id"], w["name"], w["status"], w["mode"], w["filename"], w["baseline_report_id"],
                w["latest_report_id"], json.dumps(w["snapshot"]), w["package_count"], json.dumps(w["state"]),
                w["analyzed_at"], w["baseline_as_of"], w["evidence_as_of"], w["enabled_at"],
                w["next_check_at"], json.dumps(w["replay"]) if w.get("replay") else None, w["enabled_at"],
            ),
        )
        conn.execute(
            "INSERT OR IGNORE INTO watch_reports (report_id, watch_id, created_at) VALUES (?, ?, ?)",
            (w["baseline_report_id"], w["id"], w["enabled_at"]),
        )
        conn.commit()


def get_watch(watch_id: str) -> dict | None:
    with _conn() as conn:
        return _watch(conn.execute("SELECT * FROM watches WHERE id = ?", (watch_id,)).fetchone())


def get_watch_for_report(report_id: str) -> dict | None:
    with _conn() as conn:
        row = conn.execute(
            "SELECT w.* FROM watch_reports r JOIN watches w ON w.id = r.watch_id WHERE r.report_id = ?",
            (report_id,),
        ).fetchone()
        return _watch(row)


def list_watches() -> list[dict]:
    with _conn() as conn:
        return [_watch(r) for r in conn.execute("SELECT * FROM watches ORDER BY enabled_at DESC")]


def list_due_watch_ids(now: datetime) -> list[str]:
    with _conn() as conn:
        rows = conn.execute(
            "SELECT id FROM watches WHERE status = 'active' AND next_check_at IS NOT NULL AND next_check_at <= ? "
            "ORDER BY next_check_at",
            (ts(now),),
        ).fetchall()
        return [r["id"] for r in rows]


def set_status(watch_id: str, status: str, next_check_at: str | None) -> None:
    assert status in WATCH_STATUSES
    with _conn() as conn:
        conn.execute(
            "UPDATE watches SET status = ?, next_check_at = ?, updated_at = ? WHERE id = ?",
            (status, next_check_at, ts(utcnow()), watch_id),
        )
        conn.commit()


def set_replay(watch_id: str, replay: dict, next_check_at: str | None = None) -> None:
    with _conn() as conn:
        if next_check_at is None:
            conn.execute(
                "UPDATE watches SET replay = ?, updated_at = ? WHERE id = ?",
                (json.dumps(replay), ts(utcnow()), watch_id),
            )
        else:
            conn.execute(
                "UPDATE watches SET replay = ?, next_check_at = ?, updated_at = ? WHERE id = ?",
                (json.dumps(replay), next_check_at, ts(utcnow()), watch_id),
            )
        conn.commit()


def commit_check(
    *,
    watch_id: str,
    expected_revision: int,
    check: dict,
    events: list[dict],
    new_state: dict | None,
    latest_report_id: str | None,
    evidence_as_of: str | None,
    next_check_at: str | None,
) -> tuple[bool, int]:
    """
    Atomically record a check, its events and the new baseline.
    Returns (committed, events_inserted). committed=False means another check already
    advanced this watch (revision changed) and nothing was written.
    """
    conn = _conn()
    try:
        conn.execute("BEGIN IMMEDIATE")
        sets = ["last_checked_at = ?", "last_check_id = ?", "last_check_status = ?", "updated_at = ?", "next_check_at = ?"]
        params: list[Any] = [check["finished_at"], check["id"], check["status"], check["finished_at"], next_check_at]
        if new_state is not None:
            sets += ["state = ?", "revision = revision + 1"]
            params.append(json.dumps(new_state))
        if latest_report_id:
            sets.append("latest_report_id = ?")
            params.append(latest_report_id)
        if evidence_as_of:
            sets.append("evidence_as_of = ?")
            params.append(evidence_as_of)
        if events:
            sets.append("last_change_at = ?")
            params.append(check["finished_at"])
        params += [watch_id, expected_revision]
        updated = conn.execute(
            f"UPDATE watches SET {', '.join(sets)} WHERE id = ? AND revision = ?", params
        ).rowcount
        if updated != 1:
            conn.rollback()
            return False, 0

        inserted = 0
        for ev in events:
            inserted += conn.execute(
                """
                INSERT OR IGNORE INTO watch_events
                    (id, watch_id, check_id, dedupe_key, subject, priority, change_type, detected_at, data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (ev["id"], watch_id, check["id"], ev["dedupe_key"], ev["subject"], ev["priority"],
                 ev["change_type"], ev["detected_at"], json.dumps(ev, default=str)),
            ).rowcount
        check = {**check, "events_created": inserted}
        conn.execute(
            """
            INSERT INTO watch_checks (id, watch_id, trigger, status, started_at, finished_at, evidence_as_of,
                summary, provider_issues, report_id, events_created, data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (check["id"], watch_id, check["trigger"], check["status"], check["started_at"], check["finished_at"],
             check["evidence_as_of"], check["summary"], json.dumps(check["provider_issues"]), check.get("report_id"),
             inserted, json.dumps({k: v for k, v in check.items() if k != "provider_issues"}, default=str)),
        )
        if latest_report_id:
            conn.execute(
                "INSERT OR IGNORE INTO watch_reports (report_id, watch_id, created_at) VALUES (?, ?, ?)",
                (latest_report_id, watch_id, check["finished_at"]),
            )
        conn.commit()
        return True, inserted
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ─── Events & checks ──────────────────────────────────────────────────────────

def list_events(watch_id: str | None = None, *, limit: int = 50, unacknowledged_only: bool = False,
                statuses: tuple[str, ...] | None = None) -> list[dict]:
    clauses, params = [], []
    if watch_id:
        clauses.append("e.watch_id = ?")
        params.append(watch_id)
    if unacknowledged_only:
        clauses.append("e.acknowledged_at IS NULL")
    if statuses:
        clauses.append(f"w.status IN ({','.join('?' * len(statuses))})")
        params.extend(statuses)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with _conn() as conn:
        rows = conn.execute(
            f"SELECT e.* FROM watch_events e JOIN watches w ON w.id = e.watch_id {where} "
            f"ORDER BY e.detected_at DESC, e.rowid DESC LIMIT ?",
            (*params, limit),
        ).fetchall()
        return [_event(r) for r in rows]


def count_events(watch_id: str) -> tuple[int, int]:
    with _conn() as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS total, SUM(CASE WHEN acknowledged_at IS NULL THEN 1 ELSE 0 END) AS unack "
            "FROM watch_events WHERE watch_id = ?",
            (watch_id,),
        ).fetchone()
        return int(row["total"] or 0), int(row["unack"] or 0)


def count_unacknowledged(statuses: tuple[str, ...]) -> int:
    with _conn() as conn:
        row = conn.execute(
            f"SELECT COUNT(*) AS n FROM watch_events e JOIN watches w ON w.id = e.watch_id "
            f"WHERE e.acknowledged_at IS NULL AND w.status IN ({','.join('?' * len(statuses))})",
            statuses,
        ).fetchone()
        return int(row["n"] or 0)


def acknowledge_events(watch_id: str | None, event_ids: list[str] | None) -> int:
    clauses, params = ["acknowledged_at IS NULL"], [ts(utcnow())]
    if watch_id:
        clauses.append("watch_id = ?")
        params.append(watch_id)
    if event_ids:
        clauses.append(f"id IN ({','.join('?' * len(event_ids))})")
        params.extend(event_ids)
    with _conn() as conn:
        n = conn.execute(f"UPDATE watch_events SET acknowledged_at = ? WHERE {' AND '.join(clauses)}", params).rowcount
        conn.commit()
        return n


def list_checks(watch_id: str, limit: int = 10) -> list[dict]:
    with _conn() as conn:
        rows = conn.execute(
            "SELECT * FROM watch_checks WHERE watch_id = ? ORDER BY started_at DESC, rowid DESC LIMIT ?",
            (watch_id, limit),
        ).fetchall()
        return [_check(r) for r in rows]


def get_check(check_id: str) -> dict | None:
    with _conn() as conn:
        row = conn.execute("SELECT * FROM watch_checks WHERE id = ?", (check_id,)).fetchone()
        return _check(row) if row else None
