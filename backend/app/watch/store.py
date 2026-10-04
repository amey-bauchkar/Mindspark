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

            -- Notification channels (Slack / Teams / signed webhook) per monitored project
            CREATE TABLE IF NOT EXISTS watch_channels (
                id           TEXT PRIMARY KEY,
                watch_id     TEXT NOT NULL,
                kind         TEXT NOT NULL,
                url          TEXT NOT NULL,
                secret       TEXT,
                min_priority TEXT NOT NULL,
                label        TEXT,
                enabled      INTEGER NOT NULL DEFAULT 1,
                created_at   TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_watch_channels ON watch_channels(watch_id);

            -- Durable notification outbox: one row per (message, channel), retried until sent
            CREATE TABLE IF NOT EXISTS watch_deliveries (
                id              TEXT PRIMARY KEY,
                ref             TEXT NOT NULL,
                channel_key     TEXT NOT NULL,
                watch_id        TEXT NOT NULL,
                status          TEXT NOT NULL,
                attempts        INTEGER NOT NULL DEFAULT 0,
                last_error      TEXT,
                next_attempt_at TEXT NOT NULL,
                created_at      TEXT NOT NULL,
                sent_at         TEXT,
                payload         TEXT NOT NULL,
                UNIQUE (ref, channel_key)
            );
            CREATE INDEX IF NOT EXISTS idx_watch_deliveries ON watch_deliveries(status, next_attempt_at);
        """)
        _add_columns(conn, "watches", {
            "interval_minutes": "REAL",
            "lockfile_updated_at": "TEXT",
            "failure_streak": "INTEGER NOT NULL DEFAULT 0",
        })
        _add_columns(conn, "watch_events", {
            "triage_state": "TEXT NOT NULL DEFAULT 'open'",
            "triage_note": "TEXT",
            "triaged_at": "TEXT",
        })
        conn.commit()


def _add_columns(conn: sqlite3.Connection, table: str, columns: dict[str, str]) -> None:
    """Additive schema migration for databases created by earlier versions."""
    existing = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
    for name, decl in columns.items():
        if name not in existing:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")


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
    ev["triage_state"] = row["triage_state"]
    ev["triage_note"] = row["triage_note"]
    ev["triaged_at"] = row["triaged_at"]
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


def claim_due_watch(watch_id: str, now: datetime, lease_until: datetime) -> bool:
    """
    Atomically take a due check. Several scheduler processes can share one database: only the
    process whose UPDATE succeeds runs the check; the lease is replaced when the check commits.
    """
    with _conn() as conn:
        claimed = conn.execute(
            "UPDATE watches SET next_check_at = ? WHERE id = ? AND status = 'active' "
            "AND next_check_at IS NOT NULL AND next_check_at <= ?",
            (ts(lease_until), watch_id, ts(now)),
        ).rowcount
        conn.commit()
        return claimed == 1


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
        sets.append("failure_streak = CASE WHEN ? = 'failed' THEN failure_streak + 1 ELSE 0 END")
        params.append(check["status"])
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
        n = conn.execute(
            "UPDATE watch_events SET acknowledged_at = ?, "
            "triage_state = CASE WHEN triage_state = 'open' THEN 'acknowledged' ELSE triage_state END "
            f"WHERE {' AND '.join(clauses)}", params,
        ).rowcount
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


def find_live_watch_by_name(name: str) -> dict | None:
    """Most recently enabled live, not-disabled project with this name (CI sync key)."""
    with _conn() as conn:
        return _watch(conn.execute(
            "SELECT * FROM watches WHERE name = ? AND mode = 'live' AND status != 'disabled' "
            "ORDER BY enabled_at DESC LIMIT 1", (name,),
        ).fetchone())


def update_settings(watch_id: str, *, name: str | None, interval_minutes: float | None, clear_interval: bool) -> None:
    sets, params = ["updated_at = ?"], [ts(utcnow())]
    if name is not None:
        sets.append("name = ?")
        params.append(name)
    if clear_interval:
        sets.append("interval_minutes = NULL")
    elif interval_minutes is not None:
        sets.append("interval_minutes = ?")
        params.append(interval_minutes)
    with _conn() as conn:
        conn.execute(f"UPDATE watches SET {', '.join(sets)} WHERE id = ?", (*params, watch_id))
        conn.commit()


def replace_dependency_state(*, watch_id: str, expected_revision: int, snapshot: dict, state: dict,
                             report_id: str, filename: str, evidence_as_of: str, check: dict,
                             events: list[dict]) -> tuple[bool, int]:
    """Swap in a new lockfile (snapshot + baseline state) and record it, atomically."""
    conn = _conn()
    try:
        conn.execute("BEGIN IMMEDIATE")
        updated = conn.execute(
            """
            UPDATE watches SET snapshot = ?, state = ?, package_count = ?, latest_report_id = ?, filename = ?,
                evidence_as_of = ?, lockfile_updated_at = ?, last_checked_at = ?, last_check_id = ?,
                last_check_status = ?, revision = revision + 1, updated_at = ?,
                last_change_at = CASE WHEN ? > 0 THEN ? ELSE last_change_at END
            WHERE id = ? AND revision = ?
            """,
            (json.dumps(snapshot), json.dumps(state), len(snapshot.get("packages", [])), report_id, filename,
             evidence_as_of, check["finished_at"], check["finished_at"], check["id"], check["status"],
             check["finished_at"], len(events), check["finished_at"], watch_id, expected_revision),
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
        conn.execute(
            """
            INSERT INTO watch_checks (id, watch_id, trigger, status, started_at, finished_at, evidence_as_of,
                summary, provider_issues, report_id, events_created, data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (check["id"], watch_id, check["trigger"], check["status"], check["started_at"], check["finished_at"],
             check["evidence_as_of"], check["summary"], json.dumps(check["provider_issues"]), report_id,
             inserted, json.dumps({**{k: v for k, v in check.items() if k != "provider_issues"},
                                   "events_created": inserted}, default=str)),
        )
        conn.execute("INSERT OR IGNORE INTO watch_reports (report_id, watch_id, created_at) VALUES (?, ?, ?)",
                     (report_id, watch_id, check["finished_at"]))
        conn.commit()
        return True, inserted
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def delete_watch(watch_id: str) -> list[str]:
    """Delete a project and everything attached to it. Returns its report ids (to release retention)."""
    with _conn() as conn:
        report_ids = [r["report_id"] for r in conn.execute(
            "SELECT report_id FROM watch_reports WHERE watch_id = ?", (watch_id,))]
        for table in ("watch_events", "watch_checks", "watch_channels", "watch_deliveries", "watch_reports"):
            conn.execute(f"DELETE FROM {table} WHERE watch_id = ?", (watch_id,))
        conn.execute("DELETE FROM watches WHERE id = ?", (watch_id,))
        conn.commit()
        return report_ids


TRIAGE_STATES = ("open", "acknowledged", "accepted_risk", "resolved")


def triage_event(watch_id: str, event_id: str, state: str, note: str | None) -> bool:
    assert state in TRIAGE_STATES
    now = ts(utcnow())
    with _conn() as conn:
        n = conn.execute(
            "UPDATE watch_events SET triage_state = ?, triage_note = ?, triaged_at = ?, "
            "acknowledged_at = CASE WHEN ? = 'open' THEN NULL ELSE COALESCE(acknowledged_at, ?) END "
            "WHERE id = ? AND watch_id = ?",
            (state, note, now, state, now, event_id, watch_id),
        ).rowcount
        conn.commit()
        return n == 1


def get_event(event_id: str) -> dict | None:
    with _conn() as conn:
        row = conn.execute("SELECT * FROM watch_events WHERE id = ?", (event_id,)).fetchone()
        return _event(row) if row else None


# ─── Notification channels & outbox ───────────────────────────────────────────

def create_channel(ch: dict) -> None:
    with _conn() as conn:
        conn.execute(
            "INSERT INTO watch_channels (id, watch_id, kind, url, secret, min_priority, label, enabled, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)",
            (ch["id"], ch["watch_id"], ch["kind"], ch["url"], ch.get("secret"), ch["min_priority"], ch.get("label"),
             ch["created_at"]),
        )
        conn.commit()


def list_channels(watch_id: str | None = None) -> list[dict]:
    with _conn() as conn:
        if watch_id:
            rows = conn.execute("SELECT * FROM watch_channels WHERE watch_id = ? ORDER BY created_at", (watch_id,))
        else:
            rows = conn.execute("SELECT * FROM watch_channels ORDER BY created_at")
        return [dict(r) for r in rows]


def get_channel(channel_id: str) -> dict | None:
    with _conn() as conn:
        row = conn.execute("SELECT * FROM watch_channels WHERE id = ?", (channel_id,)).fetchone()
        return dict(row) if row else None


def delete_channel(watch_id: str, channel_id: str) -> bool:
    with _conn() as conn:
        n = conn.execute("DELETE FROM watch_channels WHERE id = ? AND watch_id = ?", (channel_id, watch_id)).rowcount
        conn.execute("DELETE FROM watch_deliveries WHERE channel_key = ? AND status != 'sent'", (channel_id,))
        conn.commit()
        return n == 1


def enqueue_delivery(*, ref: str, channel_key: str, watch_id: str, payload: dict, now: datetime) -> bool:
    """Idempotent: the same message is queued at most once per channel."""
    import uuid as _uuid
    with _conn() as conn:
        n = conn.execute(
            "INSERT OR IGNORE INTO watch_deliveries (id, ref, channel_key, watch_id, status, attempts, "
            "next_attempt_at, created_at, payload) VALUES (?, ?, ?, ?, 'pending', 0, ?, ?, ?)",
            (str(_uuid.uuid4()), ref, channel_key, watch_id, ts(now), ts(now), json.dumps(payload, default=str)),
        ).rowcount
        conn.commit()
        return n == 1


def due_deliveries(now: datetime, limit: int = 50) -> list[dict]:
    with _conn() as conn:
        rows = conn.execute(
            "SELECT * FROM watch_deliveries WHERE status = 'pending' AND next_attempt_at <= ? "
            "ORDER BY next_attempt_at LIMIT ?", (ts(now), limit),
        ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["payload"] = json.loads(d["payload"])
            out.append(d)
        return out


def claim_delivery(delivery_id: str, now: datetime, lease_until: datetime) -> bool:
    with _conn() as conn:
        n = conn.execute(
            "UPDATE watch_deliveries SET next_attempt_at = ? WHERE id = ? AND status = 'pending' AND next_attempt_at <= ?",
            (ts(lease_until), delivery_id, ts(now)),
        ).rowcount
        conn.commit()
        return n == 1


def finish_delivery(delivery_id: str, *, sent: bool, error: str | None, next_attempt_at: datetime | None,
                    give_up: bool) -> None:
    now = ts(utcnow())
    status = "sent" if sent else ("failed" if give_up else "pending")
    with _conn() as conn:
        conn.execute(
            "UPDATE watch_deliveries SET status = ?, attempts = attempts + 1, last_error = ?, sent_at = ?, "
            "next_attempt_at = ? WHERE id = ?",
            (status, (error or "")[:300] or None, now if sent else None,
             ts(next_attempt_at) if next_attempt_at else now, delivery_id),
        )
        conn.commit()


def list_deliveries(watch_id: str, limit: int = 30) -> list[dict]:
    with _conn() as conn:
        rows = conn.execute(
            "SELECT id, ref, channel_key, status, attempts, last_error, created_at, sent_at, next_attempt_at "
            "FROM watch_deliveries WHERE watch_id = ? ORDER BY created_at DESC LIMIT ?", (watch_id, limit),
        ).fetchall()
        return [dict(r) for r in rows]


def delivery_stats() -> dict:
    with _conn() as conn:
        rows = conn.execute("SELECT status, COUNT(*) AS n FROM watch_deliveries GROUP BY status").fetchall()
        return {r["status"]: r["n"] for r in rows}


def events_since(created_after: str, watch_id: str | None = None) -> list[dict]:
    """Events created after a channel was added — used to reconcile the outbox after a crash."""
    with _conn() as conn:
        if watch_id:
            rows = conn.execute("SELECT * FROM watch_events WHERE detected_at >= ? AND watch_id = ?",
                                (created_after, watch_id)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM watch_events WHERE detected_at >= ?", (created_after,)).fetchall()
        return [_event(r) for r in rows]


def count_due(now: datetime) -> int:
    with _conn() as conn:
        return conn.execute(
            "SELECT COUNT(*) AS n FROM watches WHERE status = 'active' AND next_check_at <= ?", (ts(now),),
        ).fetchone()["n"]


def failing_watches(min_streak: int = 1) -> list[dict]:
    with _conn() as conn:
        rows = conn.execute(
            "SELECT id, name, failure_streak, last_checked_at FROM watches WHERE failure_streak >= ? "
            "AND status = 'active'", (min_streak,),
        ).fetchall()
        return [dict(r) for r in rows]
