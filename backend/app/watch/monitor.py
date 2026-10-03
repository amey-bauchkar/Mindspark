"""
Warrant Watch monitor.

Stored monitored project → re-run the EXISTING analysis pipeline against current evidence
→ compare old vs new engine output → create security-change events → keep the updated
analysis available.

Guarantees:
- Exact state: re-analysis rebuilds the graph from the stored dependency snapshot.
- Honest failures: provider failures make a check "partial" or "failed", never clean.
- Idempotent: events carry a dedupe key and are committed together with the new baseline
  (compare-and-swap on the watch revision), so retries and restarts never repeat an alert.
- Temporal: every re-analysis has its own as-of; the original analysis is never modified.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import sqlite3
import uuid
from contextlib import nullcontext
from urllib.parse import unquote
from datetime import datetime, timedelta

import networkx as nx

from ..config import get_settings
from ..engine.decide import _node_label
from ..graph.build import ROOT_ID, find_paths
from ..jobs import NpmAnalysis, analyze_npm_lock
from ..parsers.npm_lock import parse_npm_lock
from ..parsers.snapshot import parse_from_snapshot, snapshot_from_parse
from ..providers.cache import (
    bypass_cache_reads, load_report, load_snapshot, retain_report, save_report, save_snapshot,
)
from ..providers.health import PROVIDER_NAMES, ProviderIssue, collect_provider_issues
from . import store
from .replay import REPLAY_LABEL, load_scenario
from .state import (
    ACTIONABLE, CANNOT_ASSESS, NKF, PackageChange, compare_states, evidence_diff, empty_package,
    package_signature, priority_for, rule_ids, state_from_report, state_signature,
)
from .store import parse_ts, ts, utcnow

logger = logging.getLogger("warrant.watch")

# Security-evidence cache entries re-fetched on every live check (other caches are reused).
SECURITY_CACHE_PREFIXES = ("osv_", "cisa_kev", "epss_")

LIVE_SOURCES = ["OSV (advisories + OpenSSF MAL-* malware reports)", "CISA KEV", "EPSS"]

VERDICT_LABELS = {"ACT_NOW": "ACT NOW", "NO_KNOWN_FINDING": "NO KNOWN FINDING", "CANNOT_ASSESS": "CANNOT ASSESS"}


class WatchError(Exception):
    status_code = 400


class WatchNotFound(WatchError):
    status_code = 404


class WatchConflict(WatchError):
    status_code = 409


class WatchRateLimited(WatchError):
    status_code = 429


# A manual live check is a full re-analysis against public providers; don't let it be spammed.
MANUAL_CHECK_COOLDOWN = timedelta(seconds=30)


def _label(verdict: str) -> str:
    return VERDICT_LABELS.get(verdict, verdict)


def _report_dict(analysis: NpmAnalysis) -> dict:
    # Same serialisation as save_report(report.model_dump()) for regular analyses.
    return json.loads(json.dumps(analysis.report.model_dump(), default=str))


def _interval(mode: str) -> timedelta:
    settings = get_settings()
    if mode == "replay":
        return timedelta(seconds=settings.watch_replay_interval_seconds)
    return timedelta(minutes=settings.watch_interval_minutes)


_locks: dict[tuple[int, str], asyncio.Lock] = {}


def _lock(watch_id: str) -> asyncio.Lock:
    key = (id(asyncio.get_running_loop()), watch_id)
    if key not in _locks:
        _locks[key] = asyncio.Lock()
    return _locks[key]


# ─── Views ────────────────────────────────────────────────────────────────────

def _replay_view(w: dict) -> dict | None:
    replay = w.get("replay")
    if not replay:
        return None
    try:
        scenario = load_scenario(replay["scenario_id"])
    except (KeyError, ValueError):
        return {**replay, "label": REPLAY_LABEL, "error": "Replay scenario unavailable"}
    clock = parse_ts(replay["clock"])
    upcoming = scenario.feed.change_times(clock, scenario.end)
    return {
        "scenario_id": scenario.id,
        "title": scenario.title,
        "description": scenario.description,
        "project": scenario.project,
        "label": REPLAY_LABEL,
        "clock": replay["clock"],
        "start": scenario.start.isoformat(),
        "end": scenario.end.isoformat(),
        "next_release_at": upcoming[0].isoformat() if upcoming else None,
        "remaining_steps": len(upcoming),
        "complete": not upcoming,
        "history": replay.get("history", []),
        "notes": scenario.meta.get("notes", []),
    }


def watch_view(w: dict, *, detail: bool = False) -> dict:
    total, unack = store.count_events(w["id"])
    latest = store.list_events(w["id"], limit=1)
    counts: dict[str, int] = {}
    for pkg in w["state"].values():
        counts[pkg["verdict"]] = counts.get(pkg["verdict"], 0) + 1
    packages = w["snapshot"].get("packages", [])
    view = {
        "id": w["id"],
        "name": w["name"],
        "status": w["status"],
        "mode": w["mode"],
        "simulated": w["mode"] == "replay",
        "label": REPLAY_LABEL if w["mode"] == "replay" else None,
        "filename": w["filename"],
        "baseline_report_id": w["baseline_report_id"],
        "latest_report_id": w["latest_report_id"],
        "package_count": w["package_count"],
        "direct_count": sum(1 for p in packages if p.get("depth") == 1),
        "analyzed_at": w["analyzed_at"],
        "baseline_as_of": w["baseline_as_of"],
        "evidence_as_of": w["evidence_as_of"],
        "enabled_at": w["enabled_at"],
        "last_checked_at": w["last_checked_at"],
        "last_check_status": w["last_check_status"],
        "last_change_at": w["last_change_at"],
        "next_check_at": w["next_check_at"],
        "interval_seconds": int(_interval(w["mode"]).total_seconds()),
        "manual_check_cooldown_seconds": int(MANUAL_CHECK_COOLDOWN.total_seconds()) if w["mode"] == "live" else 0,
        "sources": ["Recorded replay feed (real OSV / OpenSSF records)"] if w["mode"] == "replay" else LIVE_SOURCES,
        "current_verdicts": counts,
        "event_count": total,
        "unacknowledged_count": unack,
        "last_check": store.get_check(w["last_check_id"]) if w["last_check_id"] else None,
        "latest_event": latest[0] if latest else None,
        "replay": _replay_view(w),
    }
    if detail:
        view["events"] = store.list_events(w["id"], limit=100)
        view["checks"] = store.list_checks(w["id"], limit=10)
    return view


def get_watch_or_404(watch_id: str) -> dict:
    w = store.get_watch(watch_id)
    if w is None:
        raise WatchNotFound("Monitored project not found")
    return w


def eligibility(report_id: str) -> dict:
    report = load_report(report_id)
    if report is None:
        return {"eligible": False, "reason": "Report not found or expired."}
    if store.get_watch_for_report(report_id):
        return {"eligible": True, "reason": None}
    if report.get("meta", {}).get("ecosystem") != "npm":
        return {"eligible": False, "reason": "Warrant Watch currently monitors npm package-lock.json analyses."}
    if load_snapshot(report_id) is None:
        return {
            "eligible": False,
            "reason": "No stored dependency state for this report (imported, or older than 24 h). "
                      "Re-analyze the lockfile to enable monitoring.",
        }
    return {"eligible": True, "reason": None}


# ─── Lifecycle ────────────────────────────────────────────────────────────────

def enable_monitoring(report_id: str, name: str | None = None) -> dict:
    existing = store.get_watch_for_report(report_id)
    if existing:
        if existing["status"] != "active":
            resume(existing["id"])
        return store.get_watch(existing["id"])

    report = load_report(report_id)
    if report is None:
        raise WatchNotFound("Report not found or expired")
    check = eligibility(report_id)
    if not check["eligible"]:
        raise WatchConflict(check["reason"])
    snapshot = load_snapshot(report_id)

    now = utcnow()
    analyzed_at = ts(parse_ts(str(report["created_at"])))
    as_of = ts(parse_ts(str(report["summary"]["as_of"])))
    meta = report.get("meta", {})
    w = {
        "id": str(uuid.uuid4()),
        "name": (name or meta.get("root_name") or snapshot.get("name") or snapshot.get("filename") or "project")[:120],
        "status": "active",
        "mode": "live",
        "filename": snapshot.get("filename") or meta.get("filename") or "package-lock.json",
        "baseline_report_id": report_id,
        "latest_report_id": report_id,
        "snapshot": snapshot,
        "package_count": len(snapshot.get("packages", [])),
        "state": state_from_report(report),
        "analyzed_at": analyzed_at,
        "baseline_as_of": as_of,
        "evidence_as_of": as_of,
        "enabled_at": ts(now),
        "next_check_at": ts(now + _interval("live")),
        "replay": None,
    }
    retain_report(report_id)
    try:
        store.create_watch(w)
    except sqlite3.IntegrityError:  # Concurrent enable for the same report
        return store.get_watch_for_report(report_id)
    logger.info("Warrant Watch: monitoring enabled for %s (%d packages)", w["name"], w["package_count"])
    return store.get_watch(w["id"])


def pause(watch_id: str) -> dict:
    get_watch_or_404(watch_id)
    store.set_status(watch_id, "paused", None)
    return store.get_watch(watch_id)


def disable(watch_id: str) -> dict:
    get_watch_or_404(watch_id)
    store.set_status(watch_id, "disabled", None)
    return store.get_watch(watch_id)


def resume(watch_id: str) -> dict:
    get_watch_or_404(watch_id)
    store.set_status(watch_id, "active", ts(utcnow()))  # Due immediately: check on the next tick
    return store.get_watch(watch_id)


# ─── Checks ───────────────────────────────────────────────────────────────────

async def run_check(watch_id: str, trigger: str = "manual") -> dict:
    lock = _lock(watch_id)
    if lock.locked():
        raise WatchConflict("A check is already running for this project")
    async with lock:
        w = get_watch_or_404(watch_id)
        if w["status"] != "active":
            raise WatchConflict(f"Monitoring is {w['status']} for this project")
        last = parse_ts(w["last_checked_at"])
        if trigger == "manual" and w["mode"] == "live" and last and utcnow() - last < MANUAL_CHECK_COOLDOWN:
            wait = int((MANUAL_CHECK_COOLDOWN - (utcnow() - last)).total_seconds()) + 1
            raise WatchRateLimited(f"This project was checked moments ago — try again in {wait} s.")
        try:
            return await _run_check_locked(w, trigger)
        except Exception as exc:
            # Never leave a watch stuck "due" (the scheduler would retry it every tick), and never
            # record an internal error as "nothing changed".
            logger.exception("Warrant Watch: check failed unexpectedly for %s", watch_id)
            check = {
                "id": str(uuid.uuid4()), "watch_id": w["id"], "trigger": trigger, "mode": w["mode"],
                "simulated": w["mode"] == "replay", "label": REPLAY_LABEL if w["mode"] == "replay" else None,
                "started_at": ts(utcnow()), "finished_at": ts(utcnow()), "evidence_as_of": w["evidence_as_of"],
                "packages_checked": w["package_count"], "status": "failed", "report_id": None,
                "summary": f"Monitoring check failed — internal error ({type(exc).__name__}). "
                           "Previous decisions retained; this is not a clean result.",
                "provider_issues": [],
            }
            store.commit_check(watch_id=w["id"], expected_revision=w["revision"], check=check, events=[],
                               new_state=None, latest_report_id=None, evidence_as_of=None,
                               next_check_at=ts(utcnow() + _interval("live")))
            return {"check": check, "events": []}


def _classify(issues: list[ProviderIssue], report: dict) -> tuple[str, list[dict], str | None]:
    has_cves = any((e.get("data") or {}).get("cve_aliases") for e in report.get("evidence", []) if e.get("source") == "osv")
    relevant = [i for i in issues if has_cves or i.provider not in ("kev", "epss")]
    total = report.get("summary", {}).get("total_packages", 0)
    osv_batch_failed = sum(i.count for i in relevant if i.provider == "osv" and i.scope == "batch")
    providers = []
    for i in relevant:
        name = PROVIDER_NAMES.get(i.provider, i.provider)
        if name not in providers:
            providers.append(name)
    if total and osv_batch_failed >= total:
        return "failed", [i.to_dict() for i in relevant], (
            "Monitoring check failed — OSV unavailable. Previous decisions retained; this is not a clean result."
        )
    if relevant:
        return "partial", [i.to_dict() for i in relevant], (
            f"Monitoring partially completed — {', '.join(providers)} unavailable. "
            "Affected checks are not treated as clean; previous decisions retained where they could not be re-confirmed."
        )
    return "complete", [], None


async def _run_check_locked(w: dict, trigger: str) -> dict:
    settings = get_settings()
    started = utcnow()
    check_id = str(uuid.uuid4())
    mode = w["mode"]
    simulated = mode == "replay"

    if simulated:
        scenario = load_scenario(w["replay"]["scenario_id"])
        as_of = parse_ts(w["replay"]["clock"])
        providers = scenario.feed.providers(as_of)
        badge = "REPLAY"
        cache_ctx = nullcontext()
    else:
        as_of = started
        providers = None
        badge = None
        cache_ctx = bypass_cache_reads(SECURITY_CACHE_PREFIXES) if not settings.offline_fixtures else nullcontext()

    base_check = {
        "id": check_id, "watch_id": w["id"], "trigger": trigger, "mode": mode, "simulated": simulated,
        "label": REPLAY_LABEL if simulated else None, "started_at": ts(started), "evidence_as_of": ts(as_of),
        "packages_checked": w["package_count"],
    }
    # Replay feeds only change when the simulated clock is advanced (advance_replay re-arms the
    # short replay interval), so an idle replay watch falls back to the live cadence.
    next_check_at = ts(utcnow() + (_interval("live") if simulated else _interval(mode)))

    report_id = str(uuid.uuid4())
    snapshot = w["snapshot"]
    with collect_provider_issues() as issues, cache_ctx:
        try:
            analysis = await analyze_npm_lock(
                report_id, parse_from_snapshot(snapshot), w["filename"], snapshot.get("context") or {},
                as_of=as_of, providers=providers, data_badge=badge,
            )
        except Exception as exc:  # Never record a crashed check as "nothing changed"
            logger.exception("Warrant Watch: re-analysis failed for %s", w["id"])
            check = {**base_check, "status": "failed", "finished_at": ts(utcnow()), "report_id": None,
                     "summary": f"Monitoring check failed — re-analysis error ({type(exc).__name__}). "
                                "Previous decisions retained; this is not a clean result.",
                     "provider_issues": [i.to_dict() for i in issues]}
            store.commit_check(watch_id=w["id"], expected_revision=w["revision"], check=check, events=[],
                               new_state=None, latest_report_id=None, evidence_as_of=None, next_check_at=next_check_at)
            return {"check": check, "events": []}

    report = _report_dict(analysis)
    status, provider_issues, issue_summary = _classify(issues, report)

    if status == "failed":
        check = {**base_check, "status": "failed", "finished_at": ts(utcnow()), "report_id": None,
                 "summary": issue_summary, "provider_issues": provider_issues}
        store.commit_check(watch_id=w["id"], expected_revision=w["revision"], check=check, events=[],
                           new_state=None, latest_report_id=None, evidence_as_of=None, next_check_at=next_check_at)
        logger.warning("Warrant Watch: %s: %s", w["name"], issue_summary)
        return {"check": check, "events": []}

    new_state = state_from_report(report)
    comparison = compare_states(w["state"], new_state, complete=(status == "complete"))
    state_changed = state_signature(comparison.next_state) != state_signature(w["state"])
    finished = utcnow()

    events = [
        _build_event(w, change, analysis=analysis, report=report, report_id=report_id, check_id=check_id,
                     detected_at=finished, as_of=as_of, old_state=w["state"], new_state=new_state,
                     check_status=status)
        for change in comparison.changes
    ]
    events.sort(key=lambda e: ({"high": 0, "medium": 1, "low": 2, "info": 3}[e["priority"]], e["subject"]))

    saved_report_id = None
    if state_changed or events:
        _decorate_report(report, w, check_id=check_id, trigger=trigger, as_of=as_of, detected_at=finished,
                         status=status, provider_issues=provider_issues, issue_summary=issue_summary)
        save_report(report_id, report, retain=True)
        saved_report_id = report_id

    summary = _check_summary(w, events, comparison, status, issue_summary, as_of)
    check = {**base_check, "status": status, "finished_at": ts(finished), "report_id": saved_report_id,
             "summary": summary, "provider_issues": provider_issues,
             "evidence_changed": len(comparison.evidence_changed), "held": comparison.held[:50]}

    committed, inserted = store.commit_check(
        watch_id=w["id"], expected_revision=w["revision"], check=check, events=events,
        new_state=comparison.next_state if state_changed else None,
        latest_report_id=saved_report_id, evidence_as_of=ts(as_of) if status == "complete" else None,
        next_check_at=next_check_at,
    )
    if not committed:
        return {"check": {**check, "status": "superseded",
                          "summary": "Another check updated this project first; this result was discarded."},
                "events": []}
    for ev in events:
        logger.warning("Warrant Watch: SECURITY CHANGE DETECTED %s@%s %s -> %s (%s)%s", ev["package"], ev["version"],
                       ev["previous"]["verdict"], ev["current"]["verdict"], ev["priority"],
                       " [SIMULATED]" if simulated else "")
    return {"check": {**check, "events_created": inserted}, "events": events}


def _check_summary(w: dict, events: list[dict], comparison, status: str, issue_summary: str | None,
                   as_of: datetime) -> str:
    n = w["package_count"]
    if events:
        text = f"{len(events)} security change{'s' if len(events) != 1 else ''} detected."
    elif comparison.evidence_changed:
        text = "Security evidence changed; no decision change requiring attention."
    else:
        text = f"No new security evidence for the {n} monitored dependency versions."
    if status == "partial":
        text = f"{text} {issue_summary}"
    return text


# ─── Events ───────────────────────────────────────────────────────────────────

def _evidence_entry(subject: str, d: dict, via: str | None = None) -> dict:
    facts = d["current"] or d["previous"] or {}
    meta = d["meta"] or {}
    return {
        "key": d["key"],
        "id": facts.get("vuln_id") or facts.get("cve"),
        "change": d["change"],
        "fields_changed": d.get("fields_changed", []),
        "source": facts.get("source"),
        "origin": meta.get("origin"),
        "kind": facts.get("kind"),
        "tier": facts.get("tier"),
        "subject": subject,
        "via": via,
        "evidence_id": meta.get("evidence_id"),
        "evidence_in": "previous" if d["change"] == "removed" else "updated",
        "published_at": meta.get("published_at"),
        "observed_at": meta.get("observed_at"),
        "modified_at": meta.get("modified_at"),
        "withdrawn": bool(facts.get("withdrawn")),
        "url": meta.get("url"),
        "claim": meta.get("claim"),
        "fixed_version": facts.get("fixed_version"),
        "previous_fixed_version": (d.get("previous") or {}).get("fixed_version"),
        "epss": meta.get("epss"),
        "threshold": meta.get("threshold"),
    }


def _describe(entry: dict) -> str:
    ident = entry["id"] or entry["key"]
    who = f" ({entry['origin']})" if entry.get("origin") else ""
    target = unquote(entry["via"].split("pkg:npm/", 1)[-1]) if entry.get("via") else "this exact version"
    change = entry["change"]
    if entry["source"] == "kev":
        return f"{ident} was added to the CISA KEV catalogue (known exploited)." if change in ("added", "reinstated") \
            else f"{ident} is no longer listed in CISA KEV for this package."
    if entry["source"] == "epss":
        score = f"{entry['epss']:.3f}" if isinstance(entry.get("epss"), (int, float)) else "n/a"
        if change == "threshold_crossed" or (change == "added" and score != "n/a"):
            return f"EPSS for {ident} is {score} (threshold {entry.get('threshold')})."
        if change == "threshold_dropped":
            return f"EPSS for {ident} fell to {score}, below threshold {entry.get('threshold')}."
        return f"EPSS data for {ident} changed."
    kind = "Malware report" if entry.get("kind") == "malware_report" or (ident or "").startswith("MAL-") else "Advisory"
    if change == "added":
        fix = f" Fix: {entry['fixed_version']}." if entry.get("fixed_version") else ""
        return f"New {kind.lower()} {ident}{who} lists {target}.{fix}"
    if change == "withdrawn" or change == "added_withdrawn":
        return f"{kind} {ident}{who} was withdrawn by its source."
    if change == "reinstated":
        return f"{kind} {ident}{who} is no longer marked withdrawn."
    if change == "removed":
        return f"{kind} {ident} is no longer reported for {target}."
    fields = ", ".join(entry.get("fields_changed") or []) or "content"
    if "fixed_version" in (entry.get("fields_changed") or []):
        return f"{kind} {ident} was corrected: fixed version {entry.get('previous_fixed_version') or 'none'} → {entry.get('fixed_version') or 'none'}."
    return f"{kind} {ident} was modified ({fields})."


def _build_event(w: dict, change: PackageChange, *, analysis: NpmAnalysis, report: dict, report_id: str,
                 check_id: str, detected_at: datetime, as_of: datetime, old_state: dict, new_state: dict,
                 check_status: str) -> dict:
    subject = change.subject
    prev, cur = change.previous, change.current
    decision = next((d for d in report.get("decisions", []) if d["subject"] == subject), None)

    # Exposure and response come from the existing engine output.
    if decision:
        exposure = {
            "scope": decision["exposure"]["scope"],
            "paths": decision["exposure"]["paths"][:3],
            "is_direct": decision.get("is_direct", False),
            "introduced_by": decision.get("introduced_by", []),
        }
        response = {
            "class": decision["response"],
            "steps": [{"text": s.get("text"), "command": s.get("command")} for s in decision.get("response_steps", [])][:8],
            "fixed_version": decision.get("fixed_version"),
        }
    else:
        pkg = analysis.build.packages.get(subject)
        paths = find_paths(analysis.build.graph, ROOT_ID, subject, max_paths=3) if pkg else []
        exposure = {
            "scope": pkg.scope if pkg else None,
            "paths": [[_node_label(analysis.build, n) for n in p] for p in paths],
            "is_direct": bool(pkg and pkg.is_direct),
            "introduced_by": list(pkg.introduced_by) if pkg else [],
        }
        response = {"class": "none", "steps": [], "fixed_version": None}

    changed = [_evidence_entry(subject, d) for d in change.evidence_diff]

    # R1' carry: the triggering evidence lives on an incident descendant.
    if "R1'" in rule_ids(cur.get("derivation")) and subject in analysis.build.graph:
        descendants = nx.descendants(analysis.build.graph, subject)
        for other, pkg_state in new_state.items():
            if other in descendants and pkg_state["verdict"] == "INCIDENT" and "R1" in rule_ids(pkg_state.get("derivation")):
                old_other = old_state.get(other) or empty_package(other)
                changed += [_evidence_entry(other, d, via=other) for d in evidence_diff(old_other, pkg_state)]

    lines = [_describe(e) for e in changed]
    if cur.get("carry_reason") and "R1'" in rule_ids(cur.get("derivation")):
        lines.append(f"{cur['carry_reason']} (rule R1').")
    rule = ", ".join(rule_ids(cur.get("derivation"))) or ("R7" if cur["verdict"] == NKF else "")
    if prev["verdict"] != cur["verdict"]:
        lines.append(f"Warrant re-ran its decision rules: {_label(prev['verdict'])} → {_label(cur['verdict'])}"
                     + (f" ({rule})." if rule else "."))
    else:
        details = [f"{f} {prev.get(f) or '—'} → {cur.get(f) or '—'}" for f in ("urgency", "qualifier", "response", "fixed_version")
                   if prev.get(f) != cur.get(f)]
        if rule_ids(prev.get("derivation")) != rule_ids(cur.get("derivation")):
            details.append(f"rule {', '.join(rule_ids(prev.get('derivation'))) or '—'} → {rule or '—'}")
        lines.append(f"Verdict unchanged ({_label(cur['verdict'])})" + (f"; {'; '.join(details)}." if details else "; supporting evidence changed."))

    signature = [w["id"], w["revision"], subject, package_signature(prev), package_signature(cur)]
    dedupe_key = hashlib.sha256(json.dumps(signature, sort_keys=True, default=str).encode()).hexdigest()
    simulated = w["mode"] == "replay"

    def side(state: dict, rid: str) -> dict:
        return {
            "verdict": state["verdict"], "urgency": state["urgency"], "qualifier": state["qualifier"],
            "response": state["response"], "fixed_version": state.get("fixed_version"),
            "rules": rule_ids(state.get("derivation")), "what": state.get("what", ""), "report_id": rid,
        }

    return {
        "id": str(uuid.uuid4()),
        "watch_id": w["id"],
        "check_id": check_id,
        "dedupe_key": dedupe_key,
        "title": "SECURITY CHANGE DETECTED",
        "project": w["name"],
        "subject": subject,
        "package": cur.get("name") or prev.get("name") or subject,
        "version": cur.get("version") or prev.get("version") or "",
        "change_type": change.change_type,
        "priority": priority_for(change),
        "previous": side(prev, w["latest_report_id"]),
        "current": side(cur, report_id),
        "reason": " ".join(lines),
        "reason_lines": lines,
        "changed_evidence": changed,
        "evidence_sources": sorted({e["source"] for e in changed if e.get("source")}),
        "exposure": exposure,
        "response": response,
        "detected_at": ts(detected_at),
        "evidence_as_of": ts(as_of),
        "report_generated_at": str(report.get("created_at")),
        "report_id": report_id,
        "previous_report_id": w["latest_report_id"],
        "baseline_report_id": w["baseline_report_id"],
        "check_status": check_status,
        "mode": w["mode"],
        "simulated": simulated,
        "label": REPLAY_LABEL if simulated else None,
    }


def _decorate_report(report: dict, w: dict, *, check_id: str, trigger: str, as_of: datetime, detected_at: datetime,
                     status: str, provider_issues: list[dict], issue_summary: str | None) -> None:
    simulated = w["mode"] == "replay"
    meta = report.setdefault("meta", {})
    meta["watch"] = {
        "watch_id": w["id"],
        "check_id": check_id,
        "generated_by": "Warrant Watch",
        "trigger": trigger,
        "project": w["name"],
        "baseline_report_id": w["baseline_report_id"],
        "previous_report_id": w["latest_report_id"],
        "evidence_as_of": ts(as_of),
        "detected_at": ts(detected_at),
        "report_generated_at": str(report.get("created_at")),
        "check_status": status,
        "provider_issues": provider_issues,
        "mode": w["mode"],
        "simulated": simulated,
        "label": REPLAY_LABEL if simulated else None,
    }
    warnings = meta.setdefault("warnings", [])
    warnings.append(f"Re-analysis generated by Warrant Watch from the stored dependency state (evidence as of {ts(as_of)}).")
    if issue_summary:
        warnings.append(issue_summary)
    if simulated:
        _mark_replay(report, w["replay"]["scenario_id"], ts(as_of))


def _mark_replay(report: dict, scenario_id: str, clock: str) -> None:
    scenario = load_scenario(scenario_id)
    report.setdefault("meta", {})["replay"] = {
        "label": REPLAY_LABEL,
        "scenario_id": scenario.id,
        "title": scenario.title,
        "simulated_clock": clock,
        "project": scenario.project,
        "notes": scenario.meta.get("notes", []),
    }
    report.setdefault("coverage", []).insert(0, {
        "check": "Evidence source: recorded replay feed",
        "status": "Replay",
        "reason": f"{REPLAY_LABEL}. Real recorded OSV/OpenSSF records served as of simulated clock {clock}; "
                  "live providers were not queried.",
        "count": None,
    })


# ─── Demo / replay ────────────────────────────────────────────────────────────

async def create_replay_demo(scenario_id: str) -> dict:
    try:
        scenario = load_scenario(scenario_id)
    except KeyError:
        raise WatchNotFound("Replay scenario not found")
    content = scenario.lockfile_path().read_text(encoding="utf-8")
    filename = scenario.project.get("filename", "package-lock.json")
    parse = parse_npm_lock(content)
    report_id = str(uuid.uuid4())
    clock = scenario.start

    analysis = await analyze_npm_lock(
        report_id, parse, filename, {}, as_of=clock, providers=scenario.feed.providers(clock), data_badge="REPLAY",
    )
    report = _report_dict(analysis)
    report["meta"].setdefault("warnings", []).append(
        f"{REPLAY_LABEL}: baseline analysis at simulated clock {ts(clock)} using recorded evidence."
    )
    _mark_replay(report, scenario.id, ts(clock))
    save_report(report_id, report, retain=True)
    snapshot = snapshot_from_parse(parse, filename, {})
    save_snapshot(report_id, snapshot)

    now = utcnow()
    w = {
        "id": str(uuid.uuid4()),
        "name": f"{scenario.title}",
        "status": "active",
        "mode": "replay",
        "filename": filename,
        "baseline_report_id": report_id,
        "latest_report_id": report_id,
        "snapshot": snapshot,
        "package_count": len(snapshot["packages"]),
        "state": state_from_report(report),
        "analyzed_at": ts(parse_ts(str(report["created_at"]))),
        "baseline_as_of": ts(clock),
        "evidence_as_of": ts(clock),
        "enabled_at": ts(now),
        "next_check_at": ts(now + _interval("replay")),
        "replay": {"scenario_id": scenario.id, "clock": ts(clock), "history": []},
    }
    store.create_watch(w)
    logger.info("Warrant Watch: replay demo %s created (%s)", scenario.id, REPLAY_LABEL)
    return store.get_watch(w["id"])


async def advance_replay(watch_id: str) -> dict:
    """Release the next recorded evidence in the replay feed. Detection is left to the monitor."""
    lock = _lock(watch_id)
    async with lock:
        w = get_watch_or_404(watch_id)
        if w["mode"] != "replay":
            raise WatchConflict("Only DEMO / REPLAY projects have a simulated clock")
        scenario = load_scenario(w["replay"]["scenario_id"])
        clock = parse_ts(w["replay"]["clock"])
        nxt = scenario.next_change_after(clock)
        if nxt is None:
            raise WatchConflict("Replay complete — all recorded evidence in this scenario has been released.")
        released = scenario.feed.released_between(clock, nxt)
        now = utcnow()
        replay = {
            **w["replay"],
            "clock": ts(nxt),
            "history": [*w["replay"].get("history", []),
                        {"clock": ts(nxt), "released": released, "advanced_at": ts(now)}],
        }
        next_check = ts(now + _interval("replay")) if w["status"] == "active" else None
        store.set_replay(watch_id, replay, next_check_at=next_check)
        return {"label": REPLAY_LABEL, "clock": ts(nxt), "previous_clock": ts(clock), "released": released,
                "next_check_at": next_check}
