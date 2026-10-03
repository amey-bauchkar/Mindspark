"""
Warrant Watch tests — continuous security-evidence monitoring.

Live-mode tests run the REAL providers (OSV, CISA KEV, EPSS, npm registry) against an
offline fake of those public APIs (httpx.MockTransport), so provider code — including its
failure paths — is exercised exactly as in production. Test packages are fictional
(`acme-*`) and test advisories use reserved-looking ids; nothing here is a real finding.

Run with: pytest tests/
"""
from __future__ import annotations

import asyncio
import json
import shutil
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

import httpx
import pytest

from app.config import get_settings
from app.engine.decide import derive_decisions
from app.graph.build import build_graph
from app.jobs import analyze_npm_lock, run_analysis
from app.models.report import AnalysisContext
from app.parsers.npm_lock import parse_npm_lock
from app.parsers.snapshot import parse_from_snapshot, snapshot_from_parse
from app.providers import cache as cache_mod
from app.providers import epss as epss_mod
from app.providers import npm_registry as npm_mod
from app.providers import osv as osv_mod
from app.providers.cache import init_db, load_report, load_snapshot
from app.providers.health import collect_provider_issues, report_provider_issue
from app.watch import monitor, replay as replay_mod, store
from app.watch.scheduler import WatchScheduler
from app.watch.state import compare_states, empty_package, state_from_report

SAMPLES = Path(__file__).resolve().parent.parent / "fixtures" / "samples"
NOW = datetime.now(timezone.utc)

# Hoisted npm v3 layout (as npm writes it): acme-tiny-parser is reached through acme-http-client.
LOCKFILE = json.dumps({
    "name": "watch-test-app", "version": "1.0.0", "lockfileVersion": 3,
    "packages": {
        "": {"name": "watch-test-app", "version": "1.0.0",
             "dependencies": {"acme-http-client": "^2.3.0"}, "devDependencies": {"acme-dev-runner": "0.9.0"}},
        "node_modules/acme-http-client": {
            "version": "2.3.0", "license": "MIT",
            "resolved": "https://registry.npmjs.org/acme-http-client/-/acme-http-client-2.3.0.tgz",
            "dependencies": {"acme-tiny-parser": "^1.1.0"},
        },
        "node_modules/acme-tiny-parser": {
            "version": "1.1.0", "license": "MIT",
            "resolved": "https://registry.npmjs.org/acme-tiny-parser/-/acme-tiny-parser-1.1.0.tgz",
        },
        "node_modules/acme-dev-runner": {
            "version": "0.9.0", "license": "MIT", "dev": True,
            "resolved": "https://registry.npmjs.org/acme-dev-runner/-/acme-dev-runner-0.9.0.tgz",
        },
    },
})
PARSER = "pkg:npm/acme-tiny-parser@1.1.0"
CLIENT = "pkg:npm/acme-http-client@2.3.0"
DEVRUN = "pkg:npm/acme-dev-runner@0.9.0"


def iso(dt: datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


def osv_record(vid: str, name: str, version: str, *, fixed: str | None = "9.9.9", cves=(), published=None,
               withdrawn=None, modified=None, malware=False) -> dict:
    affected = {"package": {"name": name, "ecosystem": "npm"}, "versions": [version]}
    if fixed:
        affected["ranges"] = [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": fixed}]}]
    rec = {
        "id": vid,
        "summary": f"{'Malicious code' if malware else 'Test advisory'} in {name}",
        "published": iso(published or NOW - timedelta(hours=1)),
        "modified": iso(modified or published or NOW - timedelta(hours=1)),
        "aliases": list(cves),
        "affected": [affected],
        "references": [{"type": "ADVISORY", "url": f"https://osv.dev/vulnerability/{vid}"}],
    }
    if withdrawn:
        rec["withdrawn"] = iso(withdrawn)
    return rec


class FakeInternet:
    """Offline stand-in for OSV, CISA KEV, FIRST EPSS, npm registry and deps.dev."""

    def __init__(self):
        self.records: dict[str, dict] = {}
        self.kev: set[str] = set()
        self.epss: dict[str, float] = {}
        recent = iso(NOW - timedelta(days=120))
        self.registry = {
            name: {"created": recent, "modified": recent, version: recent}
            for name, version in (("acme-http-client", "2.3.0"), ("acme-tiny-parser", "1.1.0"),
                                  ("acme-dev-runner", "0.9.0"))
        }
        self.down: set[str] = set()   # {"osv", "osv-detail", "kev", "epss", "registry"}
        self.calls: list[str] = []

    def add(self, rec: dict) -> None:
        self.records[rec["id"]] = rec

    def handler(self, request: httpx.Request) -> httpx.Response:
        url = request.url
        self.calls.append(f"{request.method} {url.host}{url.path}")
        if url.host == "api.osv.dev" and url.path == "/v1/querybatch":
            if "osv" in self.down:
                return httpx.Response(503)
            results = []
            for q in json.loads(request.content)["queries"]:
                vulns = [{"id": r["id"], "modified": r["modified"]} for r in self.records.values()
                         if any(a["package"]["name"] == q["package"]["name"] and q["version"] in a.get("versions", [])
                                for a in r["affected"])]
                results.append({"vulns": vulns} if vulns else {})
            return httpx.Response(200, json={"results": results})
        if url.host == "api.osv.dev" and url.path.startswith("/v1/vulns/"):
            if "osv-detail" in self.down:
                return httpx.Response(500)
            rec = self.records.get(url.path.rsplit("/", 1)[-1])
            return httpx.Response(200, json=rec) if rec else httpx.Response(404)
        if url.host == "www.cisa.gov":
            if "kev" in self.down:
                return httpx.Response(503)
            return httpx.Response(200, json={"vulnerabilities": [{"cveID": c} for c in sorted(self.kev)]})
        if url.host == "api.first.org":
            if "epss" in self.down:
                return httpx.Response(503)
            cves = parse_qs(urlparse(str(url)).query).get("cve", [""])[0].split(",")
            return httpx.Response(200, json={"data": [{"cve": c, "epss": str(self.epss[c])} for c in cves if c in self.epss]})
        if url.host == "registry.npmjs.org":
            if "registry" in self.down:
                return httpx.Response(503)
            name = unquote(url.path.lstrip("/"))
            return httpx.Response(200, json={"time": self.registry[name]}) if name in self.registry else httpx.Response(404)
        return httpx.Response(404)


@pytest.fixture
def env(tmp_path, monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "db_path", str(tmp_path / "watch.db"))
    monkeypatch.setattr(settings, "watch_scheduler_enabled", False)
    monkeypatch.setattr(settings, "watch_enabled", True)
    monkeypatch.setattr(settings, "offline_fixtures", False)
    for mod in (osv_mod, epss_mod, npm_mod):
        monkeypatch.setattr(mod, "MAX_RETRIES", 1)  # No backoff sleeps in tests
    net = FakeInternet()
    real_client = httpx.AsyncClient
    monkeypatch.setattr(httpx, "AsyncClient",
                        lambda *a, **kw: real_client(*a, transport=httpx.MockTransport(net.handler), **kw))
    init_db()
    store.init_watch_db()
    return net


def analyze(content: str = LOCKFILE, context: dict | None = None) -> str:
    import uuid
    rid = str(uuid.uuid4())
    asyncio.run(run_analysis(rid, content, "package-lock.json", context or {}))
    return rid


def enable(report_id: str) -> dict:
    return monitor.enable_monitoring(report_id)


def check(watch_id: str, trigger: str = "manual") -> dict:
    return asyncio.run(monitor.run_check(watch_id, trigger))


def decisions(report: dict) -> dict[str, dict]:
    return {d["subject"]: d for d in report["decisions"]}


def all_events(watch_id: str) -> list[dict]:
    return store.list_events(watch_id, limit=1000)


# ─── 1. Analyze → enable monitoring ───────────────────────────────────────────

def test_analyze_then_enable_monitoring_via_api(env):
    from fastapi.testclient import TestClient
    import app.main

    with TestClient(app.main.app) as client:
        rid = client.post("/api/analyze", data={"text": LOCKFILE, "context": "{}"}).json()["report_id"]
        assert client.get(f"/api/reports/{rid}").status_code == 200

        before = client.get(f"/api/watch/by-report/{rid}").json()
        assert before["watch"] is None and before["eligibility"]["eligible"] is True

        w = client.post("/api/watch", json={"report_id": rid}).json()
        assert w["status"] == "active" and w["mode"] == "live" and w["simulated"] is False
        assert w["baseline_report_id"] == rid == w["latest_report_id"]
        assert w["package_count"] == 3
        assert w["next_check_at"] and w["last_checked_at"] is None
        # Enabling twice is idempotent
        assert client.post("/api/watch", json={"report_id": rid}).json()["id"] == w["id"]
        assert client.get(f"/api/watch/by-report/{rid}").json()["watch"]["id"] == w["id"]

    # Exact dependency state was persisted (names, versions, scope flags, edges) — not the raw lockfile
    stored = store.get_watch(w["id"])["snapshot"]
    pkgs = {p["purl"]: p for p in stored["packages"]}
    assert set(pkgs) == {CLIENT, PARSER, DEVRUN}
    assert pkgs[CLIENT]["edges"] == {"acme-tiny-parser": PARSER}
    assert pkgs[DEVRUN]["dev"] is True
    assert "integrity" not in json.dumps(stored) and pkgs[CLIENT]["resolved_url"] is None


def test_monitoring_requires_stored_dependency_state(env):
    from fastapi.testclient import TestClient
    import app.main

    with TestClient(app.main.app) as client:
        report = load_report(analyze())
        report["id"] = "imported-report"
        imported = client.post("/api/reports/import",
                               files={"file": ("r.json", json.dumps(report).encode(), "application/json")}).json()
        res = client.post("/api/watch", json={"report_id": imported["report_id"]})
        assert res.status_code == 409 and "No stored dependency state" in res.json()["detail"]
        assert client.post("/api/watch", json={"report_id": "missing"}).status_code == 404


# ─── 2. No new evidence → no event ────────────────────────────────────────────

def test_no_new_evidence_no_event(env):
    rid = analyze()
    w = enable(rid)
    result = check(w["id"])
    assert result["check"]["status"] == "complete"
    assert result["events"] == [] and all_events(w["id"]) == []
    assert "No new security evidence" in result["check"]["summary"]
    after = store.get_watch(w["id"])
    assert after["latest_report_id"] == rid and after["revision"] == 0
    assert after["last_check_status"] == "complete" and after["last_checked_at"]


def test_live_checks_refetch_security_evidence_instead_of_cache(env):
    rid = analyze()
    w = enable(rid)
    env.calls.clear()
    check(w["id"])
    assert any(c.endswith("/v1/querybatch") for c in env.calls), "OSV must be re-queried, not served from cache"
    assert any("www.cisa.gov" in c for c in env.calls), "KEV must be re-fetched, not served from cache"


# ─── 3 & 4. New advisory on the exact version → re-analysis → NKF → UPGRADE ───

def test_new_advisory_exact_version_reanalysis_and_upgrade_event(env):
    rid = analyze()
    w = enable(rid)
    env.add(osv_record("GHSA-test-0001", "acme-tiny-parser", "1.1.0", fixed="1.1.1"))
    env.add(osv_record("GHSA-test-0002", "acme-tiny-parser", "1.0.9", fixed="1.1.0"))  # other version: must not match

    result = check(w["id"])
    assert result["check"]["status"] == "complete"
    [ev] = result["events"]
    assert ev["subject"] == PARSER and ev["package"] == "acme-tiny-parser" and ev["version"] == "1.1.0"
    assert ev["previous"]["verdict"] == "NO_KNOWN_FINDING" and ev["current"]["verdict"] == "UPGRADE"
    assert ev["previous"]["urgency"] == "NONE" and ev["current"]["urgency"] == "SCHEDULED"
    assert ev["change_type"] == "ESCALATION" and ev["priority"] == "medium"
    assert [e["id"] for e in ev["changed_evidence"]] == ["GHSA-test-0001"]

    # Re-analysis produced a new, stored report through the existing engine
    new_report = load_report(ev["report_id"])
    assert ev["report_id"] != rid and decisions(new_report)[PARSER]["verdict"] == "UPGRADE"
    assert decisions(new_report)[PARSER]["derivation"][0].startswith("R3")
    assert new_report["meta"]["watch"]["watch_id"] == w["id"]
    assert store.get_watch(w["id"])["latest_report_id"] == ev["report_id"]
    # The parent package's verdict is unaffected (no R1' for advisories)
    assert CLIENT not in decisions(new_report)


def test_dev_only_advisory_gives_monitor_event(env):
    w = enable(analyze())
    env.add(osv_record("GHSA-test-0003", "acme-dev-runner", "0.9.0", fixed="1.0.0"))
    [ev] = check(w["id"])["events"]
    assert ev["subject"] == DEVRUN and ev["current"]["verdict"] == "MONITOR" and ev["priority"] == "low"
    assert ev["exposure"]["scope"] == "dev"


# ─── 5. NKF → ACT NOW ─────────────────────────────────────────────────────────

def test_kev_listed_advisory_gives_act_now_high_priority(env):
    w = enable(analyze())
    env.add(osv_record("GHSA-test-0010", "acme-tiny-parser", "1.1.0", fixed="1.1.1", cves=["CVE-2099-0010"]))
    env.kev.add("CVE-2099-0010")
    [ev] = check(w["id"])["events"]
    assert ev["previous"]["verdict"] == "NO_KNOWN_FINDING" and ev["current"]["verdict"] == "ACT_NOW"
    assert ev["current"]["urgency"] == "IMMEDIATE" and ev["priority"] == "high"
    assert {e["source"] for e in ev["changed_evidence"]} == {"osv", "kev"}
    assert ev["response"]["class"] == "minimal_upgrade"


def test_high_epss_advisory_gives_act_now(env):
    w = enable(analyze())
    env.add(osv_record("GHSA-test-0011", "acme-tiny-parser", "1.1.0", fixed="1.1.1", cves=["CVE-2099-0011"]))
    env.epss["CVE-2099-0011"] = 0.42
    [ev] = check(w["id"])["events"]
    assert ev["current"]["verdict"] == "ACT_NOW" and ev["current"]["urgency"] == "OUT_OF_CYCLE"
    assert ev["priority"] == "high"


# ─── 6. NKF → INCIDENT (high priority) ────────────────────────────────────────

def test_malware_report_gives_incident_high_priority_with_carry(env):
    w = enable(analyze())
    env.add(osv_record("MAL-2099-0001", "acme-tiny-parser", "1.1.0", fixed=None, malware=True))
    result = check(w["id"])
    by_subject = {e["subject"]: e for e in result["events"]}
    assert set(by_subject) == {PARSER, CLIENT}
    direct = by_subject[PARSER]
    assert direct["current"]["verdict"] == "INCIDENT" and direct["priority"] == "high"
    assert direct["current"]["rules"] == ["R1"] and direct["response"]["class"] == "containment"
    carried = by_subject[CLIENT]  # Ancestor carries the incident (existing rule R1')
    assert carried["current"]["verdict"] == "INCIDENT" and carried["current"]["rules"] == ["R1'"]
    assert carried["changed_evidence"][0]["id"] == "MAL-2099-0001"
    assert carried["changed_evidence"][0]["via"] == PARSER
    assert result["events"][0]["priority"] == "high"


# ─── 7. Existing finding becomes more severe ──────────────────────────────────

def test_existing_upgrade_escalates_to_act_now_when_kev_lists_cve(env):
    env.add(osv_record("GHSA-test-0020", "acme-tiny-parser", "1.1.0", fixed="1.1.1", cves=["CVE-2099-0020"]))
    rid = analyze()
    assert decisions(load_report(rid))[PARSER]["verdict"] == "UPGRADE"
    w = enable(rid)
    assert check(w["id"])["events"] == []

    env.kev.add("CVE-2099-0020")
    [ev] = check(w["id"])["events"]
    assert ev["previous"]["verdict"] == "UPGRADE" and ev["current"]["verdict"] == "ACT_NOW"
    assert ev["change_type"] == "ESCALATION" and ev["priority"] == "high"
    assert any(e["source"] == "kev" and e["change"] == "added" for e in ev["changed_evidence"])


def test_epss_noise_below_threshold_is_not_an_event(env):
    env.add(osv_record("GHSA-test-0021", "acme-tiny-parser", "1.1.0", fixed="1.1.1", cves=["CVE-2099-0021"]))
    env.epss["CVE-2099-0021"] = 0.01
    w = enable(analyze())
    env.epss["CVE-2099-0021"] = 0.02  # Daily score drift, still below threshold
    assert check(w["id"])["events"] == []
    env.epss["CVE-2099-0021"] = 0.35  # Crosses threshold → decision changes
    [ev] = check(w["id"])["events"]
    assert ev["current"]["verdict"] == "ACT_NOW"
    assert any(e["change"] == "threshold_crossed" for e in ev["changed_evidence"])


def test_second_malware_report_strengthens_incident_event(env):
    env.add(osv_record("MAL-2099-0030", "acme-tiny-parser", "1.1.0", fixed=None, malware=True))
    w = enable(analyze())
    env.add(osv_record("MAL-2099-0031", "acme-tiny-parser", "1.1.0", fixed=None, malware=True))
    events = {e["subject"]: e for e in check(w["id"])["events"]}
    ev = events[PARSER]
    assert ev["change_type"] == "EVIDENCE_CHANGE"
    assert ev["previous"]["qualifier"] == "PROBABLE" and ev["current"]["qualifier"] == "ESTABLISHED"


def test_advisory_correction_changing_fix_version_is_an_event(env):
    env.add(osv_record("GHSA-test-0040", "acme-tiny-parser", "1.1.0", fixed="1.1.1"))
    w = enable(analyze())
    env.add(osv_record("GHSA-test-0040", "acme-tiny-parser", "1.1.0", fixed="1.2.0",
                       modified=NOW - timedelta(minutes=5)))
    [ev] = check(w["id"])["events"]
    assert ev["change_type"] == "EVIDENCE_CHANGE"
    assert ev["previous"]["fixed_version"] == "1.1.1" and ev["current"]["fixed_version"] == "1.2.0"
    assert ev["changed_evidence"][0]["change"] == "modified"
    assert "fixed version 1.1.1 → 1.2.0" in ev["reason"]


def test_text_only_advisory_modification_is_not_an_event(env):
    env.add(osv_record("GHSA-test-0041", "acme-tiny-parser", "1.1.0", fixed="1.1.1"))
    w = enable(analyze())
    rec = osv_record("GHSA-test-0041", "acme-tiny-parser", "1.1.0", fixed="1.1.1", modified=NOW - timedelta(minutes=1))
    rec["summary"] = "Reworded summary"
    env.add(rec)
    assert check(w["id"])["events"] == []


# ─── 8. Advisory withdrawal ───────────────────────────────────────────────────

def test_advisory_withdrawal_reanalysis_de_escalates(env):
    w = enable(analyze())
    env.add(osv_record("GHSA-test-0050", "acme-tiny-parser", "1.1.0", fixed="1.1.1", cves=["CVE-2099-0050"]))
    env.epss["CVE-2099-0050"] = 0.01
    [first] = check(w["id"])["events"]
    assert first["current"]["verdict"] == "UPGRADE"

    env.add(osv_record("GHSA-test-0050", "acme-tiny-parser", "1.1.0", fixed="1.1.1", cves=["CVE-2099-0050"],
                       withdrawn=NOW - timedelta(minutes=2), modified=NOW - timedelta(minutes=2)))
    [ev] = check(w["id"])["events"]
    assert ev["change_type"] == "DE_ESCALATION" and ev["priority"] == "info"
    assert ev["previous"]["verdict"] == "UPGRADE" and ev["current"]["verdict"] == "NO_KNOWN_FINDING"
    assert ev["changed_evidence"][0]["change"] == "withdrawn" and "withdrawn" in ev["reason"]
    report = load_report(ev["report_id"])
    assert PARSER not in decisions(report)  # Existing engine excludes withdrawn evidence (rule R7)
    assert any(e["withdrawn"] for e in report["evidence"] if e["subject"] == PARSER)
    assert check(w["id"])["events"] == []


def test_withdrawal_that_leaves_engine_unable_to_assess_is_reported_not_hidden(env):
    w = enable(analyze())
    env.add(osv_record("GHSA-test-0051", "acme-tiny-parser", "1.1.0", fixed="1.1.1"))  # No CVE alias
    check(w["id"])
    env.add(osv_record("GHSA-test-0051", "acme-tiny-parser", "1.1.0", fixed="1.1.1",
                       withdrawn=NOW - timedelta(minutes=2), modified=NOW - timedelta(minutes=2)))
    [ev] = check(w["id"])["events"]
    # Existing engine: the withdrawn advisory still leaves an "EPSS n/a" absent record → R6 CANNOT ASSESS
    assert ev["previous"]["verdict"] == "UPGRADE" and ev["current"]["verdict"] == "CANNOT_ASSESS"
    assert ev["change_type"] == "DE_ESCALATION" and ev["priority"] == "low"  # Never presented as resolved
    assert store.get_watch(w["id"])["state"][PARSER]["verdict"] == "CANNOT_ASSESS"


# ─── 9. Provider failure → partial/failed, never clean ────────────────────────

def test_osv_outage_fails_check_and_never_reports_clean(env):
    env.add(osv_record("GHSA-test-0060", "acme-tiny-parser", "1.1.0", fixed="1.1.1"))
    rid = analyze()
    w = enable(rid)
    env.down.add("osv")
    result = check(w["id"])
    assert result["check"]["status"] == "failed" and result["events"] == []
    assert "OSV unavailable" in result["check"]["summary"] and "not a clean result" in result["check"]["summary"]
    assert result["check"]["provider_issues"][0]["provider"] == "osv"
    after = store.get_watch(w["id"])
    assert after["last_check_status"] == "failed"
    assert after["state"][PARSER]["verdict"] == "UPGRADE"  # Known finding retained
    assert after["latest_report_id"] == rid

    env.down.clear()  # Recovery: nothing changed, so no event
    assert check(w["id"])["events"] == []


def test_kev_outage_is_partial_and_cannot_de_escalate(env):
    env.add(osv_record("GHSA-test-0061", "acme-tiny-parser", "1.1.0", fixed="1.1.1", cves=["CVE-2099-0061"]))
    env.kev.add("CVE-2099-0061")
    w = enable(analyze())
    assert store.get_watch(w["id"])["state"][PARSER]["verdict"] == "ACT_NOW"

    env.down.add("kev")
    result = check(w["id"])
    assert result["check"]["status"] == "partial"
    assert "Monitoring partially completed" in result["check"]["summary"] and "CISA KEV" in result["check"]["summary"]
    assert result["events"] == []  # Engine alone would now say UPGRADE — must not be reported as an improvement
    assert store.get_watch(w["id"])["state"][PARSER]["verdict"] == "ACT_NOW"


def test_partial_check_still_reports_escalations_backed_by_retrieved_evidence(env):
    w = enable(analyze())
    env.down.add("kev")
    env.add(osv_record("GHSA-test-0062", "acme-tiny-parser", "1.1.0", fixed="1.1.1", cves=["CVE-2099-0062"]))
    result = check(w["id"])
    assert result["check"]["status"] == "partial"
    [ev] = result["events"]
    assert ev["current"]["verdict"] == "UPGRADE" and ev["check_status"] == "partial"


def test_osv_record_fetch_failure_is_partial_not_clean(env):
    env.add(osv_record("GHSA-test-0063", "acme-tiny-parser", "1.1.0", fixed="1.1.1"))
    w = enable(analyze())
    env.down.add("osv-detail")
    result = check(w["id"])
    assert result["check"]["status"] == "partial" and result["events"] == []
    assert any("could not be fetched" in i["detail"] for i in result["check"]["provider_issues"])
    assert store.get_watch(w["id"])["state"][PARSER]["verdict"] == "UPGRADE"


def test_registry_outage_is_partial_and_lost_visibility_is_not_an_event(env):
    w = enable(analyze())
    with sqlite3.connect(get_settings().db_path) as conn:
        conn.execute("DELETE FROM api_cache WHERE cache_key LIKE 'npm_registry_%'")
    env.down.add("registry")
    result = check(w["id"])
    assert result["check"]["status"] == "partial" and "npm registry" in result["check"]["summary"]
    assert result["events"] == []
    assert CLIENT in result["check"]["held"]  # Would be CANNOT_ASSESS — previous decision kept, not "clean"


def test_provider_health_collector_is_noop_outside_monitoring():
    report_provider_issue("osv", "ignored")  # No active collector: must not raise or leak
    with collect_provider_issues() as issues:
        report_provider_issue("kev", "down", scope="batch")
    assert [i.provider for i in issues] == ["kev"]


# ─── 10–12. Idempotency: repeated checks, app restart, scheduler restart ──────

def test_same_evidence_checked_repeatedly_creates_one_event(env):
    w = enable(analyze())
    env.add(osv_record("GHSA-test-0070", "acme-tiny-parser", "1.1.0", fixed="1.1.1"))
    assert len(check(w["id"])["events"]) == 1
    for _ in range(3):
        assert check(w["id"])["events"] == []
    assert len(all_events(w["id"])) == 1
    assert len(store.list_checks(w["id"], limit=10)) == 4


def test_event_commit_is_idempotent_under_retry(env):
    w = enable(analyze())
    watch = store.get_watch(w["id"])
    ev = {"id": "e1", "dedupe_key": "same", "subject": PARSER, "priority": "medium", "change_type": "ESCALATION",
          "detected_at": store.ts(NOW)}
    base = {"trigger": "manual", "status": "complete", "started_at": store.ts(NOW), "finished_at": store.ts(NOW),
            "evidence_as_of": store.ts(NOW), "summary": "x", "provider_issues": []}
    ok, inserted = store.commit_check(watch_id=w["id"], expected_revision=watch["revision"], check={**base, "id": "c1"},
                                      events=[ev], new_state=watch["state"], latest_report_id=None,
                                      evidence_as_of=None, next_check_at=None)
    assert ok and inserted == 1
    # Stale revision (e.g. a crashed/concurrent check retried) → nothing written
    ok, inserted = store.commit_check(watch_id=w["id"], expected_revision=watch["revision"], check={**base, "id": "c2"},
                                      events=[{**ev, "id": "e2"}], new_state=watch["state"], latest_report_id=None,
                                      evidence_as_of=None, next_check_at=None)
    assert not ok and inserted == 0
    assert len(all_events(w["id"])) == 1


def test_application_restart_does_not_duplicate_events(env):
    from fastapi.testclient import TestClient
    import app.main

    rid = analyze()
    with TestClient(app.main.app) as client:
        wid = client.post("/api/watch", json={"report_id": rid}).json()["id"]
        env.add(osv_record("GHSA-test-0080", "acme-tiny-parser", "1.1.0", fixed="1.1.1"))
        assert len(client.post(f"/api/watch/{wid}/check").json()["events"]) == 1

    with TestClient(app.main.app) as client:  # Fresh app lifespan: DB re-initialised, state reloaded
        assert client.post(f"/api/watch/{wid}/check").json()["events"] == []
        detail = client.get(f"/api/watch/{wid}").json()
        assert detail["event_count"] == 1 and len(detail["events"]) == 1


def test_scheduler_restart_does_not_duplicate_events(env):
    w = enable(analyze())
    env.add(osv_record("GHSA-test-0090", "acme-tiny-parser", "1.1.0", fixed="1.1.1"))

    def make_due():
        store.set_status(w["id"], "active", store.ts(NOW - timedelta(minutes=1)))

    make_due()
    results = asyncio.run(WatchScheduler(tick_seconds=0).tick())
    assert len(results) == 1 and len(results[0]["events"]) == 1
    assert asyncio.run(WatchScheduler(tick_seconds=0).tick()) == []  # Not due again yet

    make_due()
    results = asyncio.run(WatchScheduler(tick_seconds=0).tick())  # "Restarted" scheduler
    assert results[0]["events"] == [] and len(all_events(w["id"])) == 1


def test_scheduler_runs_checks_automatically_in_app(env, monkeypatch):
    from fastapi.testclient import TestClient
    import app.main

    settings = get_settings()
    monkeypatch.setattr(settings, "watch_scheduler_enabled", True)
    monkeypatch.setattr(settings, "watch_tick_seconds", 0.05)
    rid = analyze()
    w = enable(rid)
    env.add(osv_record("GHSA-test-0095", "acme-tiny-parser", "1.1.0", fixed="1.1.1"))
    store.set_status(w["id"], "active", store.ts(NOW - timedelta(seconds=1)))
    with TestClient(app.main.app) as client:
        deadline = time.time() + 10
        while time.time() < deadline and not all_events(w["id"]):
            time.sleep(0.05)
        alerts = client.get("/api/watch/alerts").json()
    assert len(all_events(w["id"])) == 1
    assert alerts["unacknowledged"] == 1 and alerts["events"][0]["subject"] == PARSER
    assert store.list_checks(w["id"])[-1]["trigger"] == "scheduled"


# ─── 13. Temporal / as-of correctness ─────────────────────────────────────────

def test_original_analysis_is_unchanged_and_reproducible(env):
    rid = analyze()
    original = load_report(rid)
    w = enable(rid)
    env.add(osv_record("GHSA-test-0100", "acme-tiny-parser", "1.1.0", fixed="1.1.1"))
    [ev] = check(w["id"])["events"]
    assert load_report(rid) == original  # Historical analysis untouched
    new = load_report(ev["report_id"])
    assert new["summary"]["as_of"] > original["summary"]["as_of"]
    assert ev["evidence_as_of"] >= store.ts(datetime.fromisoformat(str(original["summary"]["as_of"])))


def test_event_keeps_publication_observation_detection_and_asof_times_distinct(env):
    published = NOW - timedelta(days=3)
    w = enable(analyze())
    env.add(osv_record("GHSA-test-0101", "acme-tiny-parser", "1.1.0", fixed="1.1.1", published=published))
    [ev] = check(w["id"])["events"]
    [evidence] = ev["changed_evidence"]
    assert datetime.fromisoformat(evidence["published_at"]) == published
    assert datetime.fromisoformat(evidence["observed_at"]) > published
    assert ev["detected_at"] and ev["evidence_as_of"] and ev["report_generated_at"]
    assert ev["detected_at"] >= ev["evidence_as_of"]


def test_future_evidence_never_leaks_into_historical_replay(env):
    clock = datetime(2026, 1, 1, tzinfo=timezone.utc)
    rec = osv_record("MAL-2099-0102", "acme-tiny-parser", "1.1.0", fixed=None, malware=True,
                     published=clock + timedelta(hours=2), withdrawn=clock + timedelta(days=5))
    feed = replay_mod.RecordedFeed(osv_records=[rec], osv_matches={PARSER: [rec["id"]]}, kev={"vulnerabilities": []},
                                   epss={"scores": {}})
    parse = parse_npm_lock(LOCKFILE)
    at = lambda t: asyncio.run(analyze_npm_lock("r", parse, "p", {}, as_of=t, providers=feed.providers(t))).report
    before = at(clock)
    assert PARSER not in {d.subject for d in before.decisions if d.verdict.value == "INCIDENT"}
    assert not [e for e in before.evidence if e.source == "osv"]
    during = at(clock + timedelta(hours=3))
    assert {d.subject: d.verdict.value for d in during.decisions}[PARSER] == "INCIDENT"
    assert not any(e.withdrawn for e in during.evidence)  # Withdrawal lies in the future of this clock
    after = at(clock + timedelta(days=6))
    assert any(e.withdrawn for e in after.evidence if e.source == "osv")
    assert PARSER not in {d.subject for d in after.decisions if d.verdict.value == "INCIDENT"}
    assert feed.change_times(clock) == [clock + timedelta(hours=2), clock + timedelta(days=5)]


# ─── 14 & 15. Event content and access to the updated analysis ────────────────

def test_event_contains_complete_evidence_and_engine_response(env):
    w = enable(analyze())
    env.add(osv_record("GHSA-test-0110", "acme-tiny-parser", "1.1.0", fixed="1.1.1", cves=["CVE-2099-0110"]))
    [ev] = check(w["id"])["events"]
    for key in ("project", "subject", "package", "version", "previous", "current", "changed_evidence",
                "evidence_sources", "detected_at", "reason", "exposure", "response", "report_id",
                "previous_report_id", "priority", "change_type"):
        assert ev[key] not in (None, "", []), key
    assert ev["title"] == "SECURITY CHANGE DETECTED" and ev["project"] == "watch-test-app"
    assert ev["evidence_sources"] == ["osv"]
    [e] = ev["changed_evidence"]
    assert e["id"] == "GHSA-test-0110" and e["source"] == "osv" and e["url"].endswith("GHSA-test-0110")
    new_report = load_report(ev["report_id"])
    assert e["evidence_id"] in {x["id"] for x in new_report["evidence"]}
    assert ["watch-test-app", "acme-http-client@2.3.0", "acme-tiny-parser@1.1.0"] in ev["exposure"]["paths"]
    assert ev["exposure"]["scope"] == "prod"
    assert ev["response"]["class"] == "upgrade" and ev["response"]["fixed_version"] == "1.1.1"
    assert any(s.get("command") for s in ev["response"]["steps"])  # Existing remediation commands
    assert "GHSA-test-0110" in ev["reason"] and "NO KNOWN FINDING → UPGRADE" in ev["reason"]
    assert ev["simulated"] is False and ev["label"] is None


def test_user_can_open_updated_analysis_and_it_is_retained(env):
    from fastapi.testclient import TestClient
    import app.main

    other = analyze()  # Not monitored → normal 24 h retention
    rid = analyze()
    w = enable(rid)
    env.add(osv_record("GHSA-test-0120", "acme-tiny-parser", "1.1.0", fixed="1.1.1"))
    [ev] = check(w["id"])["events"]
    with sqlite3.connect(get_settings().db_path) as conn:  # Age every report past the TTL
        conn.execute("UPDATE reports SET created_at = ?", (time.time() - cache_mod.TTL_REPORT - 60,))
    with TestClient(app.main.app) as client:
        updated = client.get(f"/api/reports/{ev['report_id']}")
        assert updated.status_code == 200
        assert decisions(updated.json())[PARSER]["verdict"] == "UPGRADE"
        assert client.get(f"/api/reports/{rid}").status_code == 200       # Baseline kept
        assert client.get(f"/api/reports/{other}").status_code == 404     # Unmonitored expires as before
        assert client.get(f"/api/watch/by-report/{ev['report_id']}").json()["watch"]["id"] == w["id"]
        ack = client.post(f"/api/watch/{w['id']}/events/ack", json={}).json()
        assert ack["acknowledged"] == 1 and client.get("/api/watch/alerts").json()["unacknowledged"] == 0


# ─── 16. Pause / disable / resume ─────────────────────────────────────────────

def test_pause_disable_resume_lifecycle(env):
    from fastapi.testclient import TestClient
    import app.main

    rid = analyze()
    with TestClient(app.main.app) as client:
        wid = client.post("/api/watch", json={"report_id": rid}).json()["id"]
        paused = client.post(f"/api/watch/{wid}/pause").json()
        assert paused["status"] == "paused" and paused["next_check_at"] is None
        assert client.post(f"/api/watch/{wid}/check").status_code == 409

        store.set_status(wid, "paused", store.ts(NOW - timedelta(minutes=1)))  # Even if a due time lingers…
        assert asyncio.run(WatchScheduler(tick_seconds=0).tick()) == []          # …the scheduler skips it

        disabled = client.post(f"/api/watch/{wid}/disable").json()
        assert disabled["status"] == "disabled" and disabled["next_check_at"] is None
        assert client.post(f"/api/watch/{wid}/check").status_code == 409
        env.add(osv_record("GHSA-test-0130", "acme-tiny-parser", "1.1.0", fixed="1.1.1"))
        assert asyncio.run(WatchScheduler(tick_seconds=0).tick()) == []
        assert all_events(wid) == []

        resumed = client.post(f"/api/watch/{wid}/resume").json()
        assert resumed["status"] == "active" and resumed["next_check_at"] is not None
        [result] = asyncio.run(WatchScheduler(tick_seconds=0).tick())  # Due immediately after resume
        assert len(result["events"]) == 1
        # History survives pause/disable and enabling again just resumes the same watch
        assert client.post("/api/watch", json={"report_id": rid}).json()["id"] == wid


# ─── 17. Existing analysis unchanged ──────────────────────────────────────────

def _comparable(report: dict) -> dict:
    out = json.loads(json.dumps(report, default=str))
    for key in ("id", "created_at"):
        out.pop(key, None)
    out["summary"].pop("as_of", None)
    for d in out["decisions"]:
        d.pop("as_of", None)
    for e in out["evidence"]:
        e.pop("retrieved_at", None)
    return out


def test_analysis_is_identical_with_monitoring_disabled(env, monkeypatch):
    from fastapi.testclient import TestClient
    import app.main

    env.add(osv_record("GHSA-test-0140", "acme-tiny-parser", "1.1.0", fixed="1.1.1", cves=["CVE-2099-0140"]))
    with_watch = analyze()
    monkeypatch.setattr(get_settings(), "watch_enabled", False)
    without_watch = analyze()
    assert load_snapshot(with_watch) is not None and load_snapshot(without_watch) is None
    assert _comparable(load_report(with_watch)) == _comparable(load_report(without_watch))
    with TestClient(app.main.app) as client:
        assert client.get("/api/watch").status_code == 404
        assert client.get(f"/api/reports/{without_watch}").status_code == 200


@pytest.mark.parametrize("sample", ["slack-action", "legacy-express", "axios-replay"])
def test_snapshot_round_trip_rebuilds_identical_graph_and_decisions(sample):
    content = (SAMPLES / sample / "package-lock.json").read_text(encoding="utf-8")
    original = parse_npm_lock(content)
    restored = parse_from_snapshot(json.loads(json.dumps(snapshot_from_parse(original, "package-lock.json", {}))))
    a, b = build_graph(original), build_graph(restored)
    edges = lambda g: sorted((u, v, tuple(sorted(d.items()))) for u, v, d in g.graph.edges(data=True))
    assert edges(a) == edges(b) and a.cycles_detected == b.cycles_detected
    strip = lambda p: {k: v for k, v in vars(p).items() if k != "resolved_url" or p.is_git_or_file}
    assert {k: strip(v) for k, v in a.packages.items()} == {k: strip(v) for k, v in b.packages.items()}
    when = datetime(2026, 1, 1, tzinfo=timezone.utc)
    da = [d.model_dump() for d in derive_decisions(a, [], AnalysisContext(), as_of=when)]
    db = [d.model_dump() for d in derive_decisions(b, [], AnalysisContext(), as_of=when)]
    assert da == db


# ─── 18. Demo / replay ────────────────────────────────────────────────────────

def _run_replay(scenario_id: str) -> list[tuple]:
    w = asyncio.run(monitor.create_replay_demo(scenario_id))
    timeline = []
    assert check(w["id"])["events"] == []
    while True:
        try:
            adv = asyncio.run(monitor.advance_replay(w["id"]))
        except monitor.WatchConflict:
            break
        result = check(w["id"])
        timeline.append((adv["clock"], tuple(sorted(
            (e["subject"], e["previous"]["verdict"], e["current"]["verdict"], e["change_type"], e["priority"],
             tuple(sorted(x["id"] for x in e["changed_evidence"])), e["simulated"], e["label"])
            for e in result["events"]))))
        assert check(w["id"])["events"] == []  # Re-checking the same simulated moment is idempotent
    return timeline


def test_replay_real_project_axios_advisory_is_deterministic(env):
    first = _run_replay("slack-action-axios-2026-04")
    second = _run_replay("slack-action-axios-2026-04")
    assert first == second and len(first) == 3
    clock1, events1 = first[0]
    assert clock1.startswith("2026-04-09T17:32:19")
    [(subject, prev, cur, kind, _, evidence, simulated, label)] = events1
    assert (subject, prev, cur, kind) == ("pkg:npm/axios@1.14.0", "NO_KNOWN_FINDING", "UPGRADE", "ESCALATION")
    assert evidence == ("GHSA-3p68-rc4w-qgx5",) and simulated is True
    assert label == "DEMO / REPLAY / SIMULATED EVENT"
    assert first[1][1] == ()  # Second axios advisory: same decision → no alert
    assert env.calls == []    # Replay never touches the network


def test_replay_malware_incident_scenario(env):
    timeline = _run_replay("axios-compromise-2026-03-31")
    assert [t for t, _ in timeline][0].startswith("2026-03-31T03:10:11")  # OSV import time, not publication
    step1 = {e[0]: e for e in timeline[0][1]}
    assert step1["pkg:npm/plain-crypto-js@4.2.1"][2] == "INCIDENT" and step1["pkg:npm/plain-crypto-js@4.2.1"][4] == "high"
    assert step1["pkg:npm/axios@1.14.1"][2] == "INCIDENT"  # Carried via R1'
    [(subject, prev, cur, kind, *_)] = timeline[1][1]
    assert (subject, prev, cur, kind) == ("pkg:npm/axios@1.14.1", "INCIDENT", "INCIDENT", "EVIDENCE_CHANGE")


def test_replay_reports_are_labelled_simulated(env):
    w = asyncio.run(monitor.create_replay_demo("axios-compromise-2026-03-31"))
    base = load_report(w["baseline_report_id"])
    assert base["summary"]["data_badge"] == "REPLAY" and base["meta"]["replay"]["label"] == "DEMO / REPLAY / SIMULATED EVENT"
    assert base["coverage"][0]["status"] == "Replay"
    asyncio.run(monitor.advance_replay(w["id"]))
    [ev, *_] = check(w["id"])["events"]
    updated = load_report(ev["report_id"])
    assert updated["meta"]["watch"]["simulated"] is True and updated["meta"]["replay"]["simulated_clock"].startswith("2026-03-31T03:10")
    assert updated["summary"]["as_of"].startswith("2026-03-31 03:10:11")


def test_replay_scenario_integrity_is_verified(tmp_path, monkeypatch):
    src = replay_mod.REPLAY_DIR / "axios-compromise-2026-03-31"
    dst = tmp_path / "watch_replay" / "tampered-scenario"
    shutil.copytree(src, dst)
    manifest = json.loads((dst / "scenario.json").read_text(encoding="utf-8"))
    manifest["id"] = "tampered-scenario"
    (dst / "scenario.json").write_text(json.dumps(manifest), encoding="utf-8")
    rec_path = dst / "osv" / "MAL-2026-2307.json"
    rec = json.loads(rec_path.read_text(encoding="utf-8"))
    rec["affected"][0]["versions"].append("1.14.0")  # Fabricated claim
    rec_path.write_text(json.dumps(rec), encoding="utf-8")
    monkeypatch.setattr(replay_mod, "REPLAY_DIR", tmp_path / "watch_replay")
    replay_mod.load_scenario.cache_clear()
    try:
        with pytest.raises(ValueError, match="integrity"):
            replay_mod.load_scenario("tampered-scenario")
    finally:
        replay_mod.load_scenario.cache_clear()


# ─── Comparison unit tests ────────────────────────────────────────────────────

def _pkg(verdict: str, urgency: str = "SCHEDULED", evidence: dict | None = None, **kw) -> dict:
    p = empty_package(PARSER, "acme-tiny-parser", "1.1.0")
    p.update({"verdict": verdict, "urgency": urgency, "response": kw.pop("response", "upgrade"),
              "derivation": kw.pop("derivation", ["R3 ← E0001"]), "evidence": evidence or {}, **kw})
    return p


def _adv(vid: str, withdrawn: bool = False) -> dict:
    return {f"osv:{vid}": {"facts": {"source": "osv", "tier": "T2", "kind": "advisory", "withdrawn": withdrawn,
                                     "vuln_id": vid, "is_malware": False, "fixed_version": "1.1.1",
                                     "cvss_vector": None, "cve_aliases": []},
                           "meta": {"evidence_id": "E0001"}}}


def test_compare_partial_check_never_de_escalates():
    old = {PARSER: _pkg("UPGRADE", evidence=_adv("GHSA-a"))}
    result = compare_states(old, {}, complete=False)
    assert result.changes == [] and result.next_state == old and result.held == [PARSER]
    result = compare_states(old, {}, complete=True)
    assert [c.change_type for c in result.changes] == ["DE_ESCALATION"] and result.next_state == {}


def test_compare_lost_visibility_during_outage_is_neither_alert_nor_clean():
    old = {PARSER: _pkg("UPGRADE", evidence=_adv("GHSA-a"))}
    new = {PARSER: _pkg("CANNOT_ASSESS", urgency="NONE", response="cannot_assess", derivation=["R6 — x"])}
    result = compare_states(old, new, complete=False)
    assert result.changes == [] and result.next_state == old and result.held == [PARSER]
    # With every provider answering, the same transition is a real re-assessment and is surfaced
    result = compare_states(old, new, complete=True)
    assert [c.change_type for c in result.changes] == ["DE_ESCALATION"] and result.next_state == new


def test_compare_ignores_positional_evidence_ids_and_observation_times():
    a = _pkg("UPGRADE", evidence=_adv("GHSA-a"), derivation=["R3 ← E0001"])
    b = _pkg("UPGRADE", evidence=_adv("GHSA-a"), derivation=["R3 ← E0007"])
    b["evidence"]["osv:GHSA-a"]["meta"] = {"evidence_id": "E0007", "observed_at": "later"}
    assert compare_states({PARSER: a}, {PARSER: b}, complete=True).changes == []


def test_state_from_report_reads_existing_engine_output(env):
    env.add(osv_record("GHSA-test-0150", "acme-tiny-parser", "1.1.0", fixed="1.1.1"))
    state = state_from_report(load_report(analyze()))
    assert state[PARSER]["verdict"] == "UPGRADE" and "osv:GHSA-test-0150" in state[PARSER]["evidence"]
    assert CLIENT not in state and DEVRUN not in state


def test_new_advisory_without_fix_is_surfaced_even_when_engine_cannot_assess(env):
    w = enable(analyze())
    env.add(osv_record("GHSA-test-0160", "acme-tiny-parser", "1.1.0", fixed=None))  # No fixed version published
    [ev] = check(w["id"])["events"]
    # Existing engine: advisory on a prod path without a fix → R6 CANNOT ASSESS (not "clean")
    assert ev["previous"]["verdict"] == "NO_KNOWN_FINDING" and ev["current"]["verdict"] == "CANNOT_ASSESS"
    assert ev["change_type"] == "EVIDENCE_CHANGE" and ev["priority"] == "low"
    assert ev["changed_evidence"][0]["id"] == "GHSA-test-0160"
    assert check(w["id"])["events"] == []
