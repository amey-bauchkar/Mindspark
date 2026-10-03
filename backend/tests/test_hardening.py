"""
Regression tests for the hardening pass: decision-engine edge cases, temporal correctness,
graph resolution and paths, provider failure honesty, report API resilience.

Provider tests run the real provider code against the offline FakeInternet from test_watch.
"""
from __future__ import annotations

import asyncio
import json
import random
import sqlite3
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import networkx as nx
import pytest

from app.config import get_settings
from app.engine.decide import active_evidence, derive_decisions
from app.graph.build import (
    ROOT_ID, build_from_report_graph, build_graph, find_paths, node_paths, _break_cycles_fast,
)
from app.jobs import analyze_npm_lock, decisions_for_requirements, run_analysis
from app.models.evidence import EvidenceKind, EvidenceRecord, EvidenceTier
from app.models.report import AnalysisContext
from app.parsers.npm_lock import parse_npm_lock
from app.parsers.requirements_txt import parse_requirements_txt
from app.providers import npm_registry as npm_mod
from app.providers.cache import load_report, save_report
from app.providers.epss import build_epss_kev_records, fetch_kev
from app.providers.health import collect_provider_issues
from app.providers.osv import build_osv_evidence, fetch_osv_batch
from app.providers.versions import select_fixed_version, version_key
from app.security import _SlidingWindowBucket
from app.signals.lookalike import _edit_distance_capped, check_lookalike, popular_count
from app.watch import monitor, store

from tests.test_watch import CLIENT, LOCKFILE, NOW, PARSER, FakeInternet, analyze, env, enable, osv_record  # noqa: F401

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def ev(subject, vid="GHSA-x", tier=EvidenceTier.T2, kind=EvidenceKind.ADVISORY, published=None, **data):
    withdrawn = data.pop("withdrawn", False)
    return EvidenceRecord(
        id=data.pop("eid", "E0001"), tier=tier, source="osv", origin="GHSA", kind=kind, subject=subject,
        claim=f"Vulnerability: {vid}", retrieved_at=NOW, published_at=published or NOW - timedelta(days=1),
        withdrawn=withdrawn, data={"vuln_id": vid, "cve_aliases": [], "is_malware": vid.startswith("MAL-"), **data},
    )


def lock(packages: dict, root_deps: dict | None = None) -> str:
    return json.dumps({"name": "t", "version": "1.0.0", "lockfileVersion": 3, "packages": {
        "": {"name": "t", "version": "1.0.0", "dependencies": root_deps or {}}, **packages}})


def build_of(packages: dict, root_deps: dict | None = None):
    return build_graph(parse_npm_lock(lock(packages, root_deps)))


SIMPLE = {"node_modules/a": {"version": "1.0.0", "license": "MIT", "dependencies": {"b": "1"}},
          "node_modules/b": {"version": "1.0.0", "license": "MIT"}}
A, B = "pkg:npm/a@1.0.0", "pkg:npm/b@1.0.0"


def verdicts(decisions) -> dict[str, str]:
    return {d.subject: d.verdict.value for d in decisions}


# ─── Decision engine ──────────────────────────────────────────────────────────

def test_prod_advisory_without_fix_is_never_no_known_finding():
    build = build_of(SIMPLE, {"a": "1"})
    for cves, epss in ((["CVE-2099-1"], {"CVE-2099-1": 0.01}), ([], {})):
        advisory = ev(B, fixed_version=None, cve_aliases=cves)
        evidence = [advisory] + build_epss_kev_records([advisory], epss, set(), 0.1)
        d = {x.subject: x for x in derive_decisions(build, evidence, AnalysisContext(), as_of=NOW)}
        assert d[B].verdict.value == "CANNOT_ASSESS", cves  # Before: NO_KNOWN_FINDING when a CVE had an EPSS score
        assert "without a published fix" in d[B].what and d[B].derivation[0].startswith("R6")


def test_withdrawn_advisory_cannot_drive_verdict_through_derived_kev():
    build = build_of(SIMPLE, {"a": "1"})
    advisory = ev(B, fixed_version="2.0.0", cve_aliases=["CVE-2099-2"], withdrawn=True)
    evidence = [advisory] + build_epss_kev_records([advisory], {}, {"CVE-2099-2"}, 0.1)
    assert verdicts(derive_decisions(build, evidence, AnalysisContext(), as_of=NOW)).get(B) is None


def test_withdrawal_after_as_of_is_still_active_then():
    build = build_of(SIMPLE, {"a": "1"})
    withdrawn_at = NOW - timedelta(hours=1)
    mal = ev(B, "MAL-2099-1", tier=EvidenceTier.T2, withdrawn=True, withdrawn_at=withdrawn_at.isoformat(),
             published=NOW - timedelta(days=2))
    before = verdicts(derive_decisions(build, [mal], AnalysisContext(), as_of=NOW - timedelta(days=1)))
    assert before[B] == "INCIDENT" and before[A] == "INCIDENT"  # Malware report was live then (R1 + R1')
    assert verdicts(derive_decisions(build, [mal], AnalysisContext(), as_of=NOW)).get(B) is None


def test_evidence_derived_from_future_advisory_is_excluded():
    advisory = ev(B, fixed_version="2.0.0", cve_aliases=["CVE-2099-3"], published=NOW)
    evidence = [advisory] + build_epss_kev_records([advisory], {"CVE-2099-3": 0.9}, {"CVE-2099-3"}, 0.1)
    assert active_evidence(evidence, NOW - timedelta(days=1)) == []
    assert len(active_evidence(evidence, NOW)) == len(evidence)


def test_placeholder_and_git_sources_never_carry_an_incident_to_ancestors():
    for version, extra in (("0.0.1-security", {}), ("1.0.0", {"resolved": "git+https://example.invalid/b.git"})):
        build = build_of({"node_modules/a": {"version": "1.0.0", "dependencies": {"b": "1"}},
                          "node_modules/b": {"version": version, **extra}}, {"a": "1"})
        b = f"pkg:npm/b@{version}"
        result = verdicts(derive_decisions(build, [ev(b, "MAL-2099-2", tier=EvidenceTier.T1,
                                                      kind=EvidenceKind.MALWARE_REPORT)], AnalysisContext(), as_of=NOW))
        assert result[b] in ("REVIEW", "CANNOT_ASSESS")
        assert result.get(A) != "INCIDENT", version


def test_decisions_are_deterministic_and_carry_reason_sorted():
    packages = {"node_modules/a": {"version": "1.0.0", "dependencies": {"x": "1", "y": "1"}},
                "node_modules/x": {"version": "1.0.0"}, "node_modules/y": {"version": "1.0.0"}}
    evidence = [ev("pkg:npm/y@1.0.0", "MAL-2099-3", tier=EvidenceTier.T1, kind=EvidenceKind.MALWARE_REPORT, eid="E1"),
                ev("pkg:npm/x@1.0.0", "MAL-2099-4", tier=EvidenceTier.T1, kind=EvidenceKind.MALWARE_REPORT, eid="E2")]
    runs = [[d.model_dump() for d in derive_decisions(build_of(packages, {"a": "1"}), evidence, AnalysisContext(),
                                                      as_of=NOW)] for _ in range(3)]
    assert runs[0] == runs[1] == runs[2]
    carry = next(d for d in runs[0] if d["subject"] == A)["carry_reason"]
    assert carry == "Carries incident via path to pkg:npm/x@1.0.0, pkg:npm/y@1.0.0"


# ─── Graph ────────────────────────────────────────────────────────────────────

def test_dependency_resolves_to_its_own_nested_copy_first():
    parse = parse_npm_lock(lock({
        "node_modules/a": {"version": "1.0.0", "dependencies": {"b": "1"}},
        "node_modules/a/node_modules/b": {"version": "1.0.0"},
        "node_modules/b": {"version": "2.0.0"},
        "node_modules/c": {"version": "1.0.0", "dependencies": {"b": "2"}},
    }, {"a": "1", "b": "2", "c": "1"}))
    assert parse.packages[A].__dict__["resolved_edges"] == {"b": "pkg:npm/b@1.0.0"}
    assert parse.packages["pkg:npm/c@1.0.0"].__dict__["resolved_edges"] == {"b": "pkg:npm/b@2.0.0"}
    build = build_graph(parse)
    assert find_paths(build.graph, ROOT_ID, "pkg:npm/b@1.0.0") == [[ROOT_ID, A, "pkg:npm/b@1.0.0"]]


def _random_dag(seed: int, n: int = 40, p: float = 0.12) -> nx.DiGraph:
    rnd = random.Random(seed)
    G = nx.DiGraph()
    G.add_node(ROOT_ID)
    nodes = [f"n{i:02d}" for i in range(n)]
    G.add_nodes_from(nodes)
    for i, u in enumerate(nodes):
        if rnd.random() < 0.15:
            G.add_edge(ROOT_ID, u)
        for v in nodes[i + 1:]:
            if rnd.random() < p:
                G.add_edge(u, v)
    return G


@pytest.mark.parametrize("seed", range(8))
def test_find_paths_matches_k_shortest_simple_paths(seed):
    G = _random_dag(seed)
    for target in [n for n in G if n != ROOT_ID]:
        ours = find_paths(G, ROOT_ID, target)
        if not nx.has_path(G, ROOT_ID, target):
            assert ours == []
            continue
        reference = []
        for path in nx.shortest_simple_paths(G, ROOT_ID, target):
            reference.append(path)
            if len(reference) == 10:
                break
        assert [len(p) for p in ours] == [len(p) for p in reference]  # Same lengths, shortest first
        if len(reference) < 10:
            assert sorted(map(tuple, ours)) == sorted(map(tuple, reference))  # All paths found
        assert all(nx.is_simple_path(G, p) and p[0] == ROOT_ID and p[-1] == target for p in ours)
        # Deterministic regardless of edge insertion order
        H = nx.DiGraph()
        H.add_nodes_from(reversed(list(G.nodes)))
        H.add_edges_from(reversed(list(G.edges)))
        assert find_paths(H, ROOT_ID, target) == ours


def test_find_paths_handles_cycles_cutoff_and_memoisation():
    G = nx.DiGraph([(ROOT_ID, "a"), ("a", "b"), ("b", "a"), ("b", "c"), ("c", "a")])
    assert find_paths(G, ROOT_ID, "c") == [[ROOT_ID, "a", "b", "c"]]
    chain = nx.DiGraph([(ROOT_ID, "x0")] + [(f"x{i}", f"x{i + 1}") for i in range(60)])
    assert find_paths(chain, ROOT_ID, "x55") == []  # Longer than MAX_PATH_DEPTH edges
    build = build_of(SIMPLE, {"a": "1"})
    assert node_paths(build, B, 3) == find_paths(build.graph, ROOT_ID, B, max_paths=3)


def test_cycle_cap_is_reported_not_silent():
    G = nx.DiGraph()
    for i in range(5):
        G.add_edges_from([(f"p{i}", f"q{i}"), (f"q{i}", f"p{i}")])
    detected, warnings = _break_cycles_fast(G, max_iterations=2)
    assert detected and any("left in place" in w for w in warnings)


def test_rebuilt_report_graph_gives_identical_decisions():
    content = (FIXTURES / "samples" / "slack-action" / "package-lock.json").read_text(encoding="utf-8")
    original = build_graph(parse_npm_lock(content))
    from app.jobs import _build_graph_output
    rebuilt = build_from_report_graph(_build_graph_output(original, []), original.root_name)
    evidence = [ev("pkg:npm/axios@1.14.0", fixed_version="1.15.0")]
    a = [d.model_dump() for d in derive_decisions(original, evidence, AnalysisContext(), as_of=NOW)]
    b = [d.model_dump() for d in derive_decisions(rebuilt, evidence, AnalysisContext(), as_of=NOW)]
    for x, y in zip(a, b):
        x["exposure"].pop("scope_provenance"), y["exposure"].pop("scope_provenance")
    assert a == b


# ─── Versions and OSV evidence ────────────────────────────────────────────────

def test_fixed_version_comes_from_the_range_containing_the_installed_version():
    rec = json.loads((FIXTURES / "watch_replay" / "slack-action-axios-2026-04" / "osv" / "GHSA-3p68-rc4w-qgx5.json")
                     .read_text(encoding="utf-8"))
    assert select_fixed_version(rec, "axios", "1.14.0", "npm") == "1.15.0"  # Was 0.31.0 (a downgrade)
    assert select_fixed_version(rec, "axios", "0.30.0", "npm") == "0.31.0"
    assert select_fixed_version(rec, "axios", "1.15.0", "npm") is None     # Never a downgrade
    assert select_fixed_version(rec, "other-pkg", "1.14.0", "npm") is None
    [e] = build_osv_evidence({"pkg:npm/axios@1.14.0": [rec["id"]]}, {rec["id"]: rec}, NOW)
    assert e.data["fixed_version"] == "1.15.0"


def test_version_ordering_and_regex_safety():
    assert version_key("1.2.3-alpha") < version_key("1.2.3-beta.1") < version_key("1.2.3-beta.2") < version_key("1.2.3")
    assert version_key("0") < version_key("0.0.1") < version_key("2.0.0rc1") < version_key("2.0.0")
    assert version_key("not a version") is None and version_key("1" * 100) is None
    t = time.perf_counter()
    for probe in ("1" + "a" * 60 + "!", "1.2.3-" + "a-" * 30 + "!", "1." + "1." * 30 + "x"):
        version_key(probe)
    assert time.perf_counter() - t < 0.05


def test_osv_records_are_validated_and_sanitised():
    good = {"id": "GHSA-aaaa", "published": "2026-01-01T00:00:00", "withdrawn": "2026-02-01T00:00:00Z",
            "summary": "Bad‮​text", "aliases": ["CVE-2099-9", 5],
            "references": [{"type": "ADVISORY", "url": "javascript:alert(1)"}, {"url": "https://example.org/a"}],
            "affected": [{"package": {"name": "a"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.1"}]}]}]}
    records = build_osv_evidence({A: ["GHSA-aaaa", "GHSA-missing", "GHSA-broken"]},
                                 {"GHSA-aaaa": good, "GHSA-broken": {"id": "GHSA-broken", "severity": "x", "affected": 7}}, NOW)
    by_claim = {r.claim: r for r in records}
    rec = next(r for r in records if r.data.get("vuln_id") == "GHSA-aaaa")
    assert rec.url == "https://example.org/a" and rec.quote == "Badtext" and rec.data["cve_aliases"] == ["CVE-2099-9"]
    assert rec.published_at.tzinfo is not None and rec.data["withdrawn_at"] == "2026-02-01T00:00:00Z"
    absent = [r for r in records if r.tier == EvidenceTier.ABSENT]
    assert len(absent) == 2 and any("GHSA-missing" in c for c in by_claim) and any("GHSA-broken" in c for c in by_claim)


def test_osv_short_or_malformed_batch_responses_are_never_clean(env):
    real = env.handler

    def short(request):
        if request.url.path == "/v1/querybatch":
            return httpx.Response(200, json={"results": [{}]})  # Fewer results than queries
        return real(request)

    env.handler = short
    with collect_provider_issues() as issues:
        records = asyncio.run(fetch_osv_batch([A, B]))
    assert {r.subject for r in records if r.tier == EvidenceTier.ABSENT} == {A, B}
    assert issues and issues[0].scope == "batch"

    def bad_id(request):
        if request.url.path == "/v1/querybatch":
            return httpx.Response(200, json={"results": [{"vulns": [{"id": "../../etc"}]}, {}]})
        return real(request)

    env.handler = bad_id
    records = asyncio.run(fetch_osv_batch([A, B]))
    assert [r.subject for r in records if r.tier == EvidenceTier.ABSENT] == [A]
    assert not any(c.startswith("GET api.osv.dev/v1/vulns/..") for c in env.calls)


def test_osv_permanent_errors_are_not_retried(env, monkeypatch):
    monkeypatch.setattr("app.providers.osv.MAX_RETRIES", 3)
    env.add(osv_record("GHSA-test-0900", "acme-tiny-parser", "1.1.0"))
    real, detail_calls = env.handler, []

    def handler(r):
        if r.url.path.startswith("/v1/vulns/"):
            detail_calls.append(r.url.path)
            return httpx.Response(404)
        return real(r)

    env.handler = handler
    t = time.perf_counter()
    records = asyncio.run(fetch_osv_batch([PARSER]))
    assert time.perf_counter() - t < 1.0  # No backoff sleeps on a 404
    assert len(detail_calls) == 1
    assert records[0].tier == EvidenceTier.ABSENT


def test_offline_fixture_mode_does_not_go_live_or_claim_a_clean_result(env, monkeypatch):
    monkeypatch.setattr(get_settings(), "offline_fixtures", True)
    with collect_provider_issues() as issues:
        records = asyncio.run(fetch_osv_batch([A]))
        kev = asyncio.run(fetch_kev())
    assert env.calls == []
    assert records[0].tier == EvidenceTier.ABSENT and kev is None
    assert {i.provider for i in issues} == {"osv", "kev"}


def test_kev_outage_is_recorded_per_cve_and_in_coverage(env):
    env.down.add("kev")
    assert asyncio.run(fetch_kev()) is None
    advisory = ev(B, fixed_version="2.0.0", cve_aliases=["CVE-2099-5"])
    derived = build_epss_kev_records([advisory], {}, None, 0.1)
    kev_miss = [r for r in derived if r.id.startswith("KEV-MISS")]
    assert len(kev_miss) == 1 and kev_miss[0].tier == EvidenceTier.ABSENT and kev_miss[0].data["derived_from"] == "GHSA-x"
    from app.jobs import _security_coverage
    rows = {c.check: c for c in _security_coverage([advisory], derived, 2)}
    assert rows["CISA Known Exploited Vulnerabilities"].status == "Not run"
    d = {x.subject: x for x in derive_decisions(build_of(SIMPLE, {"a": "1"}), [advisory] + derived,
                                                  AnalysisContext(), as_of=NOW)}
    assert d[B].verdict.value == "UPGRADE" and any("CISA KEV unavailable" in u for u in d[B].unrun_checks)


def test_coverage_reports_failures_and_real_list_size():
    from app.jobs import _security_coverage
    failed = [EvidenceRecord(id="X", tier=EvidenceTier.ABSENT, source="osv", origin="OSV API", kind=EvidenceKind.OTHER,
                             subject=A, claim="OSV API unavailable", retrieved_at=NOW)]
    rows = {c.check: c for c in _security_coverage(failed, [], 1)}
    assert rows["Vulnerability lookup (OSV)"].status == "Not run"
    assert rows["Malware reports (OSV MAL-*)"].status == "Not run"  # Was always "Ran"
    withdrawn = ev(B, withdrawn=True)
    rows = {c.check: c for c in _security_coverage([withdrawn], [], 2)}
    assert "0 active" in rows["Vulnerability lookup (OSV)"].reason and "1 withdrawn" in rows["Vulnerability lookup (OSV)"].reason
    assert 0 < popular_count() < 1000


def test_registry_host_check_is_cached_and_failure_reported(env, monkeypatch):
    calls = []
    monkeypatch.setattr(npm_mod, "verify_safe_outbound_ip", lambda host: calls.append(host) or True)
    npm_mod._host_check.clear()
    asyncio.run(npm_mod.bulk_fetch_npm_times([("acme-http-client", "2.3.0"), ("acme-dev-runner", "0.9.0")]))
    assert calls == ["registry.npmjs.org"]
    monkeypatch.setattr(npm_mod, "verify_safe_outbound_ip", lambda host: False)
    npm_mod._host_check.clear()
    with sqlite3.connect(get_settings().db_path) as conn:
        conn.execute("DELETE FROM api_cache")
    with collect_provider_issues() as issues:
        assert asyncio.run(npm_mod.fetch_npm_times("acme-http-client")) is None
    assert issues and issues[0].provider == "npm-registry"


def _reference_levenshtein(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] != b[j - 1]))
        prev = cur
    return prev[-1]


def test_capped_edit_distance_matches_levenshtein():
    rnd = random.Random(3)
    words = ["express", "lodash", "react", "ms", "", "a", "axios", "chalk", "debug"]
    for _ in range(3000):
        w = rnd.choice(words)
        x = "".join(rnd.choice("abcdeslx-") for _ in range(rnd.randrange(0, 9))) if rnd.random() < 0.3 else w
        y = rnd.choice(words)
        assert _edit_distance_capped(x, y) == min(_reference_levenshtein(x, y), 2), (x, y)
    assert check_lookalike("expres", "1.0.0") and not check_lookalike("express", "1.0.0")


# ─── requirements.txt ─────────────────────────────────────────────────────────

def test_requirements_malware_is_an_incident_with_pip_containment():
    req = parse_requirements_txt("evilpkg==1.0.0\nrequests==2.19.0\n")
    evil, requests_purl = req.packages[0].purl, req.packages[1].purl
    evidence = [ev(evil, "MAL-2099-7", tier=EvidenceTier.T1, kind=EvidenceKind.MALWARE_REPORT, eid="E1"),
                ev(requests_purl, "GHSA-req", fixed_version="2.20.0", eid="E2")]
    d = {x.subject: x for x in decisions_for_requirements(req.packages, evidence, AnalysisContext(), NOW)}
    assert d[evil].verdict.value == "INCIDENT"  # Before: no decision (NO KNOWN FINDING)
    assert d[requests_purl].verdict.value == "UPGRADE"
    assert any(s.command == "pip install 'requests==2.20.0'" for s in d[requests_purl].response_steps)
    assert all("requirements.txt" in " ".join(x.unrun_checks) for x in d.values())


# ─── Report API ───────────────────────────────────────────────────────────────

@pytest.fixture
def client(env):
    from fastapi.testclient import TestClient
    import app.main
    with TestClient(app.main.app) as c:
        yield c


def test_as_of_view_rederives_without_future_evidence(env, client):
    env.add(osv_record("GHSA-test-1000", "acme-tiny-parser", "1.1.0", fixed="1.1.1", published=NOW - timedelta(days=3)))
    env.add(osv_record("MAL-2099-1001", "acme-dev-runner", "0.9.0", fixed=None, malware=True,
                       published=NOW - timedelta(hours=2)))
    rid = analyze()
    now_view = client.get(f"/api/reports/{rid}").json()
    assert verdicts_from(now_view) == {PARSER: "UPGRADE", "pkg:npm/acme-dev-runner@0.9.0": "INCIDENT"}

    earlier = (NOW - timedelta(days=1)).isoformat()
    view = client.get(f"/api/reports/{rid}", params={"as_of": earlier}).json()
    assert verdicts_from(view) == {PARSER: "UPGRADE"}  # Malware report published later is not visible
    assert view["summary"]["incident"] == 0 and view["meta"]["as_of_view"]["rederived"] is True
    assert view["meta"]["as_of_view"]["excluded_evidence_count"] >= 1
    before_all = client.get(f"/api/reports/{rid}", params={"as_of": (NOW - timedelta(days=5)).isoformat()}).json()
    assert verdicts_from(before_all) == {}
    assert load_report(rid) == now_view  # Stored report untouched

    later = client.get(f"/api/reports/{rid}", params={"as_of": (NOW + timedelta(days=1)).isoformat()}).json()
    assert later["meta"]["as_of_view"]["rederived"] is False and verdicts_from(later) == verdicts_from(now_view)
    assert client.get(f"/api/reports/{rid}", params={"as_of": "yesterday"}).status_code == 400


def verdicts_from(report: dict) -> dict[str, str]:
    return {d["subject"]: d["verdict"] for d in report["decisions"]}


def test_as_of_without_stored_graph_is_an_explicit_error(env, client):
    report = load_report(analyze())
    report["graph"] = {"nodes": [], "edges": []}
    save_report("no-graph", report)
    res = client.get("/api/reports/no-graph", params={"as_of": (NOW - timedelta(days=1)).isoformat()})
    assert res.status_code == 422 and "no stored dependency graph" in res.json()["detail"]


def test_import_never_overwrites_and_is_labelled(env, client):
    rid = analyze()
    original = load_report(rid)
    tampered = {**original, "decisions": [], "meta": {**original["meta"], "watch": {"watch_id": "x"}}}
    files = {"file": ("r.json", json.dumps(tampered).encode(), "application/json")}
    new_id = client.post("/api/reports/import", files=files).json()["report_id"]
    assert new_id != rid and load_report(rid) == original  # Existing report untouched
    imported = load_report(new_id)
    assert imported["meta"]["imported"]["original_id"] == rid and "watch" not in imported["meta"]
    bad = {"file": ("r.json", json.dumps({"summary": {}, "decisions": "x"}).encode(), "application/json")}
    assert client.post("/api/reports/import", files=bad).status_code == 400


def test_simulate_fix_uses_the_engine_and_never_turns_failure_into_clean(env, client):
    env.add(osv_record("GHSA-test-1100", "acme-tiny-parser", "1.1.0", fixed="1.2.0"))
    env.add(osv_record("MAL-2099-1101", "acme-tiny-parser", "1.2.0", fixed=None, malware=True))
    rid = analyze()
    sim = client.post(f"/api/reports/{rid}/simulate-fix", json={"subject": PARSER, "to_version": "1.2.0"}).json()
    assert sim["before"]["verdict"] == "UPGRADE" and sim["after"]["verdict"] == "INCIDENT"  # Was "UPGRADE"
    clean = client.post(f"/api/reports/{rid}/simulate-fix", json={"subject": PARSER, "to_version": "1.3.0"}).json()
    assert clean["after"]["verdict"] == "NO_KNOWN_FINDING" and clean["checks_incomplete"] == []
    env.down.add("osv")  # A version not looked up before, so nothing is served from cache
    down = client.post(f"/api/reports/{rid}/simulate-fix", json={"subject": PARSER, "to_version": "1.4.0"}).json()
    assert down["after"]["verdict"] == "CANNOT_ASSESS" and down["checks_incomplete"]  # Was NO_KNOWN_FINDING
    assert client.post(f"/api/reports/{rid}/simulate-fix",
                       json={"subject": PARSER, "to_version": "1.0/../x"}).status_code == 400


def test_non_object_context_is_ignored_safely(env, client):
    rid = client.post("/api/analyze", data={"text": LOCKFILE, "context": "[1, 2]"}).json()["report_id"]
    assert client.get(f"/api/reports/{rid}").status_code == 200


def test_expensive_endpoints_share_the_strict_rate_limit_budget(env, client, monkeypatch):
    import app.security as sec
    monkeypatch.setattr(sec, "_limiter_upload", _SlidingWindowBucket(max_requests=2, window_seconds=60))
    env.add(osv_record("GHSA-test-1200", "acme-tiny-parser", "1.1.0", fixed="1.2.0"))
    rid = client.post("/api/analyze", data={"text": LOCKFILE, "context": "{}"}).json()["report_id"]
    assert client.post(f"/api/reports/{rid}/simulate-fix", json={"subject": PARSER, "to_version": "9.9.9"}).status_code == 200
    blocked = client.post("/api/analyze", data={"text": LOCKFILE, "context": "{}"})
    assert blocked.status_code == 429 and blocked.headers["retry-after"]
    assert client.get(f"/api/reports/{rid}").status_code == 200  # Reads use the general budget


def test_rate_limiter_memory_is_bounded(monkeypatch):
    bucket = _SlidingWindowBucket(max_requests=1, window_seconds=0)
    monkeypatch.setattr(_SlidingWindowBucket, "MAX_TRACKED_CLIENTS", 100)
    for i in range(1000):
        bucket.is_allowed(f"10.0.{i // 250}.{i % 250}")
    assert len(bucket._buckets) <= 101


def test_security_headers(env, client):
    headers = client.get("/api/health").headers
    assert headers["x-content-type-options"] == "nosniff" and headers["x-xss-protection"] == "0"


# ─── Warrant Watch hardening ──────────────────────────────────────────────────

def test_manual_live_checks_have_a_cooldown(env, client, monkeypatch):
    monkeypatch.setattr(monitor, "MANUAL_CHECK_COOLDOWN", timedelta(seconds=30))
    wid = client.post("/api/watch", json={"report_id": analyze()}).json()["id"]
    assert client.post(f"/api/watch/{wid}/check").status_code == 200
    again = client.post(f"/api/watch/{wid}/check")
    assert again.status_code == 429 and "try again" in again.json()["detail"]
    assert asyncio.run(monitor.run_check(wid, "scheduled"))["check"]["status"] == "complete"


def test_idle_replay_watch_is_not_reanalysed_every_tick(env):
    w = asyncio.run(monitor.create_replay_demo("axios-compromise-2026-03-31"))
    asyncio.run(monitor.run_check(w["id"], "scheduled"))
    next_check = store.parse_ts(store.get_watch(w["id"])["next_check_at"])
    assert next_check - datetime.now(timezone.utc) > timedelta(minutes=30)  # Idle: live cadence
    asyncio.run(monitor.advance_replay(w["id"]))
    next_check = store.parse_ts(store.get_watch(w["id"])["next_check_at"])
    assert next_check - datetime.now(timezone.utc) < timedelta(seconds=30)  # Release re-arms fast detection


def test_unexpected_check_error_is_recorded_and_rescheduled(env, monkeypatch):
    w = enable(analyze())

    async def boom(*a, **k):
        raise RuntimeError("bug")

    monkeypatch.setattr(monitor, "_run_check_locked", boom)
    result = asyncio.run(monitor.run_check(w["id"], "scheduled"))
    assert result["check"]["status"] == "failed" and "not a clean result" in result["check"]["summary"]
    after = store.get_watch(w["id"])
    assert after["last_check_status"] == "failed"
    assert store.parse_ts(after["next_check_at"]) > datetime.now(timezone.utc) + timedelta(minutes=30)
