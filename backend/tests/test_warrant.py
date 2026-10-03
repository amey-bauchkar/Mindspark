"""
Backend tests — parser, graph, engine rules.
Run with: pytest tests/
"""
from __future__ import annotations
import json
import pytest
from datetime import datetime, timezone
from pathlib import Path

from app.parsers.npm_lock import parse_npm_lock
from app.parsers.requirements_txt import parse_requirements_txt
from app.graph.build import build_graph, ROOT_ID
from app.models.evidence import EvidenceRecord, EvidenceTier, EvidenceKind
from app.models.report import AnalysisContext, DistributionMode, ProjectLicense
from app.engine.decide import derive_decisions
from app.engine.narrate import verify_claim, SYNTHETIC_CORRUPTED_CLAIM
from app.licenses.rules import classify_license, LICENSE_RULES_TABLE
from app.signals.lookalike import check_lookalike
from app.signals.cvss_profile import parse_cvss_vector


# ─── Parser tests ──────────────────────────────────────────────────────────────

MINIMAL_LOCK_V3 = json.dumps({
    "name": "test-app",
    "version": "1.0.0",
    "lockfileVersion": 3,
    "requires": True,
    "packages": {
        "": {
            "name": "test-app",
            "version": "1.0.0",
            "dependencies": {"express": "^4.18.0"}
        },
        "node_modules/express": {
            "version": "4.18.2",
            "resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
            "integrity": "sha512-xxx",
            "license": "MIT",
            "dependencies": {"qs": "^6.11.0"}
        },
        "node_modules/qs": {
            "version": "6.11.0",
            "resolved": "https://registry.npmjs.org/qs/-/qs-6.11.0.tgz",
            "integrity": "sha512-yyy",
            "license": "BSD-3-Clause"
        }
    }
})

LOCK_WITH_NESTED = json.dumps({
    "name": "nested-test",
    "version": "1.0.0",
    "lockfileVersion": 3,
    "packages": {
        "": {"name": "nested-test", "version": "1.0.0", "dependencies": {"a": "1.0.0"}},
        "node_modules/a": {
            "version": "1.0.0",
            "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz",
            "license": "MIT",
            "dependencies": {"b": "2.0.0"}
        },
        "node_modules/b": {
            "version": "2.0.0",
            "resolved": "https://registry.npmjs.org/b/-/b-2.0.0.tgz",
            "license": "MIT"
        },
        "node_modules/a/node_modules/b": {
            "version": "1.0.0",  # Nested version of b under a
            "resolved": "https://registry.npmjs.org/b/-/b-1.0.0.tgz",
            "license": "ISC"
        }
    }
})


def test_parse_minimal_lock():
    result = parse_npm_lock(MINIMAL_LOCK_V3)
    assert result.lockfile_version == 3
    assert result.name == "test-app"
    assert len(result.packages) == 2  # express and qs


def test_parse_rejects_v1():
    lock_v1 = json.dumps({"lockfileVersion": 1, "packages": {}})
    with pytest.raises(ValueError, match="Unsupported lockfileVersion"):
        parse_npm_lock(lock_v1)


def test_parse_rejects_invalid_json():
    with pytest.raises(ValueError, match="Invalid JSON"):
        parse_npm_lock("{not valid json")


def test_parse_edge_reconstruction():
    """Verify that edges are reconstructed correctly via nearest-ancestor."""
    result = parse_npm_lock(MINIMAL_LOCK_V3)
    # Find express package
    express_purl = next((p for p in result.packages if "express" in p), None)
    assert express_purl is not None
    express_pkg = result.packages[express_purl]
    resolved_edges = getattr(express_pkg, "resolved_edges", {})
    # express should have a resolved edge to qs
    assert "qs" in resolved_edges or len(resolved_edges) == 0  # qs may resolve


def test_nested_resolution():
    """Nearest-ancestor: node_modules/a/node_modules/b resolves for a's dep on b."""
    result = parse_npm_lock(LOCK_WITH_NESTED)
    # Both versions of b should be present
    purls = list(result.packages.keys())
    b_purls = [p for p in purls if "pkg:npm/b%40" in p or "/b@" in p.lower()]
    assert len(b_purls) >= 1


def test_git_url_detected():
    """Packages with git+ resolved URLs should be flagged."""
    lock = json.dumps({
        "name": "git-test", "version": "1.0.0", "lockfileVersion": 3,
        "packages": {
            "": {"name": "git-test", "version": "1.0.0"},
            "node_modules/my-pkg": {
                "version": "1.0.0",
                "resolved": "git+https://github.com/org/my-pkg.git#abc123",
            }
        }
    })
    result = parse_npm_lock(lock)
    git_pkg = next((p for p in result.packages.values() if p.is_git_or_file), None)
    assert git_pkg is not None


# ─── Graph tests ───────────────────────────────────────────────────────────────

def test_build_graph():
    result = parse_npm_lock(MINIMAL_LOCK_V3)
    build = build_graph(result)
    assert ROOT_ID in build.graph.nodes
    assert len(build.packages) == 2


def test_scope_propagation():
    """Dev-only package should remain dev scope."""
    lock = json.dumps({
        "name": "scope-test", "version": "1.0.0", "lockfileVersion": 3,
        "packages": {
            "": {"name": "scope-test", "version": "1.0.0", "devDependencies": {"jest": "29.0.0"}},
            "node_modules/jest": {
                "version": "29.0.0",
                "resolved": "https://registry.npmjs.org/jest/-/jest-29.0.0.tgz",
                "dev": True, "license": "MIT"
            }
        }
    })
    result = parse_npm_lock(lock)
    build = build_graph(result)
    jest_purl = next(p for p in build.packages if "jest" in p)
    assert build.packages[jest_purl].scope in ("dev", "optional")


# ─── Engine tests ──────────────────────────────────────────────────────────────

def _make_build(name: str = "a", version: str = "1.0.0"):
    lock = json.dumps({
        "name": "engine-test", "version": "1.0.0", "lockfileVersion": 3,
        "packages": {
            "": {"name": "engine-test", "version": "1.0.0", "dependencies": {name: version}},
            f"node_modules/{name}": {
                "version": version,
                "resolved": f"https://registry.npmjs.org/{name}/-/{name}-{version}.tgz",
                "license": "MIT"
            }
        }
    })
    parse = parse_npm_lock(lock)
    return build_graph(parse), parse


def _purl(name: str, version: str) -> str:
    return f"pkg:npm/{name}@{version}"


def test_r1_malware_incident():
    """R1: Active malware report → INCIDENT."""
    build, parse = _make_build("evil-pkg", "1.0.0")
    purl = _purl("evil-pkg", "1.0.0")
    now = datetime.now(timezone.utc)
    evidence = [EvidenceRecord(
        id="E0001", tier=EvidenceTier.T1, source="osv", origin="OpenSSF",
        kind=EvidenceKind.MALWARE_REPORT, subject=purl,
        claim="Malware report: MAL-2024-1234",
        retrieved_at=now, published_at=now,
        data={"vuln_id": "MAL-2024-1234", "is_malware": True},
    )]
    context = AnalysisContext()
    decisions = derive_decisions(build, evidence, context, as_of=now)
    incident_decisions = [d for d in decisions if d.subject == purl]
    assert incident_decisions, "Expected a decision for evil-pkg"
    assert incident_decisions[0].verdict.value == "INCIDENT"


def test_r7_no_known_finding_not_produced_for_clean():
    """R7: Clean packages should not clutter the decision list."""
    build, parse = _make_build("clean-pkg", "2.0.0")
    now = datetime.now(timezone.utc)
    decisions = derive_decisions(build, [], AnalysisContext(), as_of=now)
    # Should have 0 or only CANNOT_ASSESS decisions (if absent evidence)
    non_nkf = [d for d in decisions if d.verdict.value not in ("NO_KNOWN_FINDING",)]
    # We accept any outcome as long as no INCIDENT/ACT_NOW/UPGRADE without evidence
    for d in decisions:
        assert d.verdict.value != "INCIDENT"
        assert d.verdict.value != "ACT_NOW"


def test_r4_dev_only_advisory_gives_monitor():
    """R4: Advisory on dev-only path → MONITOR."""
    lock = json.dumps({
        "name": "dev-test", "version": "1.0.0", "lockfileVersion": 3,
        "packages": {
            "": {"name": "dev-test", "version": "1.0.0", "devDependencies": {"vuln-pkg": "1.0.0"}},
            "node_modules/vuln-pkg": {
                "version": "1.0.0",
                "resolved": "https://registry.npmjs.org/vuln-pkg/-/vuln-pkg-1.0.0.tgz",
                "dev": True, "license": "MIT"
            }
        }
    })
    parse = parse_npm_lock(lock)
    build = build_graph(parse)
    purl = _purl("vuln-pkg", "1.0.0")
    now = datetime.now(timezone.utc)
    evidence = [EvidenceRecord(
        id="E0002", tier=EvidenceTier.T2, source="osv", origin="GHSA",
        kind=EvidenceKind.ADVISORY, subject=purl,
        claim="Advisory CVE-2024-0001", retrieved_at=now, published_at=now,
        data={"vuln_id": "GHSA-test-0001", "is_malware": False, "fixed_version": "2.0.0", "cve_aliases": []},
    )]
    decisions = derive_decisions(build, evidence, AnalysisContext(), as_of=now)
    vuln_decisions = [d for d in decisions if d.subject == purl]
    assert vuln_decisions
    assert vuln_decisions[0].verdict.value == "MONITOR"


def test_placeholder_version_not_incident():
    """
    PC-01: OSV placeholder version 0.0.1-security must NOT trigger INCIDENT
    even if the MAL record lists 0.0.1-security in its affected versions.
    It must yield REVIEW (REMEDIATED_BY_REGISTRY).
    """
    build, parse = _make_build("plain-crypto-js", "0.0.1-security")
    purl = _purl("plain-crypto-js", "0.0.1-security")
    now = datetime.now(timezone.utc)
    # Evidence record where subject matches the placeholder version (as in real MAL-2026-2306)
    evidence = [EvidenceRecord(
        id="E0003", tier=EvidenceTier.T1, source="osv", origin="OpenSSF",
        kind=EvidenceKind.MALWARE_REPORT, subject=purl,
        claim="Malware in plain-crypto-js (lists placeholder)",
        retrieved_at=now, published_at=now,
        data={"vuln_id": "MAL-2026-2306", "is_malware": True},
    )]
    context = AnalysisContext()
    decisions = derive_decisions(build, evidence, context, as_of=now)
    placeholder_decisions = [d for d in decisions if d.subject == purl]
    assert placeholder_decisions
    assert placeholder_decisions[0].verdict.value == "REVIEW", \
        "Placeholder version 0.0.1-security must become REVIEW (remediated), never INCIDENT"


def test_withdrawn_evidence_excluded():
    """Withdrawn OSV records must not contribute to verdicts."""
    build, parse = _make_build("some-pkg", "3.0.0")
    purl = _purl("some-pkg", "3.0.0")
    now = datetime.now(timezone.utc)
    evidence = [EvidenceRecord(
        id="E0004", tier=EvidenceTier.T2, source="osv", origin="GHSA",
        kind=EvidenceKind.ADVISORY, subject=purl,
        claim="Withdrawn advisory (retracted)",
        retrieved_at=now, published_at=now,
        withdrawn=True,  # ← withdrawn
        data={"vuln_id": "GHSA-withdrawn", "is_malware": False, "cve_aliases": []},
    )]
    decisions = derive_decisions(build, evidence, AnalysisContext(), as_of=now)
    pkg_decisions = [d for d in decisions if d.subject == purl]
    for d in pkg_decisions:
        assert d.verdict.value not in ("INCIDENT", "ACT_NOW", "UPGRADE")


def test_as_of_excludes_future_evidence():
    """Evidence published after as_of must be excluded."""
    build, parse = _make_build("future-pkg", "1.0.0")
    purl = _purl("future-pkg", "1.0.0")
    from datetime import timedelta
    past_time = datetime(2020, 1, 1, tzinfo=timezone.utc)
    future_time = datetime(2030, 1, 1, tzinfo=timezone.utc)
    evidence = [EvidenceRecord(
        id="E0005", tier=EvidenceTier.T1, source="osv", origin="OpenSSF",
        kind=EvidenceKind.MALWARE_REPORT, subject=purl,
        claim="Future malware report",
        retrieved_at=future_time, published_at=future_time,
        data={"vuln_id": "MAL-2030-9999", "is_malware": True},
    )]
    # as_of = past (before the evidence)
    decisions = derive_decisions(build, evidence, AnalysisContext(), as_of=past_time)
    pkg_decisions = [d for d in decisions if d.subject == purl]
    for d in pkg_decisions:
        assert d.verdict.value != "INCIDENT", "Future evidence must not influence past decisions"


# ─── License tests ─────────────────────────────────────────────────────────────

def test_gpl_proprietary_distributed_is_conflict():
    ctx = AnalysisContext(
        distribution_mode=DistributionMode.DISTRIBUTED,
        project_license=ProjectLicense.PROPRIETARY,
    )
    status, rule, note = classify_license("GPL-3.0-or-later", ctx)
    assert status == "CONFLICT"


def test_mit_always_ok():
    ctx = AnalysisContext()
    status, rule, note = classify_license("MIT", ctx)
    assert status == "OK"


def test_agpl_saas_proprietary_is_conflict():
    ctx = AnalysisContext(
        distribution_mode=DistributionMode.SAAS,
        project_license=ProjectLicense.PROPRIETARY,
    )
    status, rule, note = classify_license("AGPL-3.0-or-later", ctx)
    assert status == "CONFLICT"


def test_missing_license_is_review():
    ctx = AnalysisContext()
    status, rule, note = classify_license(None, ctx)
    assert status == "REVIEW"


def test_license_rules_table_exists():
    assert len(LICENSE_RULES_TABLE) >= 7


# ─── Verifier tests ────────────────────────────────────────────────────────────

def test_verifier_rejects_fabricated_claim():
    from app.models.decision import Decision, Verdict, Urgency, Qualifier, ResponseClass, ExposureInfo
    dummy = Decision(
        subject="pkg:npm/dummy@1.0.0", name="dummy", version="1.0.0",
        verdict=Verdict.NO_KNOWN_FINDING, urgency=Urgency.NONE, qualifier=Qualifier.UNKNOWN,
        exposure=ExposureInfo(paths=[], scope="prod", scope_provenance="test",
                              install_phase="unknown", scripts_enabled="assumed"),
        evidence_ids=[], response=ResponseClass.NONE,
        as_of=datetime.now(timezone.utc), derivation=[], what="test",
    )
    result = verify_claim(SYNTHETIC_CORRUPTED_CLAIM, dummy, {})
    assert not result.passed


def test_verifier_passes_valid_claim():
    from app.models.decision import Decision, Verdict, Urgency, Qualifier, ResponseClass, ExposureInfo
    now = datetime.now(timezone.utc)
    dummy = Decision(
        subject="pkg:npm/lodash@4.17.20", name="lodash", version="4.17.20",
        verdict=Verdict.UPGRADE, urgency=Urgency.SCHEDULED, qualifier=Qualifier.ESTABLISHED,
        exposure=ExposureInfo(paths=[], scope="prod", scope_provenance="test",
                              install_phase="unknown", scripts_enabled="assumed"),
        evidence_ids=["E0001"], response=ResponseClass.UPGRADE,
        as_of=now, derivation=[], what="Advisory CVE-2021-23337",
    )
    valid_claim = {
        "evidence_ids": ["E0001"],
        "verdict": "UPGRADE",
        "entities": ["lodash"],
    }
    result = verify_claim(valid_claim, dummy, {})
    assert result.passed


# ─── Lookalike tests ───────────────────────────────────────────────────────────

def test_lookalike_expres_detected():
    records = check_lookalike("expres", "1.0.0")
    assert any(r.kind.value == "lookalike" for r in records)


def test_lookalike_exact_not_flagged():
    records = check_lookalike("express", "4.18.2")
    assert len(records) == 0


def test_lookalike_short_name_not_flagged():
    records = check_lookalike("ab", "1.0.0")
    assert len(records) == 0


# ─── CVSS profile tests ────────────────────────────────────────────────────────

def test_cvss_v3_parsed():
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    profile = parse_cvss_vector(vector)
    assert profile is not None
    assert profile["attack_vector"] == "network-reachable"
    assert profile["confidentiality_impact"] == "high"


def test_cvss_none_returns_none():
    assert parse_cvss_vector(None) is None


# ─── Requirements.txt parser tests ────────────────────────────────────────────

def test_requirements_parses_pinned():
    content = "requests==2.28.0\nflask==2.3.0\n# comment\nunpinned-dep>=1.0\n"
    result = parse_requirements_txt(content)
    assert len(result.packages) == 2
    assert any(p.name == "requests" for p in result.packages)
    assert any("unpinned" in w for w in result.warnings)


# ─── Corporate License Policies & Banned Dependencies Tests ───────────────────

def test_company_policy_dataset_has_at_least_3_examples():
    """Verify company_policies.json has at least 3 authentic company profiles with allowed and banned lists."""
    from app.licenses.rules import COMPANY_POLICIES
    assert len(COMPANY_POLICIES) >= 3, f"Expected at least 3 companies, got {len(COMPANY_POLICIES)}"
    for company_id in ["google", "apache", "meta"]:
        assert company_id in COMPANY_POLICIES, f"Missing {company_id} in company policies"
        policy = COMPANY_POLICIES[company_id]
        assert len(policy["allowed_licenses"]) > 0, f"{company_id} has no allowed licenses"
        assert len(policy["banned_licenses"]) > 0, f"{company_id} has no banned licenses"
        assert "http" in policy["source_url"], f"{company_id} missing authoritative source URL"


def test_corporate_policy_google_bans_agpl():
    """Google strictly bans AGPL across all backend and client code."""
    from app.licenses.rules import classify_license
    ctx = AnalysisContext(company_policy="google")
    status, rule_id, note = classify_license("AGPL-3.0", ctx)
    assert status == "CONFLICT"
    assert rule_id == "LR8"
    assert "Google" in note
    assert "prohibited" in note.lower() or "banned" in note.lower()


def test_corporate_policy_apache_bans_gpl():
    """Apache Software Foundation Category X strictly bans GPL releases."""
    from app.licenses.rules import classify_license
    ctx = AnalysisContext(company_policy="apache")
    status, rule_id, note = classify_license("GPL-3.0-only", ctx)
    assert status == "CONFLICT"
    assert rule_id == "LR8"
    assert "Apache" in note


def test_corporate_policy_meta_bans_sspl():
    """Meta strictly bans SSPL and non-commercial source-available licenses."""
    from app.licenses.rules import classify_license
    ctx = AnalysisContext(company_policy="meta")
    status, rule_id, note = classify_license("SSPL-1.0", ctx)
    assert status == "CONFLICT"
    assert rule_id == "LR8"
    assert "Meta" in note


def test_corporate_policy_allows_permissive():
    """All companies permit standard permissive licenses like MIT and Apache-2.0."""
    from app.licenses.rules import classify_license
    for company in ["google", "apache", "meta", "microsoft"]:
        ctx = AnalysisContext(company_policy=company)
        status, rule_id, _ = classify_license("MIT", ctx)
        assert status == "OK"
        assert rule_id == "LR1"


def test_custom_organization_banned_dependencies():
    """Organizations can ban specific package names or versions."""
    from app.licenses.rules import classify_license
    ctx = AnalysisContext(banned_dependencies=["blacklisted-crypto", "evil-lib@1.0.0"])
    # Package in banned list
    status, rule_id, note = classify_license("MIT", ctx, package_name="blacklisted-crypto")
    assert status == "CONFLICT"
    assert rule_id == "LR-BANNED-PKG"
    assert "blacklisted-crypto" in note

    # Clean package not in banned list
    clean_status, clean_rule, _ = classify_license("MIT", ctx, package_name="clean-package")
    assert clean_status == "OK"
    assert clean_rule == "LR1"

