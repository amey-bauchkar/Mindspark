"""
Analysis job orchestrator — coordinates parsing, graph building, evidence gathering,
signals, license checks, and decision derivation.
Runs as a background task; updates progress state in memory.
"""
from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .parsers.npm_lock import parse_npm_lock, ParseResult
from .parsers.requirements_txt import parse_requirements_txt
from .graph.build import build_graph, BuildResult, ROOT_ID
from .providers.osv import fetch_osv_batch
from .providers.epss import fetch_epss, fetch_kev, build_epss_kev_records
from .providers.deps_dev import bulk_fetch_licenses
from .providers.npm_registry import bulk_fetch_npm_times
from .signals.lookalike import check_lookalike
from .signals.staleness import check_staleness, check_install_script
from .signals.cvss_profile import parse_cvss_vector
from .licenses.rules import classify_license
from .engine.decide import derive_decisions
from .engine.remediate import build_fix_commands, format_containment_checklist
from .models.evidence import EvidenceRecord, EvidenceTier, EvidenceKind
from .models.decision import Decision, Verdict, ResponseClass
from .models.report import (
    Report, ReportSummary, AnalysisContext, GraphNode, GraphEdge,
    LicenseResult, CoverageCheck, DistributionMode, ProjectLicense,
)
from .providers.cache import save_report
from .config import get_settings


# In-memory progress state (no DB needed for transient progress)
_progress: dict[str, dict] = {}


def get_progress(report_id: str) -> dict | None:
    return _progress.get(report_id)


def _set_progress(report_id: str, stage: str, pct: int, extra: dict | None = None) -> None:
    _progress[report_id] = {
        "stage": stage,
        "progress": pct,
        "partial": False,
        **(extra or {}),
    }


def _set_error(report_id: str, stage: str, error: str) -> None:
    _progress[report_id] = {
        "stage": stage,
        "progress": 0,
        "partial": False,
        "error": error,
    }


def _set_done(report_id: str) -> None:
    if report_id in _progress:
        _progress[report_id]["stage"] = "done"
        _progress[report_id]["progress"] = 100


async def run_analysis(
    report_id: str,
    file_content: str,
    filename: str,
    context_data: dict,
) -> None:
    """
    Main analysis coroutine. Updates _progress throughout.
    Stores final report in SQLite via save_report.
    """
    settings = get_settings()
    now = datetime.now(timezone.utc)
    evidence: list[EvidenceRecord] = []
    warnings: list[str] = []
    is_requirements = filename.endswith(".txt") or "requirements" in filename.lower()
    ecosystem = "PyPI (limited)" if is_requirements else "npm"
    data_badge = "RECORDED" if settings.offline_fixtures else "LIVE"

    try:
        # ── Stage 1: Parse ────────────────────────────────────────────────────
        _set_progress(report_id, "Parsing lockfile", 5)
        await asyncio.sleep(0)  # Yield to event loop

        if is_requirements:
            req_result = parse_requirements_txt(file_content)
            warnings.extend(req_result.warnings)
            # Build a minimal report for requirements.txt
            purls = [p.purl for p in req_result.packages]

            _set_progress(report_id, "Querying OSV (vulnerabilities)", 20)
            osv_evidence = await fetch_osv_batch(purls)
            evidence.extend(osv_evidence)

            # EPSS/KEV
            _set_progress(report_id, "Fetching EPSS and CISA KEV", 40)
            all_cves = [a for e in osv_evidence for a in e.data.get("cve_aliases", [])]
            epss_scores, kev_set = await asyncio.gather(
                fetch_epss(all_cves), fetch_kev()
            )
            evidence.extend(build_epss_kev_records(osv_evidence, epss_scores, kev_set, settings.epss_threshold))

            _set_progress(report_id, "Deriving decisions", 80)
            # Build simplified decisions (no graph, paths UNKNOWN)
            decisions = _decisions_for_requirements(req_result, evidence, _parse_context(context_data), now)

            # License results
            licenses = _licenses_for_requirements(req_result, _parse_context(context_data))

            # Coverage
            coverage = _requirements_coverage()

            # Summary
            summary = _build_summary(decisions, len(purls), 0, now, ecosystem, data_badge)

            report = Report(
                id=report_id,
                created_at=now,
                meta={
                    "filename": filename,
                    "ecosystem": ecosystem,
                    "package_count": len(purls),
                    "warnings": warnings,
                    "note": "requirements.txt adapter: direct dependencies only; paths unknown.",
                },
                summary=summary,
                decisions=decisions,
                evidence=evidence,
                graph={"nodes": [], "edges": []},
                licenses=licenses,
                coverage=coverage,
                context=_parse_context(context_data),
            )
            save_report(report_id, report.model_dump())
            _set_done(report_id)
            return

        # ── npm lockfile path ─────────────────────────────────────────────────
        parse = parse_npm_lock(file_content)
        warnings.extend(parse.warnings)
        _set_progress(report_id, f"Rebuilding graph ({len(parse.packages)} packages)", 10)

        build = build_graph(parse)
        if build.cycles_detected:
            warnings.append("Dependency cycles detected (likely peer deps) — broken for analysis.")

        purls = list(build.packages.keys())
        _set_progress(report_id, f"Querying OSV ({len(purls)} packages)", 20)

        # ── Stage 2: OSV ──────────────────────────────────────────────────────
        osv_evidence = await fetch_osv_batch(purls)
        evidence.extend(osv_evidence)

        # ── Stage 3: EPSS + KEV ───────────────────────────────────────────────
        _set_progress(report_id, "Fetching EPSS and CISA KEV", 35)
        all_cves = list({a for e in osv_evidence for a in e.data.get("cve_aliases", [])})
        epss_scores, kev_set = await asyncio.gather(
            fetch_epss(all_cves), fetch_kev()
        )
        epss_kev_records = build_epss_kev_records(osv_evidence, epss_scores, kev_set, settings.epss_threshold)
        evidence.extend(epss_kev_records)

        # ── Stage 4: Licenses via deps.dev for missing ────────────────────────
        _set_progress(report_id, "Checking licenses", 50)
        missing_license_pkgs = [
            (pkg.name, pkg.version)
            for pkg in build.packages.values()
            if not pkg.license
        ]
        fetched_licenses: dict = {}
        if missing_license_pkgs:
            fetched_licenses = await bulk_fetch_licenses(missing_license_pkgs[:100])  # Cap at 100

        # Fill in fetched licenses
        for (name, version), lic in fetched_licenses.items():
            purl = f"pkg:npm/{name.replace('@', '%40').replace('/', '%2F')}@{version}"
            if purl in build.packages and not build.packages[purl].license:
                build.packages[purl].license = lic

        # ── Stage 5: Registry metadata (for direct deps + flagged packages) ───
        _set_progress(report_id, "Fetching registry metadata", 60)
        packages_needing_registry = [
            (pkg.name, pkg.version)
            for pkg in build.packages.values()
            if pkg.is_direct
        ]
        npm_times_map = await bulk_fetch_npm_times(packages_needing_registry[:50])

        # ── Stage 6: Signals ──────────────────────────────────────────────────
        _set_progress(report_id, "Running signals", 70)
        for purl, pkg in build.packages.items():
            # Install script
            evidence.extend(check_install_script(pkg.name, pkg.version, pkg.has_install_script))
            # Lookalike
            evidence.extend(check_lookalike(pkg.name, pkg.version))
            # Staleness / freshness
            times = npm_times_map.get(pkg.name)
            if times:
                evidence.extend(check_staleness(pkg.name, pkg.version, times))
            elif pkg.is_direct:
                # ABSENT: registry metadata not fetched
                evidence.append(EvidenceRecord(
                    id=f"REG-MISS-{pkg.name[:15].replace('/', '-').replace('@', '')}",
                    tier=EvidenceTier.ABSENT,
                    source="npm-registry",
                    origin="npm registry",
                    kind=EvidenceKind.OTHER,
                    subject=purl,
                    claim="Registry metadata not fetched for this package (not a direct dep or cap reached)",
                    retrieved_at=now,
                ))

        # ── Stage 7: Derive decisions ─────────────────────────────────────────
        _set_progress(report_id, "Deriving decisions", 80)
        context = _parse_context(context_data)
        decisions = derive_decisions(build, evidence, context, as_of=now)

        # Enrich with remediation commands
        for dec in decisions:
            if dec.response in (ResponseClass.CONTAINMENT,):
                dec.response_steps = format_containment_checklist(dec)
            elif dec.fixed_version:
                dec.response_steps = build_fix_commands(dec)

        # ── Stage 8: License classification ──────────────────────────────────
        _set_progress(report_id, "Classifying licenses", 88)
        licenses = _classify_all_licenses(build, context, decisions)

        # ── Stage 9: Build graph output ───────────────────────────────────────
        _set_progress(report_id, "Building graph", 93)
        graph_data = _build_graph_output(build, decisions)

        # ── Stage 10: Coverage ────────────────────────────────────────────────
        coverage = _build_coverage(build, evidence, osv_evidence, epss_kev_records, fetched_licenses, npm_times_map)

        # ── Summary ───────────────────────────────────────────────────────────
        direct_count = sum(1 for p in build.packages.values() if p.is_direct)
        summary = _build_summary(decisions, len(purls), direct_count, now, ecosystem, data_badge)

        report = Report(
            id=report_id,
            created_at=now,
            meta={
                "filename": filename,
                "ecosystem": ecosystem,
                "package_count": len(purls),
                "direct_count": direct_count,
                "lockfile_version": parse.lockfile_version,
                "root_name": parse.name,
                "root_version": parse.root_version,
                "warnings": warnings,
                "cycles_detected": build.cycles_detected,
            },
            summary=summary,
            decisions=decisions,
            evidence=evidence,
            graph=graph_data,
            licenses=licenses,
            coverage=coverage,
            context=context,
        )
        save_report(report_id, report.model_dump())
        _set_done(report_id)

    except Exception as exc:
        _set_error(report_id, "analysis", str(exc))
        raise


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _parse_context(data: dict) -> AnalysisContext:
    skipped = []
    dist_raw = data.get("distribution_mode")
    proj_lic_raw = data.get("project_license")
    scripts_raw = data.get("install_scripts_run")

    try:
        dist = DistributionMode(dist_raw) if dist_raw else DistributionMode.UNKNOWN
    except ValueError:
        dist = DistributionMode.UNKNOWN
    if not dist_raw:
        skipped.append("distribution_mode")

    try:
        proj_lic = ProjectLicense(proj_lic_raw) if proj_lic_raw else ProjectLicense.UNKNOWN
    except ValueError:
        proj_lic = ProjectLicense.UNKNOWN
    if not proj_lic_raw:
        skipped.append("project_license")

    scripts = None
    if scripts_raw is None:
        skipped.append("install_scripts_run")
    elif isinstance(scripts_raw, bool):
        scripts = scripts_raw
    elif str(scripts_raw).lower() in ("true", "yes", "1"):
        scripts = True
    elif str(scripts_raw).lower() in ("false", "no", "0"):
        scripts = False

    return AnalysisContext(
        distribution_mode=dist,
        project_license=proj_lic,
        install_scripts_run=scripts,
        skipped_fields=skipped,
    )


def _build_summary(
    decisions: list[Decision],
    total: int,
    direct: int,
    as_of: datetime,
    ecosystem: str,
    data_badge: str,
) -> ReportSummary:
    counts: dict[str, int] = {v.value: 0 for v in Verdict}
    for d in decisions:
        counts[d.verdict.value] = counts.get(d.verdict.value, 0) + 1
    return ReportSummary(
        incident=counts.get("INCIDENT", 0),
        act_now=counts.get("ACT_NOW", 0),
        upgrade=counts.get("UPGRADE", 0),
        monitor=counts.get("MONITOR", 0),
        review=counts.get("REVIEW", 0),
        cannot_assess=counts.get("CANNOT_ASSESS", 0),
        no_known_finding=counts.get("NO_KNOWN_FINDING", 0),
        total_packages=total,
        direct_packages=direct,
        as_of=as_of,
        ecosystem=ecosystem,
        data_badge=data_badge,
    )


def _build_graph_output(build: BuildResult, decisions: list[Decision]) -> dict:
    verdict_map = {d.subject: d.verdict.value for d in decisions}
    nodes = []
    for purl, pkg in build.packages.items():
        nodes.append({
            "id": purl,
            "name": pkg.name,
            "version": pkg.version,
            "is_direct": pkg.is_direct,
            "scope": pkg.scope,
            "scope_provenance": pkg.scope_provenance,
            "depth": pkg.depth,
            "has_install_script": pkg.has_install_script,
            "is_git_or_file": pkg.is_git_or_file,
            "license": pkg.license,
            "introduced_by": pkg.introduced_by,
            "direct_dependents_count": pkg.direct_dependents_count,
            "verdict": verdict_map.get(purl),
        })
    edges = []
    for u, v, data in build.graph.edges(data=True):
        if u == ROOT_ID or v == ROOT_ID:
            continue
        edges.append({
            "source": u,
            "target": v,
            "scope": data.get("scope", "prod"),
        })
    return {"nodes": nodes, "edges": edges}


def _classify_all_licenses(
    build: BuildResult,
    context: AnalysisContext,
    decisions: list[Decision],
) -> list[LicenseResult]:
    from .graph.build import ROOT_ID, find_paths
    results = []
    for purl, pkg in build.packages.items():
        lic = pkg.license
        status, rule_id, note = classify_license(lic, context)
        paths = find_paths(build.graph, ROOT_ID, purl, max_paths=3)
        path_names = [[_label(build, n) for n in p] for p in paths]
        results.append(LicenseResult(
            subject=purl,
            name=pkg.name,
            version=pkg.version,
            license_expr=lic,
            license_status=status,
            rule_fired=rule_id,
            introducing_paths=path_names,
            note=note,
        ))
    return results


def _label(build: BuildResult, node: str) -> str:
    if node == ROOT_ID:
        return build.root_name
    pkg = build.packages.get(node)
    return f"{pkg.name}@{pkg.version}" if pkg else node


def _build_coverage(build, evidence, osv_ev, epss_kev_ev, fetched_lic, npm_times_map) -> list[CoverageCheck]:
    absent_osv = sum(1 for e in osv_ev if e.tier == EvidenceTier.ABSENT)
    absent_epss = sum(1 for e in epss_kev_ev if e.tier == EvidenceTier.ABSENT)
    return [
        CoverageCheck(check="Vulnerability lookup (OSV)", status="Ran" if osv_ev else "Not run",
                      count=len([e for e in osv_ev if e.tier != EvidenceTier.ABSENT]),
                      reason=f"{absent_osv} packages had lookup failures" if absent_osv else None),
        CoverageCheck(check="Malware reports (OSV MAL-*)", status="Ran",
                      count=len([e for e in osv_ev if e.data.get("is_malware")])),
        CoverageCheck(check="EPSS prioritization scores", status="Ran" if epss_kev_ev else "Not run",
                      count=len([e for e in epss_kev_ev if e.kind.value == "epss" and e.tier != EvidenceTier.ABSENT]),
                      reason=f"{absent_epss} CVEs had no EPSS data" if absent_epss else None),
        CoverageCheck(check="CISA Known Exploited Vulnerabilities", status="Ran",
                      count=len([e for e in epss_kev_ev if e.kind.value == "kev"])),
        CoverageCheck(check="License detection (lockfile + deps.dev)", status="Ran",
                      count=len(fetched_lic)),
        CoverageCheck(check="Registry metadata (npm, staleness/freshness)", status="Partial",
                      count=len(npm_times_map),
                      reason="Only fetched for direct dependencies and flagged packages (rate limit cap)"),
        CoverageCheck(check="Lookalike name heuristic", status="Ran",
                      count=len(build.packages)),
        CoverageCheck(check="Provenance / SLSA attestation", status="Not run",
                      reason="Not implemented in this version"),
        CoverageCheck(check="Release diff / version comparison", status="Not run",
                      reason="Not implemented in this version"),
        CoverageCheck(check="Reachability / source-use analysis", status="Not run",
                      reason="Package-level paths only. Function-level reachability not assessed."),
        CoverageCheck(check="Malware sandbox", status="Not run",
                      reason="Not implemented in this version"),
    ]


def _decisions_for_requirements(req_result, evidence, context, now) -> list[Decision]:
    """Generate simplified decisions for requirements.txt (no graph)."""
    from .models.decision import ExposureInfo
    decisions = []
    for pkg in req_result.packages:
        purl = pkg.purl
        node_ev = [e for e in evidence if e.subject == purl and not e.withdrawn]
        t2 = [e for e in node_ev if e.tier == EvidenceTier.T2]
        absent = [e for e in node_ev if e.tier == EvidenceTier.ABSENT]

        exposure = ExposureInfo(
            paths=[[f"(root) → {pkg.name}"]],
            scope="prod",
            scope_provenance="assumed (no edges in requirements.txt)",
            install_phase="unknown",
            scripts_enabled="assumed",
        )

        if absent and not t2:
            from .models.decision import Decision, Verdict, Urgency, Qualifier, ResponseClass, RemediationStep
            decisions.append(Decision(
                subject=purl, name=pkg.name, version=pkg.version,
                verdict=Verdict.CANNOT_ASSESS, urgency=Urgency.NONE, qualifier=Qualifier.UNKNOWN,
                exposure=exposure, evidence_ids=[e.id for e in node_ev],
                unrun_checks=["Paths unknown — requirements.txt adapter, direct dependencies only"],
                response=ResponseClass.CANNOT_ASSESS,
                response_steps=[RemediationStep(text="Generate a package-lock.json for full analysis.")],
                as_of=now, derivation=["R6 — requirements.txt adapter"],
                introduced_by=[], depth=1, is_direct=True,
                what="Paths unknown (requirements.txt, direct dependencies only)",
            ))
        elif t2:
            from .engine.decide import derive_decisions as _derive
            # Minimal graph-less decision
            from .models.decision import Decision, Verdict, Urgency, Qualifier, ResponseClass, RemediationStep
            decisions.append(Decision(
                subject=purl, name=pkg.name, version=pkg.version,
                verdict=Verdict.UPGRADE, urgency=Urgency.SCHEDULED, qualifier=Qualifier.ESTABLISHED,
                exposure=exposure, evidence_ids=[e.id for e in t2],
                unrun_checks=["Paths unknown (requirements.txt, no graph)"],
                response=ResponseClass.UPGRADE,
                response_steps=[RemediationStep(text=f"pip install {pkg.name}=={t2[0].data.get('fixed_version', '<check advisory>')}")],
                as_of=now, derivation=[f"R3 ← {t2[0].id}"],
                introduced_by=[], depth=1, is_direct=True,
                what=f"Advisory: {t2[0].data.get('vuln_id', '')}",
            ))
    return decisions


def _licenses_for_requirements(req_result, context) -> list[LicenseResult]:
    results = []
    for pkg in req_result.packages:
        status, rule_id, note = classify_license(None, context)
        results.append(LicenseResult(
            subject=pkg.purl, name=pkg.name, version=pkg.version,
            license_expr=None, license_status="CANNOT_ASSESS",
            rule_fired="LR7", introducing_paths=[[pkg.name]],
            note="License not available in requirements.txt — check PyPI",
        ))
    return results


def _requirements_coverage() -> list[CoverageCheck]:
    return [
        CoverageCheck(check="Vulnerability lookup (OSV)", status="Ran"),
        CoverageCheck(check="EPSS / CISA KEV", status="Ran"),
        CoverageCheck(check="License detection", status="Not supported",
                      reason="requirements.txt does not include license metadata"),
        CoverageCheck(check="Graph / paths", status="Not supported",
                      reason="requirements.txt provides no dependency edges — paths unknown"),
        CoverageCheck(check="Lookalike heuristic", status="Not run",
                      reason="Only npm packages in the popular_npm.json list"),
        CoverageCheck(check="Registry metadata", status="Not run",
                      reason="Only npm registry supported"),
        CoverageCheck(check="Reachability", status="Not run",
                      reason="Package-level paths only. Function-level reachability not assessed."),
    ]
