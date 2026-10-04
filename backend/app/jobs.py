"""
Analysis job orchestrator — coordinates parsing, graph building, evidence gathering,
signals, license checks, and decision derivation.
Runs as a background task; updates progress state in memory.
"""
from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable

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
from .providers.cache import save_report, save_snapshot
from .parsers.snapshot import snapshot_from_parse
from .config import get_settings


logger = logging.getLogger(__name__)

# In-memory progress state (no DB needed for transient progress)
_progress: dict[str, dict] = {}


@dataclass
class EvidenceProviders:
    """Evidence sources used by the npm pipeline. Defaults are the live providers."""
    osv_batch: Callable[[list[str]], Awaitable[list[EvidenceRecord]]]
    epss: Callable[[list[str]], Awaitable[dict[str, float]]]
    kev: Callable[[], Awaitable[set[str]]]
    licenses: Callable[[list[tuple[str, str]]], Awaitable[dict]]
    npm_times: Callable[[list[tuple[str, str]]], Awaitable[dict]]


def default_providers() -> EvidenceProviders:
    # Resolved at call time (not import time) so the module-level provider functions stay patchable.
    return EvidenceProviders(
        osv_batch=fetch_osv_batch,
        epss=fetch_epss,
        kev=fetch_kev,
        licenses=bulk_fetch_licenses,
        npm_times=bulk_fetch_npm_times,
    )


@dataclass
class NpmAnalysis:
    report: Report
    build: BuildResult


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
            all_cves = sorted({a for e in osv_evidence for a in e.data.get("cve_aliases", [])})
            epss_scores, kev_set = await asyncio.gather(
                fetch_epss(all_cves), fetch_kev()
            )
            epss_kev_records = build_epss_kev_records(osv_evidence, epss_scores, kev_set, settings.epss_threshold)
            evidence.extend(epss_kev_records)

            _set_progress(report_id, "Deriving decisions", 80)
            # Same decision engine as npm, on a flat graph (pins only, no edges, scope assumed prod)
            decisions = decisions_for_requirements(req_result.packages, evidence, _parse_context(context_data), now)

            # License results
            licenses = _licenses_for_requirements(req_result, _parse_context(context_data))

            # Coverage
            coverage = _requirements_coverage(osv_evidence, epss_kev_records, len(purls))

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
        if settings.watch_enabled:
            _store_snapshot(report_id, parse, filename, context_data)
        analysis = await analyze_npm_lock(
            report_id, parse, filename, context_data,
            progress=lambda stage, pct: _set_progress(report_id, stage, pct),
        )
        save_report(report_id, analysis.report.model_dump())
        _set_done(report_id)

    except Exception as exc:
        # Log the failure class and report id only — never the uploaded file contents.
        logger.warning("analysis %s failed: %s", report_id, type(exc).__name__,
                       exc_info=not isinstance(exc, ValueError))
        _set_error(report_id, "analysis", str(exc)[:300])
        raise


async def analyze_npm_lock(
    report_id: str,
    parse: ParseResult,
    filename: str,
    context_data: dict,
    *,
    as_of: datetime | None = None,
    providers: EvidenceProviders | None = None,
    data_badge: str | None = None,
    progress: Callable[[str, int], None] | None = None,
) -> NpmAnalysis:
    """
    Graph → evidence → signals → decisions → report for an already-parsed npm lockfile.
    Used by `run_analysis` and by Warrant Watch re-analysis.

    `as_of` (default: now) is the evidence cut-off for decisions and the summary;
    `created_at` is always the wall-clock generation time.
    """
    settings = get_settings()
    providers = providers or default_providers()
    progress = progress or (lambda stage, pct: None)
    created_at = datetime.now(timezone.utc)
    now = as_of or created_at
    evidence: list[EvidenceRecord] = []
    warnings: list[str] = list(parse.warnings)
    ecosystem = "npm"
    data_badge = data_badge or ("RECORDED" if settings.offline_fixtures else "LIVE")

    progress(f"Rebuilding graph ({len(parse.packages)} packages)", 10)

    # CPU-bound stages run in a worker thread so the API (status polling, Warrant Watch
    # scheduler) stays responsive during large analyses.
    build = await asyncio.to_thread(build_graph, parse)
    warnings = list(build.warnings)  # Parser warnings + cycle handling (incl. any cycles left in place)

    purls = list(build.packages.keys())
    progress(f"Querying OSV ({len(purls)} packages)", 20)

    # ── Stage 2: OSV ──────────────────────────────────────────────────────
    osv_evidence = await providers.osv_batch(purls)
    evidence.extend(osv_evidence)

    # ── Stage 3: EPSS + KEV ───────────────────────────────────────────────
    progress("Fetching EPSS and CISA KEV", 35)
    all_cves = sorted({a for e in osv_evidence for a in e.data.get("cve_aliases", [])})
    epss_scores, kev_set = await asyncio.gather(
        providers.epss(all_cves), providers.kev()
    )
    epss_kev_records = build_epss_kev_records(osv_evidence, epss_scores, kev_set, settings.epss_threshold)
    evidence.extend(epss_kev_records)

    # ── Stage 4: Licenses via deps.dev for missing ────────────────────────
    progress("Checking licenses", 50)
    missing_license_pkgs = [
        (pkg.name, pkg.version)
        for pkg in build.packages.values()
        if not pkg.license
    ]
    fetched_licenses: dict = {}
    if missing_license_pkgs:
        fetched_licenses = await providers.licenses(missing_license_pkgs[:100])  # Cap at 100

    # Fill in fetched licenses
    for (name, version), lic in fetched_licenses.items():
        purl = f"pkg:npm/{name.replace('@', '%40').replace('/', '%2F')}@{version}"
        if purl in build.packages and not build.packages[purl].license:
            build.packages[purl].license = lic

    # ── Stage 5: Registry metadata (for direct deps + flagged packages) ───
    progress("Fetching registry metadata", 60)
    packages_needing_registry = [
        (pkg.name, pkg.version)
        for pkg in build.packages.values()
        if pkg.is_direct
    ]
    npm_times_map = await providers.npm_times(packages_needing_registry[:settings.registry_fetch_cap])

    # ── Stage 6: Signals ──────────────────────────────────────────────────
    progress("Running signals", 70)
    evidence.extend(await asyncio.to_thread(_run_signals, build, npm_times_map, now))

    # ── Stage 7–10: Decisions, licenses, graph output, coverage ───────────
    progress("Deriving decisions", 80)
    context = _parse_context(context_data)
    decisions, licenses, graph_data, coverage = await asyncio.to_thread(
        _decide_and_assemble, build, evidence, context, now, osv_evidence, epss_kev_records,
        fetched_licenses, npm_times_map, progress,
    )

    # ── Summary ───────────────────────────────────────────────────────────
    direct_count = sum(1 for p in build.packages.values() if p.is_direct)
    summary = _build_summary(decisions, len(purls), direct_count, now, ecosystem, data_badge)

    report = Report(
        id=report_id,
        created_at=created_at,
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
    return NpmAnalysis(report=report, build=build)


def _run_signals(build: BuildResult, npm_times_map: dict, now: datetime) -> list[EvidenceRecord]:
    """Install-script, lookalike and registry signals for every package (pure, CPU-bound)."""
    evidence: list[EvidenceRecord] = []
    for purl, pkg in build.packages.items():
        evidence.extend(check_install_script(pkg.name, pkg.version, pkg.has_install_script))
        evidence.extend(check_lookalike(pkg.name, pkg.version))
        times = npm_times_map.get(pkg.name)
        if times:
            evidence.extend(check_staleness(pkg.name, pkg.version, times))
        elif pkg.is_direct:
            # ABSENT: registry metadata missing — say why
            claim = (
                "Registry metadata unavailable — the npm registry lookup failed or the package is not public"
                if pkg.name in npm_times_map
                else f"Registry metadata not fetched — only the first {get_settings().registry_fetch_cap} direct dependencies are looked up"
            )
            evidence.append(EvidenceRecord(
                id=f"REG-MISS-{pkg.name[:15].replace('/', '-').replace('@', '')}",
                tier=EvidenceTier.ABSENT,
                source="npm-registry",
                origin="npm registry",
                kind=EvidenceKind.OTHER,
                subject=purl,
                claim=claim,
                retrieved_at=now,
            ))
    return evidence


def _policy_evidence(build: BuildResult, context: AnalysisContext, now: datetime) -> list[EvidenceRecord]:
    """Corporate policy license bans and custom banned dependencies."""
    evidence: list[EvidenceRecord] = []
    if not (context.company_policy or context.banned_dependencies):
        return evidence
    for purl, pkg in build.packages.items():
        lic_status, lic_rule, lic_note = classify_license(pkg.license, context, package_name=pkg.name, package_version=pkg.version)
        if lic_status == "CONFLICT" and lic_rule in ("LR8", "LR-BANNED-PKG"):
            evidence.append(EvidenceRecord(
                id=f"BAN-{pkg.name[:18].replace('/', '-').replace('@', '')}",
                tier=EvidenceTier.T2,
                source="corporate-policy",
                origin="Corporate Policy Enforcement",
                kind=EvidenceKind.BANNED_DEPENDENCY,
                subject=purl,
                claim=lic_note,
                retrieved_at=now,
                data={"policy": context.company_policy, "rule": lic_rule, "license": pkg.license, "package": pkg.name}
            ))
    return evidence


def enrich_remediation(decisions: list[Decision], ecosystem: str = "npm") -> None:
    """Attach copyable remediation commands to decisions (containment checklist / fix commands)."""
    for dec in decisions:
        if dec.response in (ResponseClass.CONTAINMENT,):
            dec.response_steps = format_containment_checklist(dec, ecosystem=ecosystem)
        elif dec.fixed_version:
            dec.response_steps = build_fix_commands(dec, ecosystem=ecosystem)


def _decide_and_assemble(build, evidence, context, now, osv_evidence, epss_kev_records,
                         fetched_licenses, npm_times_map, progress):
    evidence.extend(_policy_evidence(build, context, now))
    decisions = derive_decisions(build, evidence, context, as_of=now)
    enrich_remediation(decisions)
    progress("Classifying licenses", 88)
    licenses = _classify_all_licenses(build, context, decisions)
    progress("Building graph", 93)
    graph_data = _build_graph_output(build, decisions)
    coverage = _build_coverage(build, evidence, osv_evidence, epss_kev_records, fetched_licenses, npm_times_map)
    return decisions, licenses, graph_data, coverage


def _store_snapshot(report_id: str, parse: ParseResult, filename: str, context_data: dict) -> None:
    """Persist the exact analysed dependency state so monitoring can be enabled later."""
    try:
        save_snapshot(report_id, snapshot_from_parse(parse, filename, context_data))
    except Exception:  # Never let monitoring bookkeeping break an analysis
        logger.exception("Could not store dependency snapshot for %s", report_id)


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

    company_policy = data.get("company_policy")
    if company_policy and str(company_policy).strip().lower() in ("none", "", "null"):
        company_policy = None
    elif company_policy:
        company_policy = str(company_policy).strip()

    banned_deps_raw = data.get("banned_dependencies")
    if isinstance(banned_deps_raw, str):
        banned_deps = [x.strip() for x in banned_deps_raw.split(",") if x.strip()]
    elif isinstance(banned_deps_raw, list):
        banned_deps = [str(x).strip() for x in banned_deps_raw if str(x).strip()]
    else:
        banned_deps = []

    return AnalysisContext(
        distribution_mode=dist,
        project_license=proj_lic,
        install_scripts_run=scripts,
        company_policy=company_policy,
        banned_dependencies=banned_deps,
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
    from .graph.build import node_paths
    results = []
    for purl, pkg in build.packages.items():
        lic = pkg.license
        status, rule_id, note = classify_license(lic, context, package_name=pkg.name, package_version=pkg.version)
        paths = node_paths(build, purl, max_paths=3)
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


def _security_coverage(osv_ev, epss_kev_ev, total_pkgs: int) -> list[CoverageCheck]:
    """OSV / malware / EPSS / KEV rows — shared by the npm and requirements.txt adapters."""
    not_checked = {e.subject for e in osv_ev if e.tier == EvidenceTier.ABSENT}
    found = [e for e in osv_ev if e.tier != EvidenceTier.ABSENT]
    active = [e for e in found if not e.withdrawn]
    withdrawn = len(found) - len(active)
    malware_findings = len({e.subject for e in active if e.data.get("is_malware")})
    vuln_advisories = len([e for e in active if not e.data.get("is_malware")])
    all_cves = sorted({a for e in found for a in e.data.get("cve_aliases", [])})
    epss_missing = {e.data.get("cve") for e in epss_kev_ev if e.id.startswith("EPSS-MISS")}
    kev_unchecked = {e.data.get("cve") for e in epss_kev_ev if e.id.startswith("KEV-MISS")}
    kev_hits = len({e.data.get("cve") for e in epss_kev_ev if e.kind.value == "kev" and e.tier == EvidenceTier.T1})

    checked = total_pkgs - len(not_checked)
    withdrawn_note = f"; {withdrawn} withdrawn record(s) shown but not counted" if withdrawn else ""
    if not_checked:
        status = "Not run" if checked <= 0 else "Partial"
        osv_reason = (f"{len(not_checked)} of {total_pkgs} packages could not be checked (see each package's "
                      f"'not checked' list); {vuln_advisories} active advisories found in the rest{withdrawn_note}")
        malware_reason = (f"{checked} of {total_pkgs} packages checked against OSV malware reports "
                          f"({malware_findings} reported malicious); {len(not_checked)} not checked")
    else:
        status = "Ran"
        osv_reason = (f"Queried OSV for all {total_pkgs} packages ({vuln_advisories} active vulnerability "
                      f"advisories found{withdrawn_note})")
        malware_reason = (f"All {total_pkgs} packages checked against OSV malware reports "
                          f"({malware_findings} reported malicious)")

    if not all_cves:
        epss = CoverageCheck(check="EPSS prioritization scores", status="Ran", count=0,
                             reason="No CVE aliases among the advisories found — nothing to score")
        kev = CoverageCheck(check="CISA Known Exploited Vulnerabilities", status="Ran", count=0,
                            reason="No CVE aliases among the advisories found — nothing to look up")
    else:
        epss = CoverageCheck(
            check="EPSS prioritization scores",
            status="Partial" if epss_missing else "Ran",
            count=len(all_cves),
            reason=(f"Scored {len(all_cves) - len(epss_missing)} of {len(all_cves)} CVEs against FIRST EPSS "
                    f"({len(epss_missing)} without a score)") if epss_missing
            else f"Scored all {len(all_cves)} CVEs against FIRST EPSS",
        )
        if kev_unchecked:
            kev = CoverageCheck(check="CISA Known Exploited Vulnerabilities", status="Not run", count=len(all_cves),
                                reason=f"CISA KEV catalogue unavailable — exploitation status of {len(kev_unchecked)} "
                                       "CVEs not checked (not treated as 'not exploited')")
        else:
            kev = CoverageCheck(check="CISA Known Exploited Vulnerabilities", status="Ran", count=len(all_cves),
                                reason=f"Checked {len(all_cves)} CVEs against the CISA KEV catalogue "
                                       f"({kev_hits} known exploited)")
    return [
        CoverageCheck(check="Vulnerability lookup (OSV)", status=status, count=total_pkgs, reason=osv_reason),
        CoverageCheck(check="Malware reports (OSV MAL-*)", status=status, count=total_pkgs, reason=malware_reason),
        epss,
        kev,
    ]


def _build_coverage(build, evidence, osv_ev, epss_kev_ev, fetched_lic, npm_times_map) -> list[CoverageCheck]:
    from .signals.lookalike import popular_count

    total_pkgs = len(build.packages)
    pkgs_with_license = sum(1 for p in build.packages.values() if p.license)
    fetched_ok = sum(1 for v in fetched_lic.values() if v)

    # License detection
    if fetched_lic:
        lic_reason = (f"{pkgs_with_license}/{total_pkgs} licenses identified "
                      f"({fetched_ok} via deps.dev fallback, {pkgs_with_license - fetched_ok} from lockfile manifests)")
    else:
        lic_reason = f"{pkgs_with_license}/{total_pkgs} package licenses identified from lockfile manifests"

    # Registry metadata (direct dependencies only, capped)
    direct = sum(1 for p in build.packages.values() if p.is_direct)
    reg_ok = sum(1 for v in npm_times_map.values() if v)
    reg_reason = (f"Publish times fetched for {reg_ok} of {direct} direct dependencies "
                  f"(direct dependencies only, cap {get_settings().registry_fetch_cap}); transitive packages are not checked")

    popular = popular_count()
    return [
        *_security_coverage(osv_ev, epss_kev_ev, total_pkgs),
        CoverageCheck(check="License detection (lockfile + deps.dev)", status="Ran",
                      count=pkgs_with_license, reason=lic_reason),
        CoverageCheck(check="Registry metadata (npm, staleness/freshness)", status="Partial",
                      count=reg_ok, reason=reg_reason),
        CoverageCheck(check="Lookalike name heuristic", status="Ran" if popular else "Not run",
                      count=total_pkgs if popular else 0,
                      reason=(f"Compared all {total_pkgs} package names against {popular} popular npm packages "
                              "(edit distance ≤ 1, scope imitation)") if popular
                      else "Popular-package list unavailable — heuristic not run"),
        CoverageCheck(check="Provenance / SLSA attestation", status="Not run",
                      reason="Not implemented in this version"),
        CoverageCheck(check="Release diff / version comparison", status="Not run",
                      reason="Not implemented in this version"),
        CoverageCheck(check="Reachability / source-use analysis", status="Not run",
                      reason="Package-level paths only. Function-level reachability not assessed."),
        CoverageCheck(check="Malware sandbox", status="Not run",
                      reason="Not implemented in this version"),
    ]


REQUIREMENTS_PATH_NOTE = "Dependency paths unknown — requirements.txt lists direct pins only (scope assumed prod)"


def requirements_build(packages) -> BuildResult:
    """Flat graph for requirements.txt pins: every pin is a direct, production dependency."""
    import networkx as nx
    from .graph.build import GraphPackage

    G = nx.DiGraph()
    G.add_node(ROOT_ID, label="requirements.txt", is_root=True)
    graph_packages: dict[str, GraphPackage] = {}
    for pkg in packages:
        if pkg.purl in graph_packages:
            continue
        gp = GraphPackage(
            purl=pkg.purl, name=pkg.name, version=pkg.version, scope="prod",
            scope_provenance="assumed (requirements.txt has no scopes or edges)", depth=1, is_direct=True,
            has_install_script=False, is_git_or_file=False, license=None, resolved_url=None,
            introduced_by=[ROOT_ID],
        )
        graph_packages[pkg.purl] = gp
        G.add_node(pkg.purl, **gp.__dict__)
        G.add_edge(ROOT_ID, pkg.purl, requirement=None, scope="prod")
    return BuildResult(graph=G, packages=graph_packages, root_purl="requirements.txt", root_name="requirements.txt")


def decisions_for_requirements(packages, evidence, context, now) -> list[Decision]:
    """requirements.txt decisions from the standard engine (R1–R7) with pip remediation."""
    decisions = derive_decisions(requirements_build(packages), evidence, context, as_of=now)
    enrich_remediation(decisions, ecosystem="pypi")
    for dec in decisions:
        if REQUIREMENTS_PATH_NOTE not in dec.unrun_checks:
            dec.unrun_checks.append(REQUIREMENTS_PATH_NOTE)
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


def _requirements_coverage(osv_ev, epss_kev_ev, total: int) -> list[CoverageCheck]:
    return [
        *_security_coverage(osv_ev, epss_kev_ev, total),
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
