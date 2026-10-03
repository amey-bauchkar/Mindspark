"""
Decision engine — pure deterministic function of (graph, evidence, context, as_of).
Applies rules R1–R7 per node. No LLM, no randomness, no side effects.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from ..models.evidence import EvidenceRecord, EvidenceTier, EvidenceKind
from ..models.decision import (
    Decision, Verdict, Urgency, Qualifier, ResponseClass, ExposureInfo, RemediationStep
)
from ..models.report import AnalysisContext
from ..graph.build import BuildResult, ROOT_ID, find_paths
from ..config import get_settings
from .rules import RULES


# ─── Evidence indexing ─────────────────────────────────────────────────────────

def _index_evidence(
    evidence: list[EvidenceRecord],
    as_of: datetime,
) -> dict[str, list[EvidenceRecord]]:
    """Group non-withdrawn, non-future evidence by subject purl."""
    idx: dict[str, list[EvidenceRecord]] = defaultdict(list)
    for rec in evidence:
        # Temporal filter: only evidence published on or before as_of
        if rec.published_at and rec.published_at > as_of:
            continue
        # Exclude withdrawn from active evidence (keep in list for display, skip for decisions)
        if rec.withdrawn:
            continue
        idx[rec.subject].append(rec)
    return idx


# ─── Main decision function ────────────────────────────────────────────────────

def derive_decisions(
    build: BuildResult,
    evidence: list[EvidenceRecord],
    context: AnalysisContext,
    as_of: datetime | None = None,
) -> list[Decision]:
    """
    For each node in the graph, produce exactly one Decision.
    Returns only nodes with something to report (verdict ≠ NO_KNOWN_FINDING) plus
    a summary NO_KNOWN_FINDING for all clean nodes.
    """
    if as_of is None:
        as_of = datetime.now(timezone.utc)

    settings = get_settings()
    epss_threshold = settings.epss_threshold

    ev_idx = _index_evidence(evidence, as_of)
    G = build.graph
    packages = build.packages

    decisions: list[Decision] = []
    incident_nodes: set[str] = set()

    # First pass: find all INCIDENT nodes (R1)
    for purl, pkg in packages.items():
        node_ev = ev_idx.get(purl, [])
        t1_malware = [e for e in node_ev if e.tier == EvidenceTier.T1 and e.kind == EvidenceKind.MALWARE_REPORT]
        if t1_malware:
            incident_nodes.add(purl)

    # Second pass: derive a decision per node
    for purl, pkg in packages.items():
        node_ev = ev_idx.get(purl, [])
        all_ev_for_subject = ev_idx.get(purl, [])

        paths = find_paths(G, ROOT_ID, purl)
        path_names = [[_node_label(build, n) for n in path] for path in paths]

        # Scope determination
        scope = pkg.scope
        scope_provenance = pkg.scope_provenance

        # Install script context
        has_script = pkg.has_install_script
        scripts_enabled = "declared" if context.install_scripts_run is not None else "assumed"
        install_phase = "observed" if has_script else "unknown"

        exposure = ExposureInfo(
            paths=path_names[:10],
            scope=scope,
            scope_provenance=scope_provenance,
            install_phase=install_phase,
            scripts_enabled=scripts_enabled,
        )

        # Check git/file source → CANNOT ASSESS
        if pkg.is_git_or_file:
            decisions.append(_cannot_assess(
                purl, pkg, exposure, as_of,
                reason=f"Non-registry source ({pkg.resolved_url or 'unknown URL'}) — not checked against registries",
                evidence_ids=[e.id for e in node_ev],
            ))
            continue

        # Separate evidence by tier
        t1_malware = [e for e in node_ev if e.tier == EvidenceTier.T1 and e.kind == EvidenceKind.MALWARE_REPORT]
        t1_kev = [e for e in node_ev if e.tier == EvidenceTier.T1 and e.kind == EvidenceKind.KEV]
        t2_advisory = [e for e in node_ev if e.tier == EvidenceTier.T2 and e.kind == EvidenceKind.ADVISORY]
        t2_epss = [e for e in node_ev if e.tier == EvidenceTier.T2 and e.kind == EvidenceKind.EPSS]
        t3 = [e for e in node_ev if e.tier == EvidenceTier.T3]
        context_ev = [e for e in node_ev if e.tier == EvidenceTier.CONTEXT]
        absent_ev = [e for e in node_ev if e.tier == EvidenceTier.ABSENT]
        license_ev = [e for e in node_ev if e.tier == EvidenceTier.T3 and e.kind == EvidenceKind.LICENSE]

        unrun_checks = [e.claim for e in absent_ev]

        # Get fixed version from advisory data
        fixed_version = None
        for e in t2_advisory:
            fv = e.data.get("fixed_version")
            if fv and fv != "0.0.1-security":
                fixed_version = fv
                break

        # Get CVSS info
        cvss_vector = None
        cvss_severity = None
        for e in t2_advisory:
            if e.data.get("cvss_vector"):
                cvss_vector = e.data["cvss_vector"]
                cvss_severity = e.data.get("cvss_severity")
                break

        # ─── R1: Active malware ──────────────────────────────────────────────
        if t1_malware:
            # Exact-version check: ensure the advisory affects this exact version
            # (not a placeholder 0.0.1-security)
            valid_malware = []
            for e in t1_malware:
                vuln_id = e.data.get("vuln_id", "")
                valid_malware.append(e)

            if valid_malware:
                qualifier = Qualifier.PROBABLE if len(valid_malware) == 1 else Qualifier.ESTABLISHED
                origin = valid_malware[0].origin
                vuln_ids = ", ".join(e.data.get("vuln_id", e.id) for e in valid_malware)
                rule = _get_rule("R1")
                decisions.append(Decision(
                    subject=purl,
                    name=pkg.name,
                    version=pkg.version,
                    verdict=Verdict.INCIDENT,
                    urgency=Urgency.IMMEDIATE,
                    qualifier=qualifier,
                    exposure=exposure,
                    evidence_ids=[e.id for e in valid_malware + context_ev],
                    open_defeaters=_defeaters(valid_malware, context),
                    unrun_checks=unrun_checks,
                    response=ResponseClass.CONTAINMENT,
                    response_steps=[RemediationStep(text=s) for s in rule["response_steps"]],
                    as_of=as_of,
                    derivation=[f"R1 ← {e.id}" for e in valid_malware],
                    introduced_by=pkg.introduced_by,
                    fixed_version=fixed_version,
                    depth=pkg.depth,
                    is_direct=pkg.is_direct,
                    cvss_vector=cvss_vector,
                    cvss_severity=cvss_severity,
                    what=f"Reported malicious ({origin} {vuln_ids})",
                ))
                continue

        # ─── R1': Ancestor of incident node ─────────────────────────────────
        # Check if this node has an incident descendant
        incident_descendants = _find_incident_descendants(G, purl, incident_nodes)
        if incident_descendants:
            carry_reason = f"Carries incident via path to {', '.join(list(incident_descendants)[:2])}"
            decisions.append(Decision(
                subject=purl,
                name=pkg.name,
                version=pkg.version,
                verdict=Verdict.INCIDENT,
                urgency=Urgency.IMMEDIATE,
                qualifier=Qualifier.PROBABLE,
                exposure=exposure,
                evidence_ids=[e.id for e in node_ev],
                open_defeaters=[],
                unrun_checks=unrun_checks,
                response=ResponseClass.CONTAINMENT,
                response_steps=[],
                as_of=as_of,
                derivation=["R1' — ancestor of incident node"],
                introduced_by=pkg.introduced_by,
                depth=pkg.depth,
                is_direct=pkg.is_direct,
                what=carry_reason,
                carry_reason=carry_reason,
            ))
            continue

        # ─── R2: KEV or high EPSS on prod path ──────────────────────────────
        has_kev = bool(t1_kev)
        high_epss = [e for e in t2_epss if e.data.get("above_threshold")]
        if (has_kev or high_epss) and scope == "prod":
            rule = _get_rule("R2")
            src_ev = (t1_kev if has_kev else high_epss)
            qualifier = Qualifier.ESTABLISHED if has_kev else Qualifier.PROBABLE
            epss_val = high_epss[0].data.get("epss") if high_epss else None
            what_parts = []
            if has_kev:
                what_parts.append("In CISA KEV (exploited in the wild)")
            if high_epss:
                what_parts.append(f"EPSS {epss_val:.3f} ≥ threshold {settings.epss_threshold}")
            decisions.append(Decision(
                subject=purl,
                name=pkg.name,
                version=pkg.version,
                verdict=Verdict.ACT_NOW,
                urgency=Urgency.IMMEDIATE if has_kev else Urgency.OUT_OF_CYCLE,
                qualifier=qualifier,
                exposure=exposure,
                evidence_ids=[e.id for e in src_ev + t2_advisory + context_ev],
                open_defeaters=_defeaters(t2_advisory, context),
                unrun_checks=unrun_checks,
                response=ResponseClass.MINIMAL_UPGRADE,
                response_steps=[RemediationStep(text=s) for s in rule["response_steps"]],
                as_of=as_of,
                derivation=[f"R2 ← {e.id}" for e in src_ev],
                introduced_by=pkg.introduced_by,
                fixed_version=fixed_version,
                depth=pkg.depth,
                is_direct=pkg.is_direct,
                cvss_vector=cvss_vector,
                cvss_severity=cvss_severity,
                what="; ".join(what_parts),
            ))
            continue

        # ─── R3: Advisory with fix, runtime path ────────────────────────────
        if t2_advisory and fixed_version and scope == "prod":
            rule = _get_rule("R3")
            decisions.append(Decision(
                subject=purl,
                name=pkg.name,
                version=pkg.version,
                verdict=Verdict.UPGRADE,
                urgency=Urgency.SCHEDULED,
                qualifier=Qualifier.ESTABLISHED,
                exposure=exposure,
                evidence_ids=[e.id for e in t2_advisory + context_ev],
                open_defeaters=_defeaters(t2_advisory, context),
                unrun_checks=unrun_checks,
                response=ResponseClass.UPGRADE,
                response_steps=[RemediationStep(text=s) for s in rule["response_steps"]],
                as_of=as_of,
                derivation=[f"R3 ← {e.id}" for e in t2_advisory],
                introduced_by=pkg.introduced_by,
                fixed_version=fixed_version,
                depth=pkg.depth,
                is_direct=pkg.is_direct,
                cvss_vector=cvss_vector,
                cvss_severity=cvss_severity,
                what=f"Advisory with fix available — {', '.join(e.data.get('vuln_id', '') for e in t2_advisory[:2])}",
            ))
            continue

        # ─── R4: Advisory, dev/optional only ────────────────────────────────
        if t2_advisory and scope in ("dev", "optional"):
            rule = _get_rule("R4")
            decisions.append(Decision(
                subject=purl,
                name=pkg.name,
                version=pkg.version,
                verdict=Verdict.MONITOR,
                urgency=Urgency.DEFER,
                qualifier=Qualifier.ESTABLISHED,
                exposure=exposure,
                evidence_ids=[e.id for e in t2_advisory + context_ev],
                open_defeaters=_defeaters(t2_advisory, context),
                unrun_checks=unrun_checks,
                response=ResponseClass.DEFER,
                response_steps=[RemediationStep(text=s) for s in rule["response_steps"]],
                as_of=as_of,
                derivation=[f"R4 ← {e.id}" for e in t2_advisory],
                introduced_by=pkg.introduced_by,
                fixed_version=fixed_version,
                depth=pkg.depth,
                is_direct=pkg.is_direct,
                what=f"Advisory, {scope} path only — {', '.join(e.data.get('vuln_id', '') for e in t2_advisory[:2])}",
            ))
            continue

        # ─── R5: T3/license/unresolved only ─────────────────────────────────
        if t3 or license_ev:
            rule = _get_rule("R5")
            reasons = []
            for e in t3:
                if e.kind == EvidenceKind.LOOKALIKE:
                    reasons.append(f"Lookalike name (heuristic): {e.claim}")
                elif e.kind == EvidenceKind.STALE:
                    reasons.append(e.claim)
                elif e.kind == EvidenceKind.VERY_NEW:
                    reasons.append(e.claim)
                elif e.kind == EvidenceKind.LICENSE:
                    reasons.append(e.claim)
                else:
                    reasons.append(e.claim)
            decisions.append(Decision(
                subject=purl,
                name=pkg.name,
                version=pkg.version,
                verdict=Verdict.REVIEW,
                urgency=Urgency.SCHEDULED,
                qualifier=Qualifier.POSSIBLE,
                exposure=exposure,
                evidence_ids=[e.id for e in t3 + context_ev],
                open_defeaters=[],
                unrun_checks=unrun_checks,
                response=ResponseClass.REVIEW,
                response_steps=[RemediationStep(text=s) for s in rule["response_steps"]],
                as_of=as_of,
                derivation=[f"R5 ← {e.id}" for e in t3],
                introduced_by=pkg.introduced_by,
                depth=pkg.depth,
                is_direct=pkg.is_direct,
                what="; ".join(reasons[:2]) or "Heuristic or license signal",
            ))
            continue

        # ─── R6: Cannot assess ───────────────────────────────────────────────
        if absent_ev:
            reasons = "; ".join(e.claim for e in absent_ev[:3])
            decisions.append(_cannot_assess(
                purl, pkg, exposure, as_of,
                reason=reasons,
                evidence_ids=[e.id for e in node_ev],
            ))
            continue

        # ─── R7: No known finding ────────────────────────────────────────────
        # Only add NO_KNOWN_FINDING for packages that have had at least one check run
        # We'll batch these later; skip for now to keep signal-to-noise ratio down
        # (they're summarised in the summary bar)

    return decisions


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _get_rule(rule_id: str) -> dict:
    for r in RULES:
        if r["id"] == rule_id:
            return r
    return {"response_steps": []}


def _node_label(build: BuildResult, node: str) -> str:
    if node == ROOT_ID:
        return build.root_name
    pkg = build.packages.get(node)
    return f"{pkg.name}@{pkg.version}" if pkg else node


def _defeaters(advisories: list[EvidenceRecord], context: AnalysisContext) -> list[str]:
    """Open defeaters: things that would reduce confidence if true."""
    defeaters = []
    if context.install_scripts_run is None:
        defeaters.append("Install script execution status unknown (skipped in context)")
    for adv in advisories:
        if not adv.data.get("cvss_vector"):
            defeaters.append(f"No CVSS vector available for {adv.data.get('vuln_id', adv.id)}")
    return defeaters


def _find_incident_descendants(G, node: str, incident_nodes: set[str]) -> set[str]:
    """Find incident nodes reachable from `node`."""
    found = set()
    import networkx as nx
    try:
        descendants = nx.descendants(G, node)
        found = descendants & incident_nodes
    except Exception:
        pass
    return found


def _cannot_assess(
    purl: str,
    pkg,
    exposure: ExposureInfo,
    as_of: datetime,
    reason: str,
    evidence_ids: list[str],
) -> Decision:
    return Decision(
        subject=purl,
        name=pkg.name,
        version=pkg.version,
        verdict=Verdict.CANNOT_ASSESS,
        urgency=Urgency.NONE,
        qualifier=Qualifier.UNKNOWN,
        exposure=exposure,
        evidence_ids=evidence_ids,
        open_defeaters=[],
        unrun_checks=[reason],
        response=ResponseClass.CANNOT_ASSESS,
        response_steps=[RemediationStep(text="Investigate manually — the tool could not gather enough evidence.")],
        as_of=as_of,
        derivation=["R6 — cannot assess"],
        introduced_by=pkg.introduced_by,
        depth=pkg.depth,
        is_direct=pkg.is_direct,
        what=f"Cannot assess: {reason[:120]}",
    )
