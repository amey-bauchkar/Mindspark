"""Report routes — GET/POST /api/reports/{id}"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Query, UploadFile, File
from fastapi.responses import Response

import asyncio
import re

from ..config import get_settings
from ..jobs import get_progress
from ..providers.cache import load_report, save_report
from ..security import MAX_UPLOAD_BYTES, validate_json_depth
from ..engine.decide import derive_decisions
from ..engine.narrate import verify_claim, SYNTHETIC_CORRUPTED_CLAIM
from ..engine.temporal import AsOfUnavailable, rederive_as_of
from ..models.evidence import EvidenceRecord
from ..models.decision import Decision
from ..models.report import Report

_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+_~-]{0,63}$")
_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

router = APIRouter(prefix="/api")


@router.post("/reports/import")
async def import_report(file: UploadFile = File(...)):
    """Import a previously exported JSON report to view it without re-running analysis."""
    raw = await file.read()
    if len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, "Report file exceeds maximum allowed size (5 MB)")
    try:
        report_data = json.loads(raw.decode("utf-8", errors="replace"))
    except Exception:
        raise HTTPException(400, "Could not parse file as JSON")

    if not isinstance(report_data, dict) or "summary" not in report_data or "decisions" not in report_data:
        raise HTTPException(400, "File is not a valid Warrant report structure")
    try:
        validate_json_depth(report_data, max_depth=40)
        report = Report.model_validate(report_data)
    except ValueError as exc:
        raise HTTPException(400, f"File is not a valid Warrant report structure ({type(exc).__name__})")

    # Never let an imported file overwrite a stored report (e.g. a monitored baseline):
    # keep the exported id only if it is a well-formed, unused report id.
    report_id = report.id if _UUID_RE.match(report.id or "") and load_report(report.id) is None else str(uuid.uuid4())
    stored = json.loads(json.dumps(report.model_dump(), default=str))
    stored["id"] = report_id
    stored["meta"].pop("watch", None)  # Monitoring provenance belongs to the instance that produced it
    stored["meta"]["imported"] = {
        "imported_at": datetime.now(timezone.utc).isoformat(),
        "original_id": report.id,
        "note": "Imported from a file: shown as provided, not re-verified against providers.",
    }
    save_report(report_id, stored)
    return {"report_id": report_id}



@router.get("/reports/{report_id}/status")
async def report_status(report_id: str):
    progress = get_progress(report_id)
    if progress is None:
        # Check if report exists in DB
        report = load_report(report_id)
        if report:
            return {"stage": "done", "progress": 100, "partial": False}
        raise HTTPException(404, "Report not found")
    return progress


@router.get("/reports/{report_id}")
async def get_report(report_id: str, as_of: str | None = Query(default=None)):
    data = load_report(report_id)
    if data is None:
        raise HTTPException(404, "Report not found or expired (24 h retention)")

    if as_of:
        # Re-derive decisions from the stored graph + evidence active at as_of — no network calls
        try:
            as_of_dt = datetime.fromisoformat(as_of.strip().replace("Z", "+00:00"))
        except ValueError:
            raise HTTPException(400, "Invalid as_of datetime format (use ISO 8601)")
        if as_of_dt.tzinfo is None:
            as_of_dt = as_of_dt.replace(tzinfo=timezone.utc)
        try:
            data = await asyncio.to_thread(rederive_as_of, data, as_of_dt)
        except AsOfUnavailable as exc:
            raise HTTPException(422, str(exc))

    return data


@router.post("/reports/{report_id}/context")
async def update_context(report_id: str, body: dict):
    """Re-derive decisions with updated context — no re-fetch."""
    data = load_report(report_id)
    if data is None:
        raise HTTPException(404, "Report not found")

    from ..jobs import _parse_context
    from ..graph.build import BuildResult
    import networkx as nx

    # We can't easily rebuild the graph from stored data, so we re-derive licenses only
    # Full re-derive would require storing the parsed graph, which is future work
    # For now: update context in the report and re-classify licenses
    new_context = _parse_context(body)
    data["context"] = new_context.model_dump()

    # Re-classify licenses with new context
    from ..licenses.rules import classify_license
    for lic in data.get("licenses", []):
        status, rule_id, note = classify_license(
            lic.get("license_expr"),
            new_context,
            package_name=lic.get("name"),
            package_version=lic.get("version"),
        )
        lic["license_status"] = status
        lic["rule_fired"] = rule_id
        lic["note"] = note

    # Update license summary counts in summary
    conflict = sum(1 for l in data.get("licenses", []) if l.get("license_status") == "CONFLICT")
    review = sum(1 for l in data.get("licenses", []) if l.get("license_status") == "REVIEW")

    save_report(report_id, data)
    return data


@router.post("/reports/{report_id}/simulate-fix")
async def simulate_fix(report_id: str, body: dict):
    """
    Simulate upgrading one package: look the target version up in OSV / EPSS / CISA KEV and run
    the SAME decision rules on it, keeping the package's position (scope, directness) in the graph.
    A lookup that cannot run makes the result CANNOT_ASSESS — never a clean result.
    """
    from ..graph.build import BuildResult, GraphPackage, ROOT_ID
    from ..models.report import AnalysisContext
    from ..providers.epss import build_epss_kev_records, fetch_epss, fetch_kev
    from ..providers.health import collect_provider_issues
    from ..providers.osv import fetch_osv_batch
    import networkx as nx

    data = load_report(report_id)
    if data is None:
        raise HTTPException(404, "Report not found")

    subject = body.get("subject")
    to_version = str(body.get("to_version") or "").strip()
    if not isinstance(subject, str) or not subject or not to_version:
        raise HTTPException(400, "Provide subject (purl) and to_version")
    if not _VERSION_RE.match(to_version):
        raise HTTPException(400, "to_version is not a valid package version")

    original = next((d for d in data.get("decisions", []) if d.get("subject") == subject), None)
    if not original:
        raise HTTPException(404, f"No decision found for {subject}")

    name = str(original.get("name", ""))
    if subject.startswith("pkg:pypi/"):
        new_purl = f"pkg:pypi/{name.lower()}@{to_version}"
    else:
        new_purl = f"pkg:npm/{name.replace('@', '%40').replace('/', '%2F')}@{to_version}"

    with collect_provider_issues() as issues:
        osv_evidence = await fetch_osv_batch([new_purl])
        cves = sorted({a for e in osv_evidence for a in e.data.get("cve_aliases", [])})
        epss_scores, kev_set = await asyncio.gather(fetch_epss(cves), fetch_kev())
    evidence = osv_evidence + build_epss_kev_records(osv_evidence, epss_scores, kev_set, get_settings().epss_threshold)

    exposure = original.get("exposure") or {}
    pkg = GraphPackage(
        purl=new_purl, name=name, version=to_version, scope=exposure.get("scope") or "prod",
        scope_provenance="as in the analysed graph", depth=int(original.get("depth") or 1),
        is_direct=bool(original.get("is_direct")), has_install_script=False, is_git_or_file=False,
        license=None, resolved_url=None, introduced_by=list(original.get("introduced_by") or []),
    )
    G = nx.DiGraph()
    G.add_node(ROOT_ID)
    G.add_node(new_purl)
    G.add_edge(ROOT_ID, new_purl)
    build = BuildResult(graph=G, packages={new_purl: pkg}, root_purl=ROOT_ID, root_name="project")
    context = AnalysisContext.model_validate(data.get("context") or {})
    after = next(iter(derive_decisions(build, evidence, context)), None)
    new_risks = [e for e in evidence if not e.withdrawn and e.tier.value in ("T1", "T2") and e.source == "osv"]
    relevant = [i for i in issues if cves or i.provider not in ("kev", "epss")]

    return {
        "subject": subject,
        "to_version": to_version,
        "before": {"verdict": original.get("verdict")},
        "after": {
            "verdict": after.verdict.value if after else "NO_KNOWN_FINDING",
            "urgency": after.urgency.value if after else "NONE",
            "what": after.what if after else "",
            "rules": after.derivation[:3] if after else [],
        },
        "new_risks": [{"id": e.data.get("vuln_id", e.id), "claim": e.claim} for e in new_risks],
        "checks_incomplete": [i.detail for i in relevant],
        "note": "Simulated with the same decision rules. Assumes the new version's own dependencies are unchanged; "
                "nothing is installed." + (" Some lookups could not run — see checks_incomplete." if relevant else ""),
    }


@router.post("/verify-demo")
async def verify_demo():
    """Verifier self-test with a synthetic corrupted claim."""
    # Create a dummy decision to verify against
    from ..models.decision import Decision, Verdict, Urgency, Qualifier, ResponseClass, ExposureInfo
    dummy = Decision(
        subject="pkg:npm/dummy@1.0.0",
        name="dummy", version="1.0.0",
        verdict=Verdict.NO_KNOWN_FINDING,
        urgency=Urgency.NONE, qualifier=Qualifier.UNKNOWN,
        exposure=ExposureInfo(paths=[], scope="prod", scope_provenance="test",
                              install_phase="unknown", scripts_enabled="assumed"),
        evidence_ids=[], response=ResponseClass.NONE,
        as_of=datetime.now(timezone.utc), derivation=[],
        what="Test decision",
    )
    result = verify_claim(SYNTHETIC_CORRUPTED_CLAIM, dummy, {})
    return {
        "claim": SYNTHETIC_CORRUPTED_CLAIM,
        "passed": result.passed,
        "gate": result.gate,
        "detail": result.detail,
        "note": "Synthetic test — this claim was intentionally fabricated to demonstrate rejection.",
    }


@router.get("/reports/{report_id}/export")
async def export_report(report_id: str, format: str = Query(default="json")):
    data = load_report(report_id)
    if data is None:
        raise HTTPException(404, "Report not found")

    if format == "json":
        return Response(
            content=json.dumps(data, default=str, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="warrant-report-{report_id[:8]}.json"'},
        )
    elif format == "md":
        md = _report_to_markdown(data)
        return Response(
            content=md,
            media_type="text/markdown",
            headers={"Content-Disposition": f'attachment; filename="warrant-report-{report_id[:8]}.md"'},
        )
    else:
        raise HTTPException(400, "Supported formats: json, md")


def _report_to_markdown(data: dict) -> str:
    summary = data.get("summary", {})
    lines = [
        f"# Warrant Report",
        f"",
        f"**File:** {data.get('meta', {}).get('filename', 'unknown')}  ",
        f"**Generated:** {data.get('created_at', '')}  ",
        f"**Ecosystem:** {data.get('meta', {}).get('ecosystem', '')}  ",
        f"",
        f"## Summary",
        f"",
        f"- 🔴 INCIDENT: {summary.get('incident', 0)}",
        f"- 🟠 ACT NOW: {summary.get('act_now', 0)}",
        f"- 🟡 UPGRADE: {summary.get('upgrade', 0)}",
        f"- 🔵 MONITOR: {summary.get('monitor', 0)}",
        f"- 🟣 REVIEW: {summary.get('review', 0)}",
        f"- ⬜ CANNOT ASSESS: {summary.get('cannot_assess', 0)}",
        f"- ⚪ NO KNOWN FINDING: {summary.get('no_known_finding', 0)}",
        f"",
        f"Total packages: {summary.get('total_packages', 0)}",
        f"",
        f"---",
        f"",
        f"## Decisions",
        f"",
    ]
    for dec in data.get("decisions", []):
        verdict = dec.get("verdict", "")
        lines.append(f"### {dec.get('name')}@{dec.get('version')} — {verdict}")
        lines.append(f"")
        lines.append(f"**What:** {dec.get('what', '')}")
        lines.append(f"**Scope:** {dec.get('exposure', {}).get('scope', '')}  ")
        if dec.get("fixed_version"):
            lines.append(f"**Fix:** {dec['fixed_version']}  ")
        lines.append(f"")

    lines.extend([
        "---",
        "",
        "*Package-level analysis. Public data sources. Not legal advice. No code is executed.*",
        f"*Counts are unique package versions. Cannot-assess items are not safe items.*",
        f"*As of: {summary.get('as_of', '')}*",
    ])
    return "\n".join(lines)
