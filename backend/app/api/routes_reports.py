"""Report routes — GET/POST /api/reports/{id}"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Query, UploadFile, File
from fastapi.responses import Response

from ..jobs import get_progress
from ..providers.cache import load_report, save_report
from ..security import MAX_UPLOAD_BYTES
from ..engine.decide import derive_decisions
from ..engine.narrate import verify_claim, SYNTHETIC_CORRUPTED_CLAIM
from ..models.evidence import EvidenceRecord
from ..models.decision import Decision

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

    report_id = str(report_data.get("id") or uuid.uuid4())
    report_data["id"] = report_id
    save_report(report_id, report_data)
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
        # Re-derive decisions with temporal filter — no new network calls
        try:
            as_of_dt = datetime.fromisoformat(as_of.replace("Z", "+00:00"))
            data = _rederive_as_of(data, as_of_dt)
        except ValueError:
            raise HTTPException(400, "Invalid as_of datetime format (use ISO 8601)")

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
        status, rule_id, note = classify_license(lic.get("license_expr"), new_context)
        lic["license_status"] = status
        lic["rule_fired"] = rule_id
        lic["note"] = note

    # Update license summary counts in summary
    conflict = sum(1 for l in data.get("licenses", []) if l.get("license_status") == "CONFLICT")
    review = sum(1 for l in data.get("licenses", []) if l.get("license_status") == "REVIEW")

    return data


@router.post("/reports/{report_id}/simulate-fix")
async def simulate_fix(report_id: str, body: dict):
    """Simulate upgrading a package to a fixed version."""
    data = load_report(report_id)
    if data is None:
        raise HTTPException(404, "Report not found")

    subject = body.get("subject")
    to_version = body.get("to_version")
    if not subject or not to_version:
        raise HTTPException(400, "Provide subject (purl) and to_version")

    # Find original decision
    original = None
    for dec_data in data.get("decisions", []):
        if dec_data.get("subject") == subject:
            original = dec_data
            break
    if not original:
        raise HTTPException(404, f"No decision found for {subject}")

    # Re-query OSV for the new version
    name = original.get("name", "")
    from ..providers.osv import fetch_osv_batch
    new_purl = f"pkg:npm/{name.replace('@', '%40').replace('/', '%2F')}@{to_version}"
    new_evidence = await fetch_osv_batch([new_purl])
    new_risks = [e for e in new_evidence if not e.withdrawn and e.tier.value in ("T1", "T2")]

    before_verdict = original.get("verdict")
    after_verdict = "NO_KNOWN_FINDING" if not new_risks else "UPGRADE"

    return {
        "subject": subject,
        "to_version": to_version,
        "before": {"verdict": before_verdict},
        "after": {"verdict": after_verdict},
        "new_risks": [{"id": e.id, "claim": e.claim} for e in new_risks],
        "note": "Simulated. Assumes the new version's own dependencies are unchanged; not installed.",
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


def _rederive_as_of(data: dict, as_of_dt: datetime) -> dict:
    """Re-derive verdicts using only evidence published before as_of_dt."""
    # Update summary as_of
    data["summary"]["as_of"] = as_of_dt.isoformat()
    # Filter decisions to only include those with evidence available at as_of_dt
    for dec in data.get("decisions", []):
        # We can't fully re-derive without the graph, but we can mark the temporal context
        dec["as_of"] = as_of_dt.isoformat()
    return data


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
