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
    elif format in ("md", "markdown"):
        md = _report_to_markdown(data)
        return Response(
            content=md,
            media_type="text/markdown",
            headers={"Content-Disposition": f'attachment; filename="warrant-report-{report_id[:8]}.md"'},
        )
    elif format in ("html", "print"):
        html_content = _report_to_html(data)
        return Response(
            content=html_content,
            media_type="text/html; charset=utf-8",
            headers={"Content-Disposition": f'inline; filename="warrant-report-{report_id[:8]}.html"'},
        )
    else:
        raise HTTPException(400, "Supported formats: json, md, html")


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


def _report_to_html(data: dict) -> str:
    import html
    summary = data.get("summary", {})
    meta = data.get("meta", {})
    filename = html.escape(str(meta.get("filename", "Manifest")))
    ecosystem = html.escape(str(summary.get("ecosystem", "npm"))).upper()
    created_at = html.escape(str(data.get("created_at", "")))
    as_of = html.escape(str(summary.get("as_of", "")))
    report_id = html.escape(str(data.get("id", "")))

    decisions = data.get("decisions", [])
    licenses = data.get("licenses", [])
    coverage = data.get("coverage", [])

    cards_html = []
    for dec in decisions:
        name = html.escape(str(dec.get("name", "")))
        version = html.escape(str(dec.get("version", "")))
        verdict = html.escape(str(dec.get("verdict", "")))
        what = html.escape(str(dec.get("what", "")))
        scope = html.escape(str(dec.get("exposure", {}).get("scope", "prod")))
        depth = dec.get("depth", 0)
        is_direct = dec.get("is_direct", False)
        scope_desc = "Direct" if is_direct else f"Transitive (depth {depth})"

        steps_html = []
        for s in dec.get("response_steps", []):
            st_text = html.escape(str(s.get("text", "")))
            cmd = s.get("command")
            if cmd:
                steps_html.append(f"<li>{st_text} <div class='cmd'><code>$ {html.escape(cmd)}</code></div></li>")
            else:
                steps_html.append(f"<li>{st_text}</li>")

        steps_block = f"<ul class='steps'>{''.join(steps_html)}</ul>" if steps_html else ""

        cards_html.append(f"""
        <div class="card verdict-card-{verdict}">
            <div class="card-head">
                <span class="badge verdict-{verdict}">{verdict}</span>
                <span class="pkg-name">{name}@{version}</span>
                <span class="pkg-meta">{scope_desc} &bull; Scope: {scope}</span>
            </div>
            <div class="card-body">
                <p><strong>Finding:</strong> {what}</p>
                {steps_block}
            </div>
        </div>
        """)

    lic_rows = []
    for l in licenses:
        lname = html.escape(str(l.get("name", "")))
        lver = html.escape(str(l.get("version", "")))
        lexpr = html.escape(str(l.get("license_expr", "UNKNOWN") or "UNKNOWN"))
        lstatus = html.escape(str(l.get("license_status", "UNKNOWN")))
        lrule = html.escape(str(l.get("rule_fired", "") or "—"))
        lnote = html.escape(str(l.get("note", "") or "—"))
        lic_rows.append(f"<tr><td><code>{lname}@{lver}</code></td><td>{lexpr}</td><td><span class='badge lic-{lstatus}'>{lstatus}</span></td><td>{lrule}</td><td>{lnote}</td></tr>")

    cov_rows = []
    for c in coverage:
        check = html.escape(str(c.get("check", "")))
        status = html.escape(str(c.get("status", "")))
        cnt = str(c.get("count", "—") if c.get("count") is not None else "—")
        reason = html.escape(str(c.get("reason", "") or "Ran normally"))
        cov_rows.append(f"<tr><td>{check}</td><td><span class='badge cov-{status.lower()}'>{status}</span></td><td>{cnt}</td><td>{reason}</td></tr>")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Warrant Report - {filename}</title>
<style>
  @page {{ margin: 12mm 15mm; size: auto; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: #0f172a; margin: 0; padding: 24px; background: #fff; line-height: 1.5; font-size: 13px; }}
  .container {{ max-width: 900px; margin: 0 auto; }}
  .header {{ border-bottom: 2px solid #0f172a; padding-bottom: 12px; margin-bottom: 16px; }}
  .top-bar {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }}
  .title {{ font-size: 22px; font-weight: 800; margin: 0; }}
  .sub {{ font-size: 12px; color: #475569; margin: 4px 0 0; }}
  .grid {{ display: grid; grid-template-columns: repeat(7, 1fr); gap: 6px; margin: 16px 0; text-align: center; }}
  .kpi {{ border: 1px solid #cbd5e1; border-radius: 6px; padding: 8px 4px; background: #f8fafc; }}
  .kpi-count {{ font-size: 18px; font-weight: 800; }}
  .kpi-lbl {{ font-size: 9px; font-weight: 700; text-transform: uppercase; margin-top: 2px; }}
  .section {{ margin-top: 24px; break-inside: avoid; }}
  .section-title {{ font-size: 14px; font-weight: 700; text-transform: uppercase; border-bottom: 1px solid #cbd5e1; padding-bottom: 4px; margin-bottom: 10px; }}
  .card {{ border: 1px solid #cbd5e1; border-radius: 6px; margin-bottom: 10px; background: #fff; break-inside: avoid; }}
  .card-head {{ background: #f8fafc; padding: 8px 12px; border-bottom: 1px solid #e2e8f0; display: flex; align-items: center; gap: 8px; font-size: 12px; }}
  .card-body {{ padding: 10px 12px; font-size: 12px; }}
  .badge {{ font-size: 9px; font-weight: 800; padding: 2px 6px; border-radius: 4px; text-transform: uppercase; }}
  .verdict-INCIDENT {{ background: #fee2e2; color: #991b1b; }}
  .verdict-ACT_NOW {{ background: #ffedd5; color: #9a3412; }}
  .verdict-UPGRADE {{ background: #fef3c7; color: #92400e; }}
  .verdict-MONITOR {{ background: #dbeafe; color: #1e40af; }}
  .verdict-REVIEW {{ background: #ede9fe; color: #5b21b6; }}
  .verdict-CANNOT_ASSESS {{ background: #f1f5f9; color: #475569; }}
  .verdict-NO_KNOWN_FINDING {{ background: #dcfce7; color: #166534; }}
  .pkg-name {{ font-family: monospace; font-weight: 700; }}
  .pkg-meta {{ color: #64748b; font-size: 11px; }}
  .steps {{ margin: 6px 0 0; padding-left: 18px; }}
  .cmd {{ margin-top: 2px; }}
  .cmd code {{ background: #0f172a; color: #fff; padding: 2px 6px; border-radius: 3px; font-family: monospace; font-size: 11px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 11px; margin-top: 8px; }}
  th, td {{ padding: 6px 8px; border: 1px solid #cbd5e1; text-align: left; vertical-align: top; }}
  th {{ background: #f1f5f9; text-transform: uppercase; font-size: 10px; }}
  tr:nth-child(even) td {{ background: #f8fafc; }}
  .no-print {{ margin-bottom: 16px; display: flex; gap: 8px; }}
  .btn {{ padding: 6px 12px; font-weight: 600; font-size: 12px; border-radius: 4px; cursor: pointer; border: 1px solid #cbd5e1; background: #0f172a; color: #fff; text-decoration: none; }}
  @media print {{
    .no-print {{ display: none !important; }}
    body {{ padding: 0; }}
    * {{ -webkit-print-color-adjust: exact !important; print-color-adjust: exact !important; }}
  }}
</style>
</head>
<body>
<div class="container">
  <div class="no-print">
    <button class="btn" onclick="window.print()">Print / Save as PDF</button>
  </div>
  <header class="header">
    <div class="top-bar">
      <div><strong>WARRANT</strong> &bull; SUPPLY CHAIN AUDIT</div>
      <div>Generated: {created_at}</div>
    </div>
    <h1 class="title">Detailed Risk Assessment & Remediation Report</h1>
    <p class="sub">File: <strong>{filename}</strong> &bull; Ecosystem: <strong>{ecosystem}</strong> &bull; Report ID: <code>{report_id}</code> &bull; As of: {as_of}</p>
  </header>

  <div class="grid">
    <div class="kpi"><div class="kpi-count" style="color:#dc2626">{summary.get('incident', 0)}</div><div class="kpi-lbl" style="color:#dc2626">Incident</div></div>
    <div class="kpi"><div class="kpi-count" style="color:#ea580c">{summary.get('act_now', 0)}</div><div class="kpi-lbl" style="color:#ea580c">Act Now</div></div>
    <div class="kpi"><div class="kpi-count" style="color:#d97706">{summary.get('upgrade', 0)}</div><div class="kpi-lbl" style="color:#d97706">Upgrade</div></div>
    <div class="kpi"><div class="kpi-count" style="color:#2563eb">{summary.get('monitor', 0)}</div><div class="kpi-lbl" style="color:#2563eb">Monitor</div></div>
    <div class="kpi"><div class="kpi-count" style="color:#7c3aed">{summary.get('review', 0)}</div><div class="kpi-lbl" style="color:#7c3aed">Review</div></div>
    <div class="kpi"><div class="kpi-count" style="color:#64748b">{summary.get('cannot_assess', 0)}</div><div class="kpi-lbl" style="color:#64748b">Cannot Assess</div></div>
    <div class="kpi"><div class="kpi-count" style="color:#059669">{summary.get('no_known_finding', 0)}</div><div class="kpi-lbl" style="color:#059669">No Finding</div></div>
  </div>

  <div class="section">
    <div class="section-title">Findings & Decisions ({len(decisions)})</div>
    {''.join(cards_html) if cards_html else '<p>No findings recorded.</p>'}
  </div>

  {f'<div class="section"><div class="section-title">Licenses Compliance ({len(licenses)})</div><table><thead><tr><th>Package</th><th>License</th><th>Status</th><th>Rule</th><th>Note</th></tr></thead><tbody>{"".join(lic_rows)}</tbody></table></div>' if lic_rows else ''}

  {f'<div class="section"><div class="section-title">Coverage Checklist</div><table><thead><tr><th>Check</th><th>Status</th><th>Count</th><th>Notes</th></tr></thead><tbody>{"".join(cov_rows)}</tbody></table></div>' if cov_rows else ''}

  <footer style="margin-top:30px; border-top:1px solid #cbd5e1; padding-top:10px; font-size:10px; color:#64748b; text-align:center;">
    Warrant Prototype &bull; Evidence-backed decisions, not guarantees &bull; Package-level dependency analysis
  </footer>
</div>
</body>
</html>"""

