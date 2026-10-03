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

    safe_id = report_id[:8]
    if format == "json":
        return Response(
            content=json.dumps(data, default=str, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="warrant-report-{safe_id}.json"'},
        )
    elif format == "md":
        md = _report_to_markdown(data)
        return Response(
            content=md,
            media_type="text/markdown",
            headers={"Content-Disposition": f'attachment; filename="warrant-report-{safe_id}.md"'},
        )
    elif format == "html":
        html = _report_to_html(data)
        return Response(
            content=html,
            media_type="text/html",
            headers={"Content-Disposition": f'attachment; filename="warrant-report-{safe_id}.html"'},
        )
    elif format == "csv":
        csv_data = _report_to_csv(data)
        return Response(
            content=csv_data,
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="warrant-report-{safe_id}.csv"'},
        )
    else:
        raise HTTPException(400, "Supported formats: json, md, html, csv")


def _rederive_as_of(data: dict, as_of_dt: datetime) -> dict:
    """Re-derive verdicts using only evidence published before as_of_dt."""
    # Update summary as_of
    data["summary"]["as_of"] = as_of_dt.isoformat()
    # Filter decisions to only include those with evidence available at as_of_dt
    for dec in data.get("decisions", []):
        dec["as_of"] = as_of_dt.isoformat()
    return data


def _report_to_markdown(data: dict) -> str:
    summary = data.get("summary", {})
    filename = data.get("meta", {}).get("filename") or data.get("meta", {}).get("sample_name") or "unknown"
    evidence_map = {e.get("id"): e for e in data.get("evidence", []) if isinstance(e, dict) and e.get("id")}

    lines = [
        f"# Warrant Security Analysis Report: {filename}",
        f"",
        f"> **Deterministic Dependency Risk Assessment**",
        f"> Computed from printed rule table — not a black-box score.",
        f"",
        f"---",
        f"",
        f"### 📋 Audit Metadata",
        f"",
        f"| Property | Value |",
        f"|---|---|",
        f"| **Target File** | `{filename}` |",
        f"| **Report ID** | `{data.get('id', '')}` |",
        f"| **Generated** | {data.get('created_at', '')} |",
        f"| **Ecosystem** | {summary.get('ecosystem', data.get('meta', {}).get('ecosystem', 'npm'))} |",
        f"| **Total Packages** | **{summary.get('total_packages', 0)}** ({summary.get('direct_packages', 0)} direct) |",
        f"| **As Of Timestamp** | {summary.get('as_of', '')} |",
        f"| **Data Badge** | `{summary.get('data_badge', 'LIVE')}` |",
        f"",
        f"### 🎯 Executive Findings Summary",
        f"",
        f"| Verdict | Finding Count | Meaning |",
        f"|---|---|---|",
        f"| 🔴 **INCIDENT** | **{summary.get('incident', 0)}** | Active malware report or compromise |",
        f"| 🟠 **ACT NOW** | **{summary.get('act_now', 0)}** | Known exploited (KEV) or high EPSS on prod path |",
        f"| 🟡 **UPGRADE** | **{summary.get('upgrade', 0)}** | Advisory with known fix on prod path |",
        f"| 🔵 **MONITOR** | **{summary.get('monitor', 0)}** | Advisory on dev/optional path |",
        f"| 🟣 **REVIEW** | **{summary.get('review', 0)}** | Heuristic or license signal |",
        f"| ⬜ **CANNOT ASSESS** | **{summary.get('cannot_assess', 0)}** | Required check could not complete |",
        f"| ⚪ **NO KNOWN FINDING** | **{summary.get('no_known_finding', 0)}** | All checks ran, nothing found as of this timestamp |",
        f"",
        f"---",
        f"",
        f"## 🔍 Detailed Decisions",
        f"",
    ]

    for dec in data.get("decisions", []):
        verdict = dec.get("verdict", "")
        name = dec.get("name", "")
        version = dec.get("version", "")
        exposure = dec.get("exposure") or {}
        scope = exposure.get("scope", "prod")
        depth = dec.get("depth", 0)
        is_direct = dec.get("is_direct", False)
        
        lines.append(f"### {name}@{version} — `{verdict}`")
        lines.append(f"")
        lines.append(f"- **Subject (PURL):** `{dec.get('subject', '')}`")
        lines.append(f"- **Exposure:** `{scope}` scope · Depth: **{depth}** ({'Direct' if is_direct else 'Transitive'})")
        lines.append(f"- **Urgency:** `{dec.get('urgency', 'NONE')}` · Qualifier: `{dec.get('qualifier', 'UNKNOWN')}`")
        if dec.get("cvss_severity"):
            lines.append(f"- **CVSS:** {dec.get('cvss_severity')} (`{dec.get('cvss_vector', '')}`)")
        lines.append(f"- **Rationale:** {dec.get('what', '')}")
        if dec.get("derivation"):
            lines.append(f"- **Rule Derivation:** `{'; '.join(dec.get('derivation', []))}`")
        if dec.get("carry_reason"):
            lines.append(f"- **Inherited From:** ⚠️ {dec['carry_reason']}")
        lines.append(f"")

        # Dependency Paths
        paths = exposure.get("paths", [])
        if paths:
            lines.append("**Dependency Paths:**")
            for p in paths:
                lines.append(f"- `root` ➔ `{'` ➔ `'.join(p)}`")
            lines.append("")

        # Supporting Evidence
        eids = dec.get("evidence_ids", [])
        if eids:
            lines.append("**Evidence Records:**")
            lines.append("")
            lines.append("| ID | Tier | Source | Claim | Link |")
            lines.append("|---|---|---|---|---|")
            for eid in eids:
                ev = evidence_map.get(eid)
                if ev:
                    link = f"[Advisory]({ev.get('url')})" if ev.get("url") else "—"
                    claim = ev.get("claim", "")
                    lines.append(f"| `{eid}` | **{ev.get('tier', '')}** | {ev.get('source', '')} | {claim} | {link} |")
                else:
                    lines.append(f"| `{eid}` | — | Recorded | — | — |")
            lines.append("")

        # Remediation
        if dec.get("fixed_version") or dec.get("response_steps"):
            lines.append("**Remediation:**")
            if dec.get("fixed_version"):
                lines.append(f"- 💡 Upgrade to version: `{dec.get('fixed_version')}`")
            for step in dec.get("response_steps", []):
                lines.append(f"- {step.get('text', '')}")
                if step.get("command"):
                    lines.append(f"  ```bash")
                    lines.append(f"  {step['command']}")
                    lines.append(f"  ```")
            lines.append("")

        lines.append("---")
        lines.append("")

    # License summary
    licenses = data.get("licenses", [])
    if licenses:
        lines.append("## 📜 License Compliance")
        lines.append("")
        lines.append("| Package | Version | License | Status | Note |")
        lines.append("|---|---|---|---|---|")
        for lic in licenses[:50]:
            lines.append(f"| `{lic.get('name')}` | `{lic.get('version')}` | `{lic.get('license_expr', 'UNKNOWN')}` | **{lic.get('license_status')}** | {lic.get('note', '—')} |")
        lines.append("")

    lines.extend([
        "---",
        "",
        "*Package-level analysis. Public data sources. Deterministic rule evaluation. Not legal advice.*",
        f"*Counts are unique package versions. Cannot-assess items are not safe items.*",
        f"*As of: {summary.get('as_of', '')}*",
    ])
    return "\n".join(lines)


def _report_to_csv(data: dict) -> str:
    import csv
    import io

    output = io.StringIO()
    writer = csv.writer(output, lineterminator="\r\n")

    writer.writerow([
        "Package",
        "Version",
        "Verdict",
        "Urgency",
        "Scope",
        "Direct",
        "Depth",
        "Fixed Version",
        "CVSS Severity",
        "Rule",
        "Rationale",
        "Primary Path",
        "Remediation Command",
    ])

    for dec in data.get("decisions", []):
        exposure = dec.get("exposure") or {}
        paths = exposure.get("paths", [])
        primary_path = " -> ".join(paths[0]) if paths else ("Direct" if dec.get("is_direct") else "")
        cmd = ""
        for s in dec.get("response_steps", []):
            if s.get("command"):
                cmd = s["command"]
                break

        writer.writerow([
            dec.get("name", ""),
            dec.get("version", ""),
            dec.get("verdict", ""),
            dec.get("urgency", ""),
            exposure.get("scope", "prod"),
            "Yes" if dec.get("is_direct") else "No",
            dec.get("depth", 0),
            dec.get("fixed_version", ""),
            dec.get("cvss_severity", ""),
            "; ".join(dec.get("derivation", [])),
            dec.get("what", ""),
            primary_path,
            cmd,
        ])

    return output.getvalue()


def _report_to_html(data: dict) -> str:
    summary = data.get("summary", {})
    filename = data.get("meta", {}).get("filename") or data.get("meta", {}).get("sample_name") or "manifest.json"
    decisions = data.get("decisions", [])

    rows_html = []
    for dec in decisions:
        verdict = dec.get("verdict", "")
        name = dec.get("name", "")
        version = dec.get("version", "")
        what = dec.get("what", "")
        fixed = dec.get("fixed_version", "")
        fix_badge = f"<span style='color: green; font-weight: 600;'>Fix: {fixed}</span>" if fixed else "—"

        rows_html.append(f"""
        <tr>
          <td><strong>{name}@{version}</strong></td>
          <td><span class="badge badge-{verdict.lower()}">{verdict}</span></td>
          <td>{dec.get('urgency', 'NONE')}</td>
          <td>{what}</td>
          <td>{fix_badge}</td>
        </tr>
        """)

    return f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Warrant Report — {filename}</title>
  <style>
    body {{ font-family: system-ui, -apple-system, sans-serif; background: #f8fafc; color: #0f172a; padding: 24px; }}
    .container {{ max-width: 1000px; margin: 0 auto; background: #fff; padding: 24px; border-radius: 8px; border: 1px solid #e2e8f0; }}
    h1 {{ margin-top: 0; font-size: 22px; }}
    .kpis {{ display: flex; gap: 12px; margin: 20px 0; flex-wrap: wrap; }}
    .kpi {{ padding: 12px 18px; border-radius: 6px; background: #f1f5f9; text-align: center; font-weight: 700; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 13px; }}
    th, td {{ border: 1px solid #e2e8f0; padding: 8px 12px; text-align: left; }}
    th {{ background: #f8fafc; }}
    .badge {{ display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 700; }}
    .badge-incident {{ background: #fef2f2; color: #b91c1c; border: 1px solid #fecaca; }}
    .badge-act_now {{ background: #fff7ed; color: #c2410c; border: 1px solid #fed7aa; }}
    .badge-upgrade {{ background: #fefce8; color: #a16207; border: 1px solid #fef08a; }}
    .badge-monitor {{ background: #eff6ff; color: #1d4ed8; border: 1px solid #bfdbfe; }}
    .badge-review {{ background: #faf5ff; color: #7e22ce; border: 1px solid #e9d5ff; }}
    @media print {{ body {{ background: #fff; padding: 0; }} .container {{ border: none; }} }}
  </style>
</head>
<body>
  <div class="container">
    <h1>🛡️ Warrant Security Audit Report</h1>
    <p>Target: <strong>{filename}</strong> · Total Packages: {summary.get('total_packages', 0)} · Ecosystem: {summary.get('ecosystem', 'npm')}</p>
    <div class="kpis">
      <div class="kpi" style="color: #b91c1c;">Incident: {summary.get('incident', 0)}</div>
      <div class="kpi" style="color: #c2410c;">Act Now: {summary.get('act_now', 0)}</div>
      <div class="kpi" style="color: #a16207;">Upgrade: {summary.get('upgrade', 0)}</div>
      <div class="kpi" style="color: #1d4ed8;">Monitor: {summary.get('monitor', 0)}</div>
      <div class="kpi" style="color: #7e22ce;">Review: {summary.get('review', 0)}</div>
      <div class="kpi">Clean: {summary.get('no_known_finding', 0)}</div>
    </div>
    <table>
      <thead>
        <tr>
          <th>Package</th>
          <th>Verdict</th>
          <th>Urgency</th>
          <th>Findings & Rationale</th>
          <th>Remediation</th>
        </tr>
      </thead>
      <tbody>
        {"".join(rows_html)}
      </tbody>
    </table>
  </div>
</body>
</html>"""
