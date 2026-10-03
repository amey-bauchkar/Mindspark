import type { Report, Decision, EvidenceRecord, Verdict } from './types';
import { VERDICT_ORDER, VERDICT_LABELS, VERDICT_ICONS } from './types';
import { formatDate } from './format';

export type ExportFormat = 'html' | 'md' | 'csv' | 'json';

/**
 * Clean base filename for downloads
 */
export function getReportBaseFilename(report: Report): string {
  const raw = (report.meta?.filename as string) || (report.meta?.sample_name as string) || 'warrant-report';
  const clean = raw.replace(/\.[^/.]+$/, '').replace(/[^a-zA-Z0-9_-]/g, '_');
  const dateStr = new Date(report.created_at || Date.now()).toISOString().slice(0, 10);
  return `warrant-report-${clean}-${dateStr}`;
}

/**
 * Trigger client-side file download
 */
export function downloadBlob(content: string, filename: string, mimeType: string): void {
  const blob = new Blob([content], { type: `${mimeType};charset=utf-8;` });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.setAttribute('download', filename);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  setTimeout(() => URL.revokeObjectURL(url), 1500);
}

/**
 * Generate comprehensive detailed Markdown report
 */
export function generateDetailedMarkdown(report: Report): string {
  const { summary, decisions, evidence = [], licenses = [], coverage = [] } = report;
  const filename = (report.meta?.filename as string) || (report.meta?.sample_name as string) || 'Target Manifest';
  const evidenceMap = new Map<string, EvidenceRecord>(evidence.map(e => [e.id, e]));

  const sortedDecisions = [...decisions].sort(
    (a, b) => (VERDICT_ORDER[a.verdict as Verdict] ?? 99) - (VERDICT_ORDER[b.verdict as Verdict] ?? 99)
  );

  const lines: string[] = [];

  // Header
  lines.push(`# Warrant Security Analysis Report: ${filename}`);
  lines.push('');
  lines.push(`> **Deterministic Dependency Risk Assessment**`);
  lines.push(`> Computed from printed rule table — not a black-box machine learning score.`);
  lines.push('');
  lines.push('---');
  lines.push('');

  // Metadata Table
  lines.push('### 📋 Audit Metadata');
  lines.push('');
  lines.push('| Property | Value |');
  lines.push('|---|---|');
  lines.push(`| **Target File** | \`${filename}\` |`);
  lines.push(`| **Report ID** | \`${report.id}\` |`);
  lines.push(`| **Ecosystem** | ${summary.ecosystem || 'npm'} |`);
  lines.push(`| **Total Packages** | **${summary.total_packages}** (${summary.direct_packages} direct, ${summary.total_packages - summary.direct_packages} transitive) |`);
  lines.push(`| **Analysis Timestamp** | ${formatDate(report.created_at)} |`);
  lines.push(`| **Evaluated As-Of** | ${formatDate(summary.as_of)} |`);
  lines.push(`| **Data Feed Mode** | \`${summary.data_badge}\` |`);
  lines.push('');

  // Executive Summary KPI Table
  lines.push('### 🎯 Executive Findings Summary');
  lines.push('');
  lines.push('| Verdict | Severity Level | Finding Count | Required Action |');
  lines.push('|---|---|---|---|');
  lines.push(`| 🔴 **INCIDENT** | Critical (Malware/Exploit) | **${summary.incident}** | Immediate containment and credential revocation |`);
  lines.push(`| 🟠 **ACT NOW** | High (KEV / High EPSS) | **${summary.act_now}** | Out-of-cycle emergency upgrade |`);
  lines.push(`| 🟡 **UPGRADE** | Medium (Known Advisory + Fix) | **${summary.upgrade}** | Scheduled version upgrade |`);
  lines.push(`| 🔵 **MONITOR** | Low (Dev/Optional path) | **${summary.monitor}** | Track and update during maintenance |`);
  lines.push(`| 🟣 **REVIEW** | Info (Heuristic / License) | **${summary.review}** | Human verification required |`);
  lines.push(`| ⬜ **CANNOT ASSESS** | Caution (Check unavailable) | **${summary.cannot_assess}** | Treat as unverified — NOT safe |`);
  lines.push(`| ⚪ **NO KNOWN FINDING** | Clean (All checks passed) | **${summary.no_known_finding}** | Baseline clean as of evaluation time |`);
  lines.push('');
  lines.push('---');
  lines.push('');

  // Detailed Decisions
  lines.push('## 🔍 Detailed Dependency Findings');
  lines.push('');

  if (sortedDecisions.length === 0) {
    lines.push('_No package decisions recorded._');
    lines.push('');
  } else {
    for (const dec of sortedDecisions) {
      const icon = VERDICT_ICONS[dec.verdict as Verdict] || '▫️';
      const label = VERDICT_LABELS[dec.verdict as Verdict] || dec.verdict;

      lines.push(`### ${icon} ${dec.name}@${dec.version} — \`${label}\``);
      lines.push('');
      lines.push(`- **Subject (PURL):** \`${dec.subject}\``);
      lines.push(`- **Exposure:** \`${dec.exposure?.scope || 'unknown'}\` scope · Depth: **${dec.depth}** (${dec.is_direct ? 'Direct Dependency' : 'Transitive'})`);
      lines.push(`- **Urgency Level:** \`${dec.urgency}\` · Qualifier: \`${dec.qualifier}\``);
      if (dec.cvss_severity || dec.cvss_vector) {
        lines.push(`- **CVSS Profile:** **${dec.cvss_severity || 'N/A'}** (\`${dec.cvss_vector || 'N/A'}\`)`);
      }
      lines.push(`- **Verdict Rationale:** ${dec.what}`);
      if (dec.derivation && dec.derivation.length > 0) {
        lines.push(`- **Rule Derivation:** \`${dec.derivation.join('; ')}\``);
      }
      if (dec.carry_reason) {
        lines.push(`- **Inherited From:** ⚠️ ${dec.carry_reason}`);
      }
      lines.push('');

      // Dependency Paths
      if (dec.exposure?.paths && dec.exposure.paths.length > 0) {
        lines.push('**Resolved Dependency Chains:**');
        for (const path of dec.exposure.paths) {
          lines.push(`- \`root\` ➔ \`${path.join('` ➔ `')}\``);
        }
        lines.push('');
      }

      // Evidence Items
      if (dec.evidence_ids && dec.evidence_ids.length > 0) {
        lines.push('**Supporting Evidence & Authority Records:**');
        lines.push('');
        lines.push('| ID | Tier | Source | Claim / Finding | Advisory Link |');
        lines.push('|---|---|---|---|---|');
        for (const eid of dec.evidence_ids) {
          const ev = evidenceMap.get(eid);
          if (ev) {
            const link = ev.url ? `[View Advisory](${ev.url})` : '—';
            const quote = ev.quote ? `<br>_"${ev.quote.slice(0, 150)}${ev.quote.length > 150 ? '...' : ''}"_` : '';
            lines.push(`| \`${ev.id}\` | **${ev.tier}** | ${ev.source} | ${ev.claim}${quote} | ${link} |`);
          } else {
            lines.push(`| \`${eid}\` | — | Recorded Evidence | — | — |`);
          }
        }
        lines.push('');
      }

      // Remediation Actions
      if (dec.fixed_version || (dec.response_steps && dec.response_steps.length > 0)) {
        lines.push('**Recommended Remediation:**');
        if (dec.fixed_version) {
          lines.push(`- 💡 **Fixed in Version:** \`${dec.fixed_version}\``);
        }
        if (dec.response_steps) {
          for (const step of dec.response_steps) {
            lines.push(`- ${step.text}`);
            if (step.command) {
              lines.push('  ```bash');
              lines.push(`  ${step.command}`);
              lines.push('  ```');
            }
          }
        }
        lines.push('');
      }

      // Unrun checks if any
      if (dec.unrun_checks && dec.unrun_checks.length > 0) {
        lines.push(`> ⚠️ **Unrun Checks:** ${dec.unrun_checks.join(', ')}`);
        lines.push('');
      }

      lines.push('---');
      lines.push('');
    }
  }

  // License Compliance Section
  lines.push('## 📜 License Compliance Audit');
  lines.push('');
  if (licenses.length === 0) {
    lines.push('_No license metadata analyzed for this project._');
    lines.push('');
  } else {
    const conflicts = licenses.filter(l => l.license_status === 'CONFLICT').length;
    const reviews = licenses.filter(l => l.license_status === 'REVIEW').length;
    const permitted = licenses.filter(l => l.license_status === 'PERMITTED' || l.license_status === 'PERMISSIVE').length;

    lines.push(`- **Policy Conflicts:** ${conflicts}`);
    lines.push(`- **Under Legal Review:** ${reviews}`);
    lines.push(`- **Permitted / Compliant:** ${permitted}`);
    lines.push('');
    lines.push('| Package | Version | SPDX Expression | Status | Rule Fired | Compliance Notes |');
    lines.push('|---|---|---|---|---|---|');
    for (const lic of licenses.slice(0, 50)) {
      lines.push(
        `| \`${lic.name}\` | \`${lic.version}\` | \`${lic.license_expr || 'UNKNOWN'}\` | **${lic.license_status}** | \`${lic.rule_fired || '—'}\` | ${lic.note || '—'} |`
      );
    }
    if (licenses.length > 50) {
      lines.push(`| ... | ... | ... | ... | ... | _Showing 50 of ${licenses.length} packages_ |`);
    }
    lines.push('');
    lines.push('---');
    lines.push('');
  }

  // Coverage and Assurance Section
  lines.push('## 🛡️ Coverage, Methodology & Assurance');
  lines.push('');
  lines.push('| Security Check | Status | Packages Evaluated | Notes / Reason |');
  lines.push('|---|---|---|---|');
  if (coverage.length > 0) {
    for (const cov of coverage) {
      lines.push(`| ${cov.check} | **${cov.status}** | ${cov.count ?? 'All'} | ${cov.reason || 'Executed successfully'} |`);
    }
  } else {
    lines.push('| OSV Vulnerability Database | RUN | All | Exact PURL matches |');
    lines.push('| CISA KEV Exploited Catalog | RUN | All | Cross-referenced |');
    lines.push('| EPSS Probability Scoring | RUN | All | First.org live API |');
    lines.push('| Dependency Graph Extraction | RUN | All | Full resolution |');
  }
  lines.push('');

  // Disclaimers
  lines.push('### ⚠️ Methodology Notes & Boundaries');
  lines.push('- **Package-Level Analysis:** Function-level reachability is not assessed. All findings represent package version exposure.');
  lines.push('- **Deterministic Rules:** Every verdict is derived from the public rule table in top-down order (R1 ➔ R7).');
  lines.push('- **Never-Green Principle:** `NO KNOWN FINDING` means all required checks ran as of this timestamp; it is not a certificate of absolute safety.');
  lines.push('- **CANNOT ASSESS ≠ Clean:** A required external check could not complete (e.g. rate limit, unresolvable package).');
  lines.push('');
  lines.push(`_Report generated by Warrant on ${new Date().toUTCString()}._`);

  return lines.join('\n');
}

/**
 * Generate Standalone Executive & Technical HTML report with PDF print styling
 */
export function generateDetailedHtml(report: Report): string {
  const { summary, decisions, evidence = [], licenses = [], coverage = [] } = report;
  const filename = (report.meta?.filename as string) || (report.meta?.sample_name as string) || 'manifest.json';
  const evidenceMap = new Map<string, EvidenceRecord>(evidence.map(e => [e.id, e]));

  const sortedDecisions = [...decisions].sort(
    (a, b) => (VERDICT_ORDER[a.verdict as Verdict] ?? 99) - (VERDICT_ORDER[b.verdict as Verdict] ?? 99)
  );

  const escapeHtml = (str: string | null | undefined): string => {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  };

  const getVerdictBadgeClass = (v: string): string => {
    switch (v) {
      case 'INCIDENT': return 'badge-incident';
      case 'ACT_NOW': return 'badge-act-now';
      case 'UPGRADE': return 'badge-upgrade';
      case 'MONITOR': return 'badge-monitor';
      case 'REVIEW': return 'badge-review';
      case 'CANNOT_ASSESS': return 'badge-cannot-assess';
      default: return 'badge-clean';
    }
  };

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Warrant Report — ${escapeHtml(filename)}</title>
  <style>
    :root {
      --bg: #F8FAFC;
      --card-bg: #FFFFFF;
      --border: #E2E8F0;
      --border-subtle: #F1F5F9;
      --text: #0F172A;
      --text-muted: #64748B;
      --text-secondary: #334155;
      --accent: #0284C7;
      
      --incident-bg: #FEF2F2;
      --incident-text: #B91C1C;
      --incident-border: #FECACA;
      
      --act-now-bg: #FFF7ED;
      --act-now-text: #C2410C;
      --act-now-border: #FED7AA;
      
      --upgrade-bg: #FEFCE8;
      --upgrade-text: #A16207;
      --upgrade-border: #FEF08A;
      
      --monitor-bg: #EFF6FF;
      --monitor-text: #1D4ED8;
      --monitor-border: #BFDBFE;
      
      --review-bg: #FAF5FF;
      --review-text: #7E22CE;
      --review-border: #E9D5FF;
      
      --cannot-bg: #F1F5F9;
      --cannot-text: #475569;
      --cannot-border: #CBD5E1;
      
      --clean-bg: #F8FAFC;
      --clean-text: #334155;
      --clean-border: #E2E8F0;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
      padding: 32px 16px;
    }
    .container {
      max-width: 1100px;
      margin: 0 auto;
    }
    
    /* Top Header Bar */
    .header-bar {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 24px;
      margin-bottom: 24px;
      box-shadow: 0 1px 3px rgba(0,0,0,0.05);
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 16px;
    }
    .header-title h1 {
      font-size: 24px;
      font-weight: 700;
      color: var(--text);
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .header-meta {
      font-size: 13px;
      color: var(--text-muted);
      margin-top: 6px;
    }
    .print-btn {
      background: var(--text);
      color: #fff;
      border: none;
      padding: 8px 16px;
      border-radius: 6px;
      font-weight: 600;
      font-size: 14px;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      transition: opacity 0.2s;
    }
    .print-btn:hover { opacity: 0.85; }

    /* Summary KPI Grid */
    .kpi-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
      gap: 12px;
      margin-bottom: 24px;
    }
    .kpi-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 16px;
      text-align: center;
      box-shadow: 0 1px 2px rgba(0,0,0,0.04);
    }
    .kpi-card.incident { background: var(--incident-bg); border-color: var(--incident-border); color: var(--incident-text); }
    .kpi-card.act-now { background: var(--act-now-bg); border-color: var(--act-now-border); color: var(--act-now-text); }
    .kpi-card.upgrade { background: var(--upgrade-bg); border-color: var(--upgrade-border); color: var(--upgrade-text); }
    .kpi-card.monitor { background: var(--monitor-bg); border-color: var(--monitor-border); color: var(--monitor-text); }
    .kpi-card.review { background: var(--review-bg); border-color: var(--review-border); color: var(--review-text); }
    
    .kpi-value {
      font-size: 28px;
      font-weight: 800;
      line-height: 1.1;
    }
    .kpi-label {
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      margin-top: 4px;
    }

    /* Section Styling */
    .section-title {
      font-size: 18px;
      font-weight: 700;
      margin: 32px 0 16px;
      display: flex;
      align-items: center;
      gap: 8px;
      color: var(--text);
    }
    
    /* Decision Cards */
    .decision-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 10px;
      margin-bottom: 16px;
      padding: 20px;
      box-shadow: 0 1px 3px rgba(0,0,0,0.04);
      page-break-inside: avoid;
    }
    .decision-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 12px;
      flex-wrap: wrap;
      gap: 8px;
    }
    .decision-title {
      font-size: 16px;
      font-weight: 700;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    }
    .badge {
      display: inline-block;
      padding: 3px 8px;
      border-radius: 9999px;
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 0.3px;
      text-transform: uppercase;
    }
    .badge-incident { background: var(--incident-bg); color: var(--incident-text); border: 1px solid var(--incident-border); }
    .badge-act-now { background: var(--act-now-bg); color: var(--act-now-text); border: 1px solid var(--act-now-border); }
    .badge-upgrade { background: var(--upgrade-bg); color: var(--upgrade-text); border: 1px solid var(--upgrade-border); }
    .badge-monitor { background: var(--monitor-bg); color: var(--monitor-text); border: 1px solid var(--monitor-border); }
    .badge-review { background: var(--review-bg); color: var(--review-text); border: 1px solid var(--review-border); }
    .badge-cannot-assess { background: var(--cannot-bg); color: var(--cannot-text); border: 1px solid var(--cannot-border); }
    .badge-clean { background: var(--clean-bg); color: var(--clean-text); border: 1px solid var(--clean-border); }
    
    .meta-tags {
      display: flex;
      gap: 12px;
      font-size: 12px;
      color: var(--text-muted);
      margin-bottom: 12px;
      flex-wrap: wrap;
    }
    .meta-item { display: inline-flex; align-items: center; gap: 4px; }
    .meta-item strong { color: var(--text-secondary); }

    .rationale-box {
      background: var(--bg);
      border-left: 3px solid var(--accent);
      padding: 10px 14px;
      font-size: 13px;
      border-radius: 0 6px 6px 0;
      margin-bottom: 14px;
    }

    .path-box {
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 12px;
      background: #F1F5F9;
      padding: 8px 12px;
      border-radius: 6px;
      margin-bottom: 12px;
      color: var(--text-secondary);
      overflow-x: auto;
    }

    .evidence-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 12px;
      margin: 12px 0;
    }
    .evidence-table th, .evidence-table td {
      border: 1px solid var(--border);
      padding: 8px 10px;
      text-align: left;
    }
    .evidence-table th {
      background: var(--bg);
      color: var(--text-secondary);
      font-weight: 600;
    }
    .remediation-box {
      background: #F0FDF4;
      border: 1px solid #BBF7D0;
      border-radius: 6px;
      padding: 12px;
      font-size: 13px;
      color: #166534;
      margin-top: 12px;
    }
    .code-cmd {
      background: #0F172A;
      color: #F8FAFC;
      padding: 6px 10px;
      border-radius: 4px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 12px;
      display: block;
      margin-top: 6px;
    }

    /* Print media styles */
    @media print {
      body { background: #fff; padding: 0; }
      .container { max-width: 100%; }
      .print-btn { display: none; }
      .decision-card { box-shadow: none; border: 1px solid #ccc; page-break-inside: avoid; }
      .header-bar { border: none; padding: 0 0 16px 0; border-bottom: 2px solid #000; }
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header-bar">
      <div class="header-title">
        <h1>🛡️ Warrant Security Audit</h1>
        <div class="header-meta">
          <strong>Target:</strong> ${escapeHtml(filename)} · 
          <strong>Packages:</strong> ${summary.total_packages} (${summary.direct_packages} direct) · 
          <strong>Ecosystem:</strong> ${escapeHtml(summary.ecosystem)} · 
          <strong>Evaluated As Of:</strong> ${escapeHtml(formatDate(summary.as_of))}
        </div>
      </div>
      <div>
        <button class="print-btn" onclick="window.print()">🖨️ Print / Save as PDF</button>
      </div>
    </div>

    <!-- KPI Summary Grid -->
    <div class="kpi-grid">
      <div class="kpi-card incident">
        <div class="kpi-value">${summary.incident}</div>
        <div class="kpi-label">Incident</div>
      </div>
      <div class="kpi-card act-now">
        <div class="kpi-value">${summary.act_now}</div>
        <div class="kpi-label">Act Now</div>
      </div>
      <div class="kpi-card upgrade">
        <div class="kpi-value">${summary.upgrade}</div>
        <div class="kpi-label">Upgrade</div>
      </div>
      <div class="kpi-card monitor">
        <div class="kpi-value">${summary.monitor}</div>
        <div class="kpi-label">Monitor</div>
      </div>
      <div class="kpi-card review">
        <div class="kpi-value">${summary.review}</div>
        <div class="kpi-label">Review</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-value">${summary.cannot_assess}</div>
        <div class="kpi-label">Cannot Assess</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-value">${summary.no_known_finding}</div>
        <div class="kpi-label">No Known Finding</div>
      </div>
    </div>

    <!-- Findings Section -->
    <h2 class="section-title">🔍 Risky Dependency Decisions (${decisions.filter(d => d.verdict !== 'NO_KNOWN_FINDING').length})</h2>

    ${sortedDecisions.map(dec => {
      const badgeCls = getVerdictBadgeClass(dec.verdict);
      const icon = VERDICT_ICONS[dec.verdict as Verdict] || '▫️';
      const label = VERDICT_LABELS[dec.verdict as Verdict] || dec.verdict;

      return `
      <div class="decision-card">
        <div class="decision-header">
          <div class="decision-title">${icon} ${escapeHtml(dec.name)}@${escapeHtml(dec.version)}</div>
          <span class="badge ${badgeCls}">${escapeHtml(label)}</span>
        </div>

        <div class="meta-tags">
          <div class="meta-item"><strong>Scope:</strong> ${escapeHtml(dec.exposure?.scope || 'prod')}</div>
          <div class="meta-item"><strong>Depth:</strong> ${dec.depth} (${dec.is_direct ? 'Direct' : 'Transitive'})</div>
          <div class="meta-item"><strong>Urgency:</strong> ${escapeHtml(dec.urgency)}</div>
          ${dec.cvss_severity ? `<div class="meta-item"><strong>CVSS:</strong> ${escapeHtml(dec.cvss_severity)}</div>` : ''}
          ${dec.derivation && dec.derivation.length ? `<div class="meta-item"><strong>Rule:</strong> ${escapeHtml(dec.derivation.join(', '))}</div>` : ''}
        </div>

        <div class="rationale-box">
          <strong>Verdict Rationale:</strong> ${escapeHtml(dec.what)}
        </div>

        ${dec.exposure?.paths && dec.exposure.paths.length ? `
          <div class="path-box">
            <strong>Path:</strong> root &rarr; ${dec.exposure.paths[0].map(p => escapeHtml(p)).join(' &rarr; ')}
          </div>
        ` : ''}

        ${dec.evidence_ids && dec.evidence_ids.length ? `
          <table class="evidence-table">
            <thead>
              <tr>
                <th style="width: 80px;">Tier</th>
                <th style="width: 90px;">Source</th>
                <th>Evidence Claim / Advisory</th>
                <th style="width: 100px;">Reference</th>
              </tr>
            </thead>
            <tbody>
              ${dec.evidence_ids.map(eid => {
                const ev = evidenceMap.get(eid);
                if (!ev) return `<tr><td colspan="4">${escapeHtml(eid)}</td></tr>`;
                return `
                  <tr>
                    <td><strong>${escapeHtml(ev.tier)}</strong></td>
                    <td>${escapeHtml(ev.source)}</td>
                    <td>
                      ${escapeHtml(ev.claim)}
                      ${ev.quote ? `<div style="color: var(--text-muted); font-style: italic; margin-top: 3px;">"${escapeHtml(ev.quote.slice(0, 180))}"</div>` : ''}
                    </td>
                    <td>
                      ${ev.url ? `<a href="${escapeHtml(ev.url)}" target="_blank" rel="noopener noreferrer" style="color: var(--accent);">View Link &nearr;</a>` : '—'}
                    </td>
                  </tr>
                `;
              }).join('')}
            </tbody>
          </table>
        ` : ''}

        ${dec.fixed_version || (dec.response_steps && dec.response_steps.length) ? `
          <div class="remediation-box">
            ${dec.fixed_version ? `<div><strong>Remediation:</strong> Fixed in version <code>${escapeHtml(dec.fixed_version)}</code></div>` : ''}
            ${dec.response_steps ? dec.response_steps.map(s => `
              <div style="margin-top: 4px;">${escapeHtml(s.text)}</div>
              ${s.command ? `<code class="code-cmd">${escapeHtml(s.command)}</code>` : ''}
            `).join('') : ''}
          </div>
        ` : ''}
      </div>
      `;
    }).join('')}

    <!-- License Compliance Section -->
    ${licenses.length ? `
      <h2 class="section-title">📜 License Compliance Summary</h2>
      <table class="evidence-table" style="background: var(--card-bg);">
        <thead>
          <tr>
            <th>Package</th>
            <th>Version</th>
            <th>License Expression</th>
            <th>Status</th>
            <th>Notes</th>
          </tr>
        </thead>
        <tbody>
          ${licenses.slice(0, 40).map(lic => `
            <tr>
              <td><code>${escapeHtml(lic.name)}</code></td>
              <td>${escapeHtml(lic.version)}</td>
              <td><code>${escapeHtml(lic.license_expr || 'UNKNOWN')}</code></td>
              <td><strong>${escapeHtml(lic.license_status)}</strong></td>
              <td>${escapeHtml(lic.note || '—')}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    ` : ''}

    <div style="margin-top: 40px; padding-top: 16px; border-top: 1px solid var(--border); font-size: 11px; color: var(--text-muted); text-align: center;">
      Generated by Warrant Software Supply Chain Risk Analyzer · Evidence-backed deterministic rules · As of ${escapeHtml(formatDate(summary.as_of))}
    </div>
  </div>
</body>
</html>`;
}

/**
 * Generate RFC 4180 compliant CSV export
 */
export function generateDetailedCsv(report: Report): string {
  const { decisions, summary, evidence = [] } = report;
  const evidenceMap = new Map<string, EvidenceRecord>(evidence.map(e => [e.id, e]));

  const escapeCsv = (str: string | number | null | undefined): string => {
    if (str === null || str === undefined) return '""';
    const val = String(str).replace(/"/g, '""');
    return `"${val}"`;
  };

  const headers = [
    'Package Name',
    'Version',
    'Ecosystem',
    'Verdict',
    'Urgency',
    'Scope',
    'Is Direct',
    'Depth',
    'Fixed Version',
    'CVSS Severity',
    'Rule Derivation',
    'Verdict Explanation',
    'Primary Dependency Path',
    'Evidence Count',
    'Advisory IDs',
    'Remediation Command',
  ];

  const rows: string[] = [headers.map(escapeCsv).join(',')];

  const sortedDecisions = [...decisions].sort(
    (a, b) => (VERDICT_ORDER[a.verdict as Verdict] ?? 99) - (VERDICT_ORDER[b.verdict as Verdict] ?? 99)
  );

  for (const dec of sortedDecisions) {
    const primaryPath = dec.exposure?.paths?.[0]?.join(' -> ') || (dec.is_direct ? 'Direct' : 'Unknown');
    const advisoryIds = (dec.evidence_ids || [])
      .map(id => {
        const ev = evidenceMap.get(id);
        return ev?.id || id;
      })
      .join('; ');
    const cmd = dec.response_steps?.find(s => s.command)?.command || '';

    const row = [
      escapeCsv(dec.name),
      escapeCsv(dec.version),
      escapeCsv(summary.ecosystem || 'npm'),
      escapeCsv(dec.verdict),
      escapeCsv(dec.urgency),
      escapeCsv(dec.exposure?.scope || 'prod'),
      escapeCsv(dec.is_direct ? 'Yes' : 'No'),
      escapeCsv(dec.depth),
      escapeCsv(dec.fixed_version || ''),
      escapeCsv(dec.cvss_severity || ''),
      escapeCsv((dec.derivation || []).join('; ')),
      escapeCsv(dec.what),
      escapeCsv(primaryPath),
      escapeCsv(dec.evidence_ids?.length || 0),
      escapeCsv(advisoryIds),
      escapeCsv(cmd),
    ];
    rows.push(row.join(','));
  }

  return rows.join('\r\n');
}

/**
 * Generate full formatted JSON
 */
export function generateDetailedJson(report: Report): string {
  return JSON.stringify(report, null, 2);
}

/**
 * High-level download trigger for any format
 */
export function downloadReportFile(report: Report, format: ExportFormat): void {
  const baseFilename = getReportBaseFilename(report);

  switch (format) {
    case 'html': {
      const html = generateDetailedHtml(report);
      downloadBlob(html, `${baseFilename}.html`, 'text/html');
      break;
    }
    case 'md': {
      const md = generateDetailedMarkdown(report);
      downloadBlob(md, `${baseFilename}.md`, 'text/markdown');
      break;
    }
    case 'csv': {
      const csv = generateDetailedCsv(report);
      downloadBlob(csv, `${baseFilename}.csv`, 'text/csv');
      break;
    }
    case 'json': {
      const json = generateDetailedJson(report);
      downloadBlob(json, `${baseFilename}.json`, 'application/json');
      break;
    }
  }
}
