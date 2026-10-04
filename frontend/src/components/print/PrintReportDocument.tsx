import React from 'react';
import type { Report, Decision, EvidenceRecord } from '../../lib/types';
import { VERDICT_ORDER, VERDICT_LABELS } from '../../lib/types';
import { formatDate } from '../../lib/format';

export interface PrintOptions {
  actionableOnly?: boolean;
  includeLicenses?: boolean;
  includeCoverage?: boolean;
  includeEvidenceDetails?: boolean;
  includePaths?: boolean;
  includeRemediation?: boolean;
}

interface PrintReportDocumentProps {
  report: Report;
  options?: PrintOptions;
}

export function PrintReportDocument({
  report,
  options = {
    actionableOnly: false,
    includeLicenses: true,
    includeCoverage: true,
    includeEvidenceDetails: true,
    includePaths: true,
    includeRemediation: true,
  },
}: PrintReportDocumentProps) {
  const { meta, summary, decisions, evidence, licenses, coverage, context } = report;

  // Filter decisions according to options
  const displayedDecisions = decisions
    .filter(d => {
      if (options.actionableOnly) {
        return ['INCIDENT', 'ACT_NOW', 'UPGRADE', 'REVIEW'].includes(d.verdict);
      }
      return true;
    })
    .sort((a, b) => (VERDICT_ORDER[a.verdict] ?? 99) - (VERDICT_ORDER[b.verdict] ?? 99));

  // Map evidence for quick lookup
  const evidenceMap = new Map<string, EvidenceRecord>();
  evidence.forEach(e => evidenceMap.set(e.id, e));

  const verdictCounts = [
    { key: 'INCIDENT', label: 'Incident', count: summary.incident, color: '#DC2626', bg: '#FEE2E2' },
    { key: 'ACT_NOW', label: 'Act Now', count: summary.act_now, color: '#EA580C', bg: '#FFEDD5' },
    { key: 'UPGRADE', label: 'Upgrade', count: summary.upgrade, color: '#D97706', bg: '#FEF3C7' },
    { key: 'MONITOR', label: 'Monitor', count: summary.monitor, color: '#2563EB', bg: '#DBEAFE' },
    { key: 'REVIEW', label: 'Review', count: summary.review, color: '#7C3AED', bg: '#EDE9FE' },
    { key: 'CANNOT_ASSESS', label: 'Cannot Assess', count: summary.cannot_assess, color: '#64748B', bg: '#F1F5F9' },
    { key: 'NO_KNOWN_FINDING', label: 'No Finding', count: summary.no_known_finding, color: '#059669', bg: '#D1FAE5' },
  ];

  return (
    <div className="print-document">
      {/* ─── DOCUMENT HEADER ──────────────────────────────────────────────────────── */}
      <header className="print-header">
        <div className="print-header-top">
          <div className="print-brand">
            <img src="/logo.png" alt="Warrant" style={{ width: 22, height: 22, objectFit: 'contain', verticalAlign: 'middle' }} />
            <span className="print-brand-title">WARRANT</span>
            <span className="print-brand-badge">SUPPLY CHAIN SECURITY AUDIT</span>
          </div>
          <div className="print-meta-badge">
            <span className={`print-badge-pill ${summary.data_badge === 'LIVE' ? 'live' : 'recorded'}`}>
              {summary.data_badge || 'AUDIT'}
            </span>
            <span className="print-date">Generated: {new Date(report.created_at).toLocaleString()}</span>
          </div>
        </div>

        <div className="print-title-area">
          <h1 className="print-title">Detailed Risk Assessment & Remediation Report</h1>
          <p className="print-subtitle">
            Target: <strong>{String(meta.filename || 'Manifest Lockfile')}</strong> &bull; Ecosystem:{' '}
            <strong>{summary.ecosystem?.toUpperCase() || 'NPM'}</strong> &bull; Report ID:{' '}
            <code>{report.id.slice(0, 16)}</code>
          </p>
        </div>

        {/* Project Context Parameters */}
        <div className="print-context-bar">
          <div className="print-context-item">
            <span className="ctx-label">Distribution Mode:</span>
            <span className="ctx-val">{context?.distribution_mode || 'Unknown / Assumed'}</span>
          </div>
          <div className="print-context-item">
            <span className="ctx-label">Declared Project License:</span>
            <span className="ctx-val">{context?.project_license || 'Unknown'}</span>
          </div>
          <div className="print-context-item">
            <span className="ctx-label">Install Scripts Executed:</span>
            <span className="ctx-val">
              {context?.install_scripts_run === true
                ? 'Yes'
                : context?.install_scripts_run === false
                ? 'No (Blocked)'
                : 'Not Specified'}
            </span>
          </div>
          <div className="print-context-item">
            <span className="ctx-label">Temporal Anchor (As of):</span>
            <span className="ctx-val">{formatDate(summary.as_of)}</span>
          </div>
        </div>
      </header>

      {/* ─── EXECUTIVE SCORECARD ─────────────────────────────────────────────────── */}
      <section className="print-section print-avoid-break">
        <h2 className="print-section-title">Executive Risk Overview</h2>
        <div className="print-scorecard-grid">
          {verdictCounts.map(v => (
            <div
              key={v.key}
              className="print-scorecard-cell"
              style={{ borderColor: v.color, backgroundColor: v.bg }}
            >
              <div className="print-scorecard-count" style={{ color: v.color }}>
                {v.count}
              </div>
              <div className="print-scorecard-label" style={{ color: v.color }}>
                {v.label}
              </div>
            </div>
          ))}
        </div>

        <div className="print-summary-details">
          <p>
            Scanned <strong>{summary.total_packages} total resolved dependencies</strong> (
            <strong>{summary.direct_packages} direct</strong>,{' '}
            <strong>{Math.max(0, summary.total_packages - summary.direct_packages)} transitive</strong>).
            {summary.incident > 0 && (
              <span className="print-alert-text">
                {' '}
                CRITICAL WARNING: {summary.incident} active malicious or compromised package(s) detected.
              </span>
            )}
            {summary.act_now > 0 && (
              <span className="print-warn-text">
                {' '}
                {summary.act_now} package(s) on production path require immediate out-of-cycle intervention (CISA KEV / high EPSS).
              </span>
            )}
          </p>
        </div>
      </section>

      {/* ─── DETAILED FINDINGS & DECISIONS ────────────────────────────────────────── */}
      <section className="print-section">
        <div className="print-section-header">
          <h2 className="print-section-title">
            Dependency Decisions & Evidence ({displayedDecisions.length}
            {options.actionableOnly ? ' Actionable Items' : ' Total Findings'})
          </h2>
          <span className="print-section-note">
            Top-down deterministic rules applied &bull; Evidence cited per package
          </span>
        </div>

        {displayedDecisions.length === 0 ? (
          <div className="print-empty-box">No findings to display under current filter settings.</div>
        ) : (
          <div className="print-decisions-list">
            {displayedDecisions.map((dec, idx) => {
              const decEv = dec.evidence_ids
                .map(id => evidenceMap.get(id))
                .filter((e): e is EvidenceRecord => !!e);
              const fixCmd = dec.response_steps.find(s => s.command)?.command;

              return (
                <div key={dec.subject || idx} className="print-decision-card print-avoid-break">
                  <div className="print-card-header">
                    <div className="print-card-left">
                      <span className={`print-verdict-tag verdict-${dec.verdict}`}>
                        {VERDICT_LABELS[dec.verdict] || dec.verdict}
                      </span>
                      <strong className="print-pkg-name">
                        {dec.name}@{dec.version}
                      </strong>
                      <span className="print-pkg-scope">
                        {dec.is_direct ? 'Direct dependency' : `Transitive (depth ${dec.depth})`} &bull;{' '}
                        Scope: {dec.exposure.scope}
                      </span>
                    </div>
                    <div className="print-card-right">
                      {dec.urgency && <span className="print-urgency-badge">Urgency: {dec.urgency}</span>}
                    </div>
                  </div>

                  <div className="print-card-body">
                    {/* What */}
                    <div className="print-field">
                      <span className="print-field-label">Finding:</span>
                      <span className="print-field-val print-what">{dec.what}</span>
                    </div>

                    {/* Rule fired / derivation */}
                    {dec.derivation && dec.derivation.length > 0 && (
                      <div className="print-field">
                        <span className="print-field-label">Rule Derivation:</span>
                        <code className="print-derivation">{dec.derivation.join('; ')}</code>
                      </div>
                    )}

                    {/* Dependency Paths */}
                    {options.includePaths && dec.exposure.paths && dec.exposure.paths.length > 0 && (
                      <div className="print-field">
                        <span className="print-field-label">Dependency Chain:</span>
                        <div className="print-path-list">
                          {dec.exposure.paths.slice(0, 2).map((p, pIdx) => (
                            <div key={pIdx} className="print-path-line">
                              {p.join(' &rarr; ')}
                            </div>
                          ))}
                          {dec.exposure.paths.length > 2 && (
                            <div className="print-path-more">
                              +{dec.exposure.paths.length - 2} additional path(s)
                            </div>
                          )}
                        </div>
                      </div>
                    )}

                    {/* Evidence cited */}
                    {options.includeEvidenceDetails && decEv.length > 0 && (
                      <div className="print-evidence-box">
                        <span className="print-field-label">Evidence Cited ({decEv.length}):</span>
                        <div className="print-evidence-grid">
                          {decEv.map(ev => (
                            <div key={ev.id} className="print-evidence-item">
                              <div className="print-ev-header">
                                <span className={`print-tier-tag tier-${ev.tier}`}>{ev.tier}</span>
                                <code>{ev.id}</code>
                                <span className="print-ev-source">
                                  {ev.source} &bull; {ev.origin}
                                </span>
                              </div>
                              <p className="print-ev-claim">{ev.claim}</p>
                              {ev.quote && (
                                <blockquote className="print-ev-quote">"{ev.quote}"</blockquote>
                              )}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Remediation & Command */}
                    {options.includeRemediation && dec.response_steps.length > 0 && (
                      <div className="print-remediation-box">
                        <span className="print-field-label">Required Remediation:</span>
                        <ul className="print-steps-list">
                          {dec.response_steps.map((st, sIdx) => (
                            <li key={sIdx}>
                              <span>{st.text}</span>
                              {st.command && (
                                <div className="print-cmd-box">
                                  <code>$ {st.command}</code>
                                </div>
                              )}
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </section>

      {/* ─── LICENSE COMPLIANCE TABLE ────────────────────────────────────────────── */}
      {options.includeLicenses && licenses && licenses.length > 0 && (
        <section className="print-section print-avoid-break">
          <div className="print-section-header">
            <h2 className="print-section-title">License Compliance & Legal Risks ({licenses.length})</h2>
            <span className="print-section-note">
              Evaluated against project context: {context?.project_license || 'Unknown'} /{' '}
              {context?.distribution_mode || 'Unknown'}
            </span>
          </div>

          <table className="print-table">
            <thead>
              <tr>
                <th style={{ width: '28%' }}>Package</th>
                <th style={{ width: '18%' }}>SPDX License</th>
                <th style={{ width: '14%' }}>Compliance</th>
                <th style={{ width: '10%' }}>Rule</th>
                <th style={{ width: '30%' }}>Assessment Note</th>
              </tr>
            </thead>
            <tbody>
              {licenses.map(l => (
                <tr key={l.subject}>
                  <td>
                    <code>
                      {l.name}@{l.version}
                    </code>
                  </td>
                  <td>
                    <span className="print-lic-expr">{l.license_expr || 'UNKNOWN'}</span>
                  </td>
                  <td>
                    <span className={`print-lic-badge lic-${l.license_status}`}>
                      {l.license_status.replace('_', ' ')}
                    </span>
                  </td>
                  <td>{l.rule_fired || '—'}</td>
                  <td className="print-table-note">{l.note || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}

      {/* ─── SECURITY COVERAGE & ASSURANCE CHECKLIST ──────────────────────────────── */}
      {options.includeCoverage && coverage && coverage.length > 0 && (
        <section className="print-section print-avoid-break">
          <div className="print-section-header">
            <h2 className="print-section-title">Analysis Coverage & Public Data Verification</h2>
            <span className="print-section-note">
              "Not run" checks are explicitly disclosed and never assumed safe
            </span>
          </div>

          <table className="print-table">
            <thead>
              <tr>
                <th style={{ width: '35%' }}>Security Check / Provider</th>
                <th style={{ width: '15%' }}>Status</th>
                <th style={{ width: '12%' }}>Items Evaluated</th>
                <th style={{ width: '38%' }}>Details / Omissions</th>
              </tr>
            </thead>
            <tbody>
              {coverage.map((c, i) => (
                <tr key={i}>
                  <td>
                    <strong>{c.check}</strong>
                  </td>
                  <td>
                    <span className={`print-cov-badge cov-${c.status.toLowerCase().replace(/\s+/g, '-')}`}>
                      {c.status}
                    </span>
                  </td>
                  <td>{c.count !== null && c.count !== undefined ? c.count : '—'}</td>
                  <td className="print-table-note">{c.reason || 'Executed as expected'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}

      {/* ─── AUDIT FOOTER & SIGN-OFF ─────────────────────────────────────────────── */}
      <footer className="print-footer print-avoid-break">
        <div className="print-footer-grid">
          <div>
            <strong>Warrant Methodology Notice</strong>
            <p>
              This report represents deterministic, evidence-backed supply chain risk evaluation computed
              from published rules (R1&ndash;R7, LR1&ndash;LR7). Evidence gathered from OSV.dev, CISA KEV,
              EPSS (FIRST.org), deps.dev, and registry metadata.
            </p>
          </div>
          <div>
            <strong>Audit & Disclaimer</strong>
            <p>
              Package-level dependency assessment. Not formal legal advice. No untrusted package code was
              executed during this analysis. Reproducible audit stamp: <code>{report.id}</code>.
            </p>
          </div>
        </div>
        <div className="print-page-stamp">
          Warrant Security Analyzer &bull; Confidential &bull; Generated {new Date().toLocaleDateString()}
        </div>
      </footer>
    </div>
  );
}

export default PrintReportDocument;
