import React, { useState, useEffect, useRef } from 'react';
import { useParams, Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import {
  X, Copy, Check, ChevronDown, ChevronRight, ExternalLink,
  AlertTriangle, Shield, Download, RefreshCw
} from 'lucide-react';
import { getReport, exportUrl, verifyDemo, simulateFix } from '../lib/api';
import { formatDate, formatDateShort, saveRecentReport } from '../lib/format';
import type {
  Report, Decision, EvidenceRecord, Verdict,
  LicenseResult, CoverageCheck
} from '../lib/types';
import { VERDICT_ORDER, VERDICT_LABELS, VERDICT_ICONS } from '../lib/types';

// ── Verdict chip ──────────────────────────────────────────────────────────────
function VerdictChip({ verdict }: { verdict: string }) {
  const label = VERDICT_LABELS[verdict as Verdict] || verdict;
  const icon = VERDICT_ICONS[verdict as Verdict] || '';
  return (
    <span className={`verdict-chip verdict-${verdict}`} aria-label={`Verdict: ${label}`}>
      <span aria-hidden>{icon}</span> {label}
    </span>
  );
}

// ── Copy button ───────────────────────────────────────────────────────────────
function CopyButton({ text, label = 'Copy' }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  async function copy() {
    try { await navigator.clipboard.writeText(text); } catch { return; }
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }
  return (
    <button onClick={copy} className="btn btn-ghost btn-sm btn-icon" aria-label={label} title={label}>
      {copied ? <Check size={14} aria-hidden /> : <Copy size={14} aria-hidden />}
    </button>
  );
}

// ── Evidence tier badge ───────────────────────────────────────────────────────
function TierBadge({ tier }: { tier: string }) {
  return <span className={`tier-badge tier-${tier}`}>{tier}</span>;
}

// ── Decision drawer ───────────────────────────────────────────────────────────
interface DrawerProps {
  decision: Decision;
  evidence: EvidenceRecord[];
  reportId: string;
  onClose: () => void;
}

function Drawer({ decision: dec, evidence: allEvidence, reportId, onClose }: DrawerProps) {
  const overlayRef = useRef<HTMLDivElement>(null);
  const closeRef = useRef<HTMLButtonElement>(null);
  const [verifyResult, setVerifyResult] = useState<Record<string, unknown> | null>(null);
  const [simResult, setSimResult] = useState<Record<string, unknown> | null>(null);
  const [simLoading, setSimLoading] = useState(false);
  const [unrunExpanded, setUnrunExpanded] = useState(false);

  useEffect(() => {
    closeRef.current?.focus();
    const handleEsc = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    document.addEventListener('keydown', handleEsc);
    return () => document.removeEventListener('keydown', handleEsc);
  }, [onClose]);

  const decEvidence = allEvidence.filter(e => dec.evidence_ids.includes(e.id));

  async function handleSimulate() {
    if (!dec.fixed_version) return;
    setSimLoading(true);
    try {
      const result = await simulateFix(reportId, dec.subject, dec.fixed_version) as Record<string, unknown>;
      setSimResult(result);
    } catch { }
    setSimLoading(false);
  }

  async function handleVerify() {
    const result = await verifyDemo() as Record<string, unknown>;
    setVerifyResult(result);
  }

  return (
    <>
      <div
        className="drawer-overlay"
        ref={overlayRef}
        onClick={onClose}
        aria-hidden="true"
      />
      <aside
        className="drawer"
        role="dialog"
        aria-modal="true"
        aria-labelledby="drawer-title"
      >
        <div className="drawer-header">
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', flexWrap: 'wrap', marginBottom: 'var(--space-2)' }}>
              <VerdictChip verdict={dec.verdict} />
              <span style={{ fontSize: 'var(--text-xs)', color: 'var(--color-muted)' }}>
                {dec.urgency} · {dec.qualifier}
              </span>
            </div>
            <h2 id="drawer-title" style={{ fontSize: 'var(--text-base)', fontWeight: 600 }}>
              <code className="purl">{dec.name}@{dec.version}</code>
            </h2>
          </div>
          <button
            ref={closeRef}
            onClick={onClose}
            className="btn btn-ghost btn-icon"
            aria-label="Close details panel"
          >
            <X size={18} aria-hidden />
          </button>
        </div>

        <div className="drawer-body">
          {/* WHAT */}
          <section aria-labelledby="drawer-what">
            <p className="drawer-section-title" id="drawer-what">What</p>
            <p style={{ fontSize: 'var(--text-sm)', lineHeight: 1.6 }}>{dec.what}</p>
          </section>

          {/* WHY IT MATTERS */}
          <section aria-labelledby="drawer-why">
            <p className="drawer-section-title" id="drawer-why">Why it matters</p>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)', fontSize: 'var(--text-sm)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--color-muted)' }}>Scope</span>
                <span style={{ fontWeight: 500 }}>{dec.exposure.scope}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--color-muted)' }}>Install scripts</span>
                <span>{dec.exposure.install_phase === 'observed' ? '⚠ Install script detected' : 'Not observed'}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--color-muted)' }}>Context</span>
                <span>{dec.exposure.scripts_enabled === 'assumed' ? 'Assumed (skipped)' : 'Declared'}</span>
              </div>
            </div>
          </section>

          {/* HOW WE KNOW */}
          <section aria-labelledby="drawer-evidence">
            <p className="drawer-section-title" id="drawer-evidence">How we know</p>
            {decEvidence.length === 0 ? (
              <p style={{ fontSize: 'var(--text-sm)', color: 'var(--color-muted)' }}>No evidence records attached.</p>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
                {decEvidence.map(e => (
                  <div
                    key={e.id}
                    style={{
                      padding: 'var(--space-3)',
                      border: '1px solid var(--color-border)',
                      borderRadius: 'var(--radius-md)',
                      fontSize: 'var(--text-xs)',
                      background: e.withdrawn ? 'var(--color-bg)' : undefined,
                      opacity: e.withdrawn ? 0.6 : 1,
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginBottom: 'var(--space-2)', flexWrap: 'wrap' }}>
                      <code style={{ fontFamily: 'var(--font-mono)', color: 'var(--color-muted)' }}>{e.id}</code>
                      <TierBadge tier={e.tier} />
                      {e.withdrawn && <span style={{ color: 'var(--verdict-cannot-fg)', fontWeight: 600 }}>[withdrawn]</span>}
                    </div>
                    <p style={{ fontWeight: 500, marginBottom: 'var(--space-1)' }}>{e.claim}</p>
                    <p style={{ color: 'var(--color-muted)' }}>
                      Source: {e.source} · Origin: {e.origin}
                      {e.published_at && ` · Published: ${formatDateShort(e.published_at)}`}
                    </p>
                    {e.quote && (
                      <blockquote style={{ marginTop: 'var(--space-2)', borderLeft: '3px solid var(--color-border)', paddingLeft: 'var(--space-3)', color: 'var(--color-muted)', fontStyle: 'italic' }}>
                        "{e.quote}"
                      </blockquote>
                    )}
                    {e.url && (
                      <a href={e.url} target="_blank" rel="noopener noreferrer" style={{ color: 'var(--color-accent)', display: 'inline-flex', alignItems: 'center', gap: 4, marginTop: 'var(--space-1)' }}>
                        Advisory <ExternalLink size={12} aria-hidden />
                      </a>
                    )}
                  </div>
                ))}
              </div>
            )}
          </section>

          {/* HOW CERTAIN */}
          <section aria-labelledby="drawer-certain">
            <p className="drawer-section-title" id="drawer-certain">How certain</p>
            <p style={{ fontSize: 'var(--text-sm)' }}>
              <strong>{dec.qualifier}</strong>
              {dec.open_defeaters.length > 0 && (
                <>
                  {' · '}Open defeaters:
                  <ul style={{ marginTop: 'var(--space-1)', paddingLeft: 'var(--space-4)' }}>
                    {dec.open_defeaters.map((d, i) => <li key={i}>{d}</li>)}
                  </ul>
                </>
              )}
            </p>
          </section>

          {/* PATH */}
          {dec.exposure.paths.length > 0 && (
            <section aria-labelledby="drawer-path">
              <p className="drawer-section-title" id="drawer-path">Why is this here? (dependency path)</p>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}>
                {dec.exposure.paths.slice(0, 3).map((path, i) => (
                  <ol key={i} style={{ paddingLeft: 'var(--space-4)', fontSize: 'var(--text-sm)', lineHeight: 2 }}>
                    {path.map((node, j) => (
                      <li key={j}>
                        <code style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)' }}>{node}</code>
                        {node.includes(dec.name) && dec.exposure.install_phase === 'observed' && (
                          <span style={{ marginLeft: 'var(--space-2)', color: 'var(--verdict-act-now-fg)', fontSize: 'var(--text-xs)' }}>
                            ⚠ install script
                          </span>
                        )}
                      </li>
                    ))}
                  </ol>
                ))}
              </div>
            </section>
          )}

          {/* CVSS IMPACT PROFILE */}
          {dec.cvss_vector && (
            <section aria-labelledby="drawer-impact">
              <p className="drawer-section-title" id="drawer-impact">Impact profile</p>
              <code style={{ fontSize: 'var(--text-xs)', fontFamily: 'var(--font-mono)', color: 'var(--color-muted)', wordBreak: 'break-all' }}>
                {dec.cvss_vector}
              </code>
              <p style={{ marginTop: 'var(--space-2)', fontSize: 'var(--text-xs)', color: 'var(--color-muted)', fontStyle: 'italic' }}>
                Read from the CVSS vector. This is not confirmed exploitability on your system.
              </p>
            </section>
          )}

          {/* WHAT TO DO */}
          {dec.response_steps.length > 0 && (
            <section aria-labelledby="drawer-todo">
              <p className="drawer-section-title" id="drawer-todo">What to do</p>
              <ol style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)', paddingLeft: 'var(--space-4)' }}>
                {dec.response_steps.map((step, i) => (
                  <li key={i} style={{ fontSize: 'var(--text-sm)', lineHeight: 1.6 }}>
                    {step.text}
                    {step.command && (
                      <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginTop: 'var(--space-1)' }}>
                        <code
                          style={{
                            display: 'block',
                            flex: 1,
                            padding: 'var(--space-2) var(--space-3)',
                            background: 'var(--color-bg)',
                            borderRadius: 'var(--radius-sm)',
                            fontFamily: 'var(--font-mono)',
                            fontSize: 'var(--text-xs)',
                            border: '1px solid var(--color-border)',
                            whiteSpace: 'pre-wrap',
                            wordBreak: 'break-all',
                          }}
                        >
                          {step.command}
                        </code>
                        <CopyButton text={step.command} label="Copy command" />
                      </div>
                    )}
                  </li>
                ))}
              </ol>

              {dec.fixed_version && (
                <div style={{ marginTop: 'var(--space-4)' }}>
                  <button
                    onClick={handleSimulate}
                    disabled={simLoading}
                    className="btn btn-secondary btn-sm"
                  >
                    <RefreshCw size={14} aria-hidden />
                    {simLoading ? 'Simulating…' : `Simulate fix → ${dec.fixed_version}`}
                  </button>
                  {simResult && (
                    <div className="callout callout-info" style={{ marginTop: 'var(--space-3)', fontSize: 'var(--text-xs)' }}>
                      <p><strong>Before:</strong> {String(((simResult as any).before as any)?.verdict)}</p>
                      <p><strong>After:</strong> {String(((simResult as any).after as any)?.verdict)}</p>
                      <p><strong>New risks found:</strong> {((simResult as any).new_risks as any[])?.length ?? 0}</p>
                      <p style={{ marginTop: 'var(--space-1)', fontStyle: 'italic' }}>{String((simResult as any).note)}</p>
                    </div>
                  )}
                </div>
              )}
            </section>
          )}

          {/* NOT CHECKED */}
          <section aria-labelledby="drawer-notchecked">
            <button
              style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', background: 'none', border: 'none', cursor: 'pointer', padding: 0, width: '100%' }}
              onClick={() => setUnrunExpanded(x => !x)}
              aria-expanded={unrunExpanded}
              aria-controls="not-checked-list"
            >
              <p className="drawer-section-title" id="drawer-notchecked" style={{ marginBottom: 0 }}>
                Not checked ({dec.unrun_checks.length})
              </p>
              {unrunExpanded ? <ChevronDown size={14} aria-hidden /> : <ChevronRight size={14} aria-hidden />}
            </button>
            {unrunExpanded && (
              <ul id="not-checked-list" style={{ marginTop: 'var(--space-2)', display: 'flex', flexDirection: 'column', gap: 'var(--space-1)', paddingLeft: 'var(--space-4)' }}>
                {dec.unrun_checks.length === 0
                  ? <li style={{ fontSize: 'var(--text-xs)', color: 'var(--color-muted)' }}>None — all required checks ran.</li>
                  : dec.unrun_checks.map((c, i) => (
                    <li key={i} style={{ fontSize: 'var(--text-xs)', color: 'var(--color-muted)' }}>{c}</li>
                  ))}
                <li style={{ fontSize: 'var(--text-xs)', color: 'var(--color-muted)' }}>
                  Reachability: not assessed (package-level paths only)
                </li>
              </ul>
            )}
          </section>

          {/* DERIVATION */}
          <section aria-labelledby="drawer-derivation">
            <p className="drawer-section-title" id="drawer-derivation">Derivation</p>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--space-1)' }}>
              {dec.derivation.map((d, i) => (
                <code
                  key={i}
                  style={{ fontSize: 'var(--text-xs)', fontFamily: 'var(--font-mono)', padding: '2px 6px', background: 'var(--color-bg)', border: '1px solid var(--color-border)', borderRadius: 'var(--radius-sm)' }}
                >
                  {d}
                </code>
              ))}
            </div>
            <p style={{ marginTop: 'var(--space-2)', fontSize: 'var(--text-xs)', color: 'var(--color-muted)' }}>
              <Link to="/methodology" style={{ color: 'var(--color-accent)' }}>View rule table</Link>
            </p>
          </section>

          {/* NARRATIVE */}
          <section aria-labelledby="drawer-narrative">
            <p className="drawer-section-title" id="drawer-narrative">Narrative</p>
            <div style={{ padding: 'var(--space-3)', background: 'var(--color-bg)', borderRadius: 'var(--radius-md)', fontSize: 'var(--text-xs)', lineHeight: 1.7, fontFamily: 'var(--font-sans)' }}>
              <p><strong>{dec.name}@{dec.version}</strong> — {VERDICT_LABELS[dec.verdict as Verdict]} ({dec.urgency})</p>
              <p style={{ marginTop: 4 }}>{dec.what}</p>
              <p style={{ marginTop: 4, color: 'var(--color-muted)' }}>Scope: {dec.exposure.scope}</p>
              {dec.fixed_version && <p style={{ marginTop: 4, color: 'var(--color-muted)' }}>Fixed in: {dec.fixed_version}</p>}
            </div>
            <p style={{ marginTop: 'var(--space-2)', fontSize: 'var(--text-xs)', color: 'var(--color-muted)', fontStyle: 'italic' }}>
              Generated from rules, no AI.
            </p>
            <button className="btn btn-ghost btn-sm" onClick={handleVerify} style={{ marginTop: 'var(--space-2)' }}>
              Run verifier self-test
            </button>
            {verifyResult && (
              <div className={`callout ${(verifyResult as any).passed ? 'callout-info' : 'callout-warn'}`} style={{ marginTop: 'var(--space-2)', fontSize: 'var(--text-xs)' }}>
                <p><strong>Gate:</strong> {String((verifyResult as any).gate)}</p>
                <p><strong>Passed:</strong> {String((verifyResult as any).passed)}</p>
                <p>{String((verifyResult as any).detail)}</p>
                {(verifyResult as any).note && <p style={{ fontStyle: 'italic', marginTop: 4 }}>{String((verifyResult as any).note)}</p>}
              </div>
            )}
          </section>
        </div>
      </aside>
    </>
  );
}

// ── Decision card ─────────────────────────────────────────────────────────────
interface CardProps {
  decision: Decision;
  onOpen: (d: Decision) => void;
}

function DecisionCard({ decision: dec, onOpen }: CardProps) {
  const [copyText, setCopyText] = useState('');

  const fixCmd = dec.response_steps.find(s => s.command)?.command;

  return (
    <div
      className="card"
      style={{
        borderLeft: `4px solid var(--verdict-${dec.verdict}-fg, var(--color-border))`,
        padding: 'var(--space-4) var(--space-5)',
        cursor: 'pointer',
        transition: 'box-shadow var(--duration-fast) var(--ease-out)',
      }}
      onClick={() => onOpen(dec)}
    >
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 'var(--space-4)', flexWrap: 'wrap' }}>
        <div style={{ flex: 1, minWidth: 200 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', flexWrap: 'wrap', marginBottom: 'var(--space-2)' }}>
            <VerdictChip verdict={dec.verdict} />
            <span style={{ fontSize: 'var(--text-xs)', color: 'var(--color-muted)' }}>
              {dec.is_direct ? 'direct' : `depth ${dec.depth}`} · {dec.exposure.scope}
            </span>
            {dec.exposure.install_phase === 'observed' && (
              <span style={{ fontSize: 'var(--text-xs)', color: 'var(--verdict-act-now-fg)' }}>⚠ install script</span>
            )}
          </div>
          <code className="purl">{dec.name}@{dec.version}</code>
          <p style={{ marginTop: 'var(--space-2)', fontSize: 'var(--text-sm)', color: 'var(--color-text)', lineHeight: 1.5 }}>
            {dec.what}
          </p>
          {dec.introduced_by.length > 0 && (
            <p style={{ marginTop: 'var(--space-1)', fontSize: 'var(--text-xs)', color: 'var(--color-muted)' }}>
              Via: {dec.introduced_by.slice(0, 2).join(', ')}
              {dec.introduced_by.length > 2 && ` +${dec.introduced_by.length - 2} more`}
            </p>
          )}
        </div>
        <div style={{ display: 'flex', gap: 'var(--space-2)', flexShrink: 0, alignItems: 'flex-start' }}>
          {fixCmd && <CopyButton text={fixCmd} label="Copy fix command" />}
          <button
            className="btn btn-secondary btn-sm"
            onClick={e => { e.stopPropagation(); onOpen(dec); }}
            aria-label={`Open details for ${dec.name}@${dec.version}`}
          >
            Details
          </button>
        </div>
      </div>

      {/* Not checked count — always visible */}
      <p style={{ marginTop: 'var(--space-3)', fontSize: 'var(--text-xs)', color: 'var(--color-muted)', borderTop: '1px solid var(--color-border)', paddingTop: 'var(--space-2)' }}>
        Not checked: {dec.unrun_checks.length > 0 ? dec.unrun_checks.length : 'none'} items
        {dec.unrun_checks.length > 0 && ` (open details for list)`}
        · Reachability: not assessed
      </p>
    </div>
  );
}

// ── Licenses tab ──────────────────────────────────────────────────────────────
function LicensesTab({ licenses }: { licenses: LicenseResult[] }) {
  const counts = { CONFLICT: 0, REVIEW: 0, UNKNOWN: 0, CANNOT_ASSESS: 0, OK: 0 };
  licenses.forEach(l => { if (l.license_status in counts) (counts as any)[l.license_status]++; });

  return (
    <div>
      <div style={{ display: 'flex', gap: 'var(--space-3)', flexWrap: 'wrap', marginBottom: 'var(--space-6)' }}>
        {Object.entries(counts).map(([k, v]) => (
          <div key={k} style={{ padding: 'var(--space-3) var(--space-4)', background: 'var(--color-surface)', border: '1px solid var(--color-border)', borderRadius: 'var(--radius-md)', textAlign: 'center', minWidth: 80 }}>
            <p style={{ fontSize: 'var(--text-xl)', fontWeight: 700 }}>{v}</p>
            <p style={{ fontSize: 'var(--text-xs)', color: 'var(--color-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>{k.replace('_', ' ')}</p>
          </div>
        ))}
      </div>
      <div className="table-wrapper">
        <table>
          <caption className="visually-hidden">License classification results</caption>
          <thead>
            <tr>
              <th scope="col">Package</th>
              <th scope="col">License</th>
              <th scope="col">Status</th>
              <th scope="col">Rule</th>
              <th scope="col">Note</th>
            </tr>
          </thead>
          <tbody>
            {licenses.map(l => (
              <tr key={l.subject}>
                <td><code className="purl">{l.name}@{l.version}</code></td>
                <td style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)' }}>{l.license_expr || '—'}</td>
                <td>
                  <span className={`verdict-chip verdict-${l.license_status === 'CONFLICT' ? 'INCIDENT' : l.license_status === 'OK' ? 'NO_KNOWN_FINDING' : 'REVIEW'}`}>
                    {l.license_status}
                  </span>
                </td>
                <td style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', color: 'var(--color-muted)' }}>{l.rule_fired || '—'}</td>
                <td style={{ fontSize: 'var(--text-xs)', color: 'var(--color-muted)', maxWidth: 300 }}>{l.note || '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p style={{ marginTop: 'var(--space-4)', fontSize: 'var(--text-xs)', color: 'var(--color-muted)', fontStyle: 'italic' }}>
        Rule-based flags for review, not legal advice. Results depend on the context answers provided.
      </p>
    </div>
  );
}

// ── Coverage tab ──────────────────────────────────────────────────────────────
function CoverageTab({ coverage }: { coverage: CoverageCheck[] }) {
  return (
    <div>
      <div className="callout callout-info" style={{ marginBottom: 'var(--space-4)' }}>
        <p style={{ fontSize: 'var(--text-sm)', fontWeight: 500 }}>What we checked and what we didn't</p>
        <p style={{ fontSize: 'var(--text-xs)', color: 'var(--color-muted)', marginTop: 'var(--space-1)' }}>
          Every row corresponds to real code that ran. "Not run" items are never treated as clean.
        </p>
      </div>
      <div className="table-wrapper">
        <table>
          <caption className="visually-hidden">Analysis coverage</caption>
          <thead>
            <tr>
              <th scope="col">Check</th>
              <th scope="col">Status</th>
              <th scope="col">Count</th>
              <th scope="col">Notes</th>
            </tr>
          </thead>
          <tbody>
            {coverage.map(c => (
              <tr key={c.check}>
                <td style={{ fontSize: 'var(--text-sm)' }}>{c.check}</td>
                <td>
                  <span style={{
                    fontSize: 'var(--text-xs)',
                    fontWeight: 600,
                    padding: '2px 8px',
                    borderRadius: 'var(--radius-full)',
                    background: c.status === 'Ran' ? '#DCFCE7' : c.status === 'Partial' ? 'var(--verdict-upgrade-bg)' : 'var(--color-bg)',
                    color: c.status === 'Ran' ? '#15803D' : c.status === 'Partial' ? 'var(--verdict-upgrade-fg)' : 'var(--color-muted)',
                  }}>
                    {c.status}
                  </span>
                </td>
                <td style={{ fontSize: 'var(--text-sm)', color: 'var(--color-muted)' }}>
                  {c.count !== undefined ? c.count : '—'}
                </td>
                <td style={{ fontSize: 'var(--text-xs)', color: 'var(--color-muted)' }}>{c.reason || '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ── Main report page ──────────────────────────────────────────────────────────
export default function ReportPage() {
  const { id } = useParams<{ id: string }>();
  const [activeTab, setActiveTab] = useState<'decisions' | 'graph' | 'licenses' | 'coverage'>('decisions');
  const [openDecision, setOpenDecision] = useState<Decision | null>(null);
  const [activeVerdicts, setActiveVerdicts] = useState<Set<string>>(new Set());
  const [search, setSearch] = useState('');

  const { data: report, isLoading, error } = useQuery({
    queryKey: ['report', id],
    queryFn: () => getReport(id!),
    enabled: !!id,
    refetchInterval: false,
  });

  // Save to recent reports
  useEffect(() => {
    if (report) {
      saveRecentReport({
        id: report.id,
        name: String(report.meta.filename || 'Report'),
        timestamp: report.created_at,
        summary: {
          incident: report.summary.incident,
          act_now: report.summary.act_now,
          total_packages: report.summary.total_packages,
        },
      });
    }
  }, [report]);

  if (isLoading) {
    return (
      <div className="container" style={{ paddingTop: 'var(--space-12)' }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
          {[1, 2, 3].map(i => (
            <div key={i} className="skeleton" style={{ height: 100, borderRadius: 'var(--radius-lg)' }} />
          ))}
        </div>
      </div>
    );
  }

  if (error || !report) {
    return (
      <div className="container" style={{ paddingTop: 'var(--space-12)', textAlign: 'center' }}>
        <Shield size={48} style={{ color: 'var(--color-border)', margin: '0 auto var(--space-4)' }} aria-hidden />
        <h1 style={{ fontSize: 'var(--text-xl)', fontWeight: 700, marginBottom: 'var(--space-2)' }}>Report not found</h1>
        <p style={{ color: 'var(--color-muted)', marginBottom: 'var(--space-6)' }}>
          This report has expired or never existed. Reports are kept for 24 hours.
        </p>
        <Link to="/analyze" className="btn btn-primary">Analyze a new lockfile</Link>
      </div>
    );
  }

  const { summary, decisions, evidence, licenses, coverage } = report;

  // Filter decisions
  const filtered = decisions
    .filter(d => {
      if (activeVerdicts.size > 0 && !activeVerdicts.has(d.verdict)) return false;
      if (search && !d.name.toLowerCase().includes(search.toLowerCase()) && !d.subject.toLowerCase().includes(search.toLowerCase())) return false;
      return true;
    })
    .sort((a, b) => (VERDICT_ORDER[a.verdict as Verdict] ?? 99) - (VERDICT_ORDER[b.verdict as Verdict] ?? 99));

  const verdictGroups = [
    { verdict: 'INCIDENT', label: 'Incident', count: summary.incident },
    { verdict: 'ACT_NOW', label: 'Act Now', count: summary.act_now },
    { verdict: 'UPGRADE', label: 'Upgrade', count: summary.upgrade },
    { verdict: 'MONITOR', label: 'Monitor', count: summary.monitor },
    { verdict: 'REVIEW', label: 'Review', count: summary.review },
    { verdict: 'CANNOT_ASSESS', label: 'Cannot Assess', count: summary.cannot_assess },
    { verdict: 'NO_KNOWN_FINDING', label: 'No Known Finding', count: summary.no_known_finding },
  ];

  function toggleVerdict(v: string) {
    setActiveVerdicts(prev => {
      const next = new Set(prev);
      next.has(v) ? next.delete(v) : next.add(v);
      return next;
    });
  }

  return (
    <div>
      {/* Header */}
      <div style={{ background: 'var(--color-surface)', borderBottom: '1px solid var(--color-border)', padding: 'var(--space-6) 0' }}>
        <div className="container">
          <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 'var(--space-4)', flexWrap: 'wrap' }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)', marginBottom: 'var(--space-2)', flexWrap: 'wrap' }}>
                <h1 style={{ fontSize: 'var(--text-lg)', fontWeight: 700 }}>
                  {String(report.meta.filename || 'Report')}
                </h1>
                <span className={`nav-badge ${summary.data_badge === 'LIVE' ? 'live' : 'recorded'}`}>
                  {summary.data_badge}
                </span>
                <span style={{ fontSize: 'var(--text-xs)', color: 'var(--color-muted)' }}>
                  {summary.ecosystem}
                </span>
              </div>
              <p style={{ fontSize: 'var(--text-xs)', color: 'var(--color-muted)' }}>
                {summary.total_packages} packages ({summary.direct_packages} direct) · As of {formatDate(summary.as_of)}
              </p>
            </div>
            <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
              <a href={exportUrl(report.id, 'json')} download className="btn btn-secondary btn-sm">
                <Download size={14} aria-hidden /> JSON
              </a>
              <a href={exportUrl(report.id, 'md')} download className="btn btn-secondary btn-sm">
                <Download size={14} aria-hidden /> Markdown
              </a>
              <Link to="/analyze" className="btn btn-ghost btn-sm">New analysis</Link>
            </div>
          </div>

          {/* Summary sentence */}
          <div
            style={{
              marginTop: 'var(--space-4)',
              padding: 'var(--space-4)',
              background: 'var(--color-bg)',
              borderRadius: 'var(--radius-md)',
              border: '1px solid var(--color-border)',
            }}
            aria-live="polite"
          >
            <p style={{ fontSize: 'var(--text-lg)', fontWeight: 600, lineHeight: 1.5 }}>
              {summary.incident > 0 && <span style={{ color: 'var(--verdict-incident-fg)' }}>{summary.incident} incident · </span>}
              {summary.act_now > 0 && <span style={{ color: 'var(--verdict-act-now-fg)' }}>{summary.act_now} act now · </span>}
              {summary.upgrade > 0 && <span style={{ color: 'var(--verdict-upgrade-fg)' }}>{summary.upgrade} upgrade · </span>}
              {summary.monitor > 0 && <span style={{ color: 'var(--verdict-monitor-fg)' }}>{summary.monitor} monitor · </span>}
              {summary.review > 0 && <span style={{ color: 'var(--verdict-review-fg)' }}>{summary.review} review · </span>}
              {summary.cannot_assess > 0 && <span>{summary.cannot_assess} cannot assess · </span>}
              <span style={{ color: 'var(--color-muted)' }}>across {summary.total_packages} packages</span>
            </p>
            <p style={{ fontSize: 'var(--text-xs)', color: 'var(--color-muted)', marginTop: 'var(--space-1)' }}>
              Counts are unique package versions. Cannot-assess items are not safe items.
            </p>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div style={{ background: 'var(--color-surface)', borderBottom: '1px solid var(--color-border)', position: 'sticky', top: 'var(--nav-height)', zIndex: 40 }}>
        <div className="container">
          <div className="tabs" role="tablist" aria-label="Report tabs">
            {[
              { id: 'decisions', label: 'Decisions', count: decisions.length },
              { id: 'graph', label: 'Graph', count: null },
              { id: 'licenses', label: 'Licenses', count: licenses.length },
              { id: 'coverage', label: 'Coverage', count: coverage.length },
            ].map(tab => (
              <button
                key={tab.id}
                role="tab"
                aria-selected={activeTab === tab.id}
                aria-controls={`tab-panel-${tab.id}`}
                id={`tab-${tab.id}`}
                className={`tab-btn${activeTab === tab.id ? ' active' : ''}`}
                onClick={() => setActiveTab(tab.id as typeof activeTab)}
              >
                {tab.label}
                {tab.count !== null && <span className="tab-count">{tab.count}</span>}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Tab content */}
      <div className="container" style={{ paddingTop: 'var(--space-6)', paddingBottom: 'var(--space-16)' }}>
        {/* Decisions tab */}
        {activeTab === 'decisions' && (
          <div role="tabpanel" id="tab-panel-decisions" aria-labelledby="tab-decisions">
            {/* Filter chips */}
            <div style={{ display: 'flex', gap: 'var(--space-2)', flexWrap: 'wrap', marginBottom: 'var(--space-4)', alignItems: 'center' }}>
              {verdictGroups.filter(g => g.count > 0).map(g => (
                <button
                  key={g.verdict}
                  onClick={() => toggleVerdict(g.verdict)}
                  className={`verdict-chip verdict-${g.verdict}`}
                  style={{
                    cursor: 'pointer',
                    opacity: activeVerdicts.size === 0 || activeVerdicts.has(g.verdict) ? 1 : 0.4,
                    border: '1px solid',
                    fontWeight: 600,
                    minHeight: 32,
                  }}
                  aria-pressed={activeVerdicts.has(g.verdict)}
                >
                  {g.label} {g.count}
                </button>
              ))}
              <input
                type="search"
                placeholder="Filter by name…"
                value={search}
                onChange={e => setSearch(e.target.value)}
                className="input"
                style={{ maxWidth: 220, marginLeft: 'auto' }}
                aria-label="Filter decisions by package name"
              />
            </div>

            {filtered.length === 0 && (
              <div style={{ textAlign: 'center', paddingTop: 'var(--space-12)', color: 'var(--color-muted)' }}>
                <Shield size={48} style={{ margin: '0 auto var(--space-4)', color: 'var(--color-border)' }} aria-hidden />
                <p>No decisions match your filter.</p>
              </div>
            )}

            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
              {filtered.map(dec => (
                <DecisionCard
                  key={dec.subject}
                  decision={dec}
                  onOpen={setOpenDecision}
                />
              ))}
            </div>

            {/* No known finding summary */}
            {summary.no_known_finding > 0 && (
              <details style={{ marginTop: 'var(--space-6)' }}>
                <summary
                  style={{ fontSize: 'var(--text-sm)', fontWeight: 500, cursor: 'pointer', padding: 'var(--space-3)', background: 'var(--color-surface)', border: '1px solid var(--color-border)', borderRadius: 'var(--radius-md)' }}
                >
                  {summary.no_known_finding} package{summary.no_known_finding !== 1 ? 's' : ''} with no known finding
                  — <em>not safe, all checks ran</em>
                </summary>
                <p style={{ fontSize: 'var(--text-xs)', color: 'var(--color-muted)', padding: 'var(--space-3)', borderTop: '1px solid var(--color-border)' }}>
                  These packages had all required checks run with nothing found as of {formatDate(summary.as_of)}.
                  This is not a guarantee of safety — public data may lag behind actual events.
                </p>
              </details>
            )}
          </div>
        )}

        {/* Graph tab */}
        {activeTab === 'graph' && (
          <div role="tabpanel" id="tab-panel-graph" aria-labelledby="tab-graph">
            <div className="callout callout-info" style={{ marginBottom: 'var(--space-4)' }}>
              <p style={{ fontSize: 'var(--text-sm)' }}>
                <strong>{report.graph.nodes.length}</strong> nodes and{' '}
                <strong>{report.graph.edges.length}</strong> edges in the dependency graph.
                Select a decision to see its path.
              </p>
            </div>

            {/* Text path alternative (accessibility) */}
            <div>
              <h2 style={{ fontSize: 'var(--text-base)', fontWeight: 600, marginBottom: 'var(--space-4)' }}>
                Dependency paths (text view)
              </h2>
              {decisions.filter(d => d.exposure.paths.length > 0).slice(0, 20).map(dec => (
                <div key={dec.subject} style={{ marginBottom: 'var(--space-4)' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginBottom: 'var(--space-2)' }}>
                    <span className={`verdict-chip verdict-${dec.verdict}`}>{VERDICT_LABELS[dec.verdict as Verdict]}</span>
                    <code className="purl">{dec.name}@{dec.version}</code>
                  </div>
                  <ol style={{ paddingLeft: 'var(--space-6)', fontSize: 'var(--text-xs)', fontFamily: 'var(--font-mono)', lineHeight: 2, color: 'var(--color-muted)' }}>
                    {dec.exposure.paths[0]?.map((node, i) => (
                      <li key={i}>{node}{node.includes(dec.name) && dec.exposure.install_phase === 'observed' ? ' ⚠' : ''}</li>
                    ))}
                  </ol>
                </div>
              ))}
              <p style={{ fontSize: 'var(--text-xs)', color: 'var(--color-muted)', fontStyle: 'italic' }}>
                Visual graph view (Cytoscape) can be added as an enhancement. Text path above is the accessible alternative.
              </p>
            </div>
          </div>
        )}

        {/* Licenses tab */}
        {activeTab === 'licenses' && (
          <div role="tabpanel" id="tab-panel-licenses" aria-labelledby="tab-licenses">
            <LicensesTab licenses={licenses} />
          </div>
        )}

        {/* Coverage tab */}
        {activeTab === 'coverage' && (
          <div role="tabpanel" id="tab-panel-coverage" aria-labelledby="tab-coverage">
            <CoverageTab coverage={coverage} />
          </div>
        )}
      </div>

      {/* Drawer */}
      {openDecision && (
        <Drawer
          decision={openDecision}
          evidence={evidence}
          reportId={report.id}
          onClose={() => setOpenDecision(null)}
        />
      )}
    </div>
  );
}
