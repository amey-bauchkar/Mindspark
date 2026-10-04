import React, { useState, useEffect, useRef } from 'react';
import {
  X,
  ExternalLink,
  RefreshCw,
  ShieldAlert,
  GitBranch,
  CheckCircle2,
  AlertOctagon,
  FileText,
  Activity,
  ChevronDown,
  ChevronUp,
  Terminal,
  ShieldCheck,
} from 'lucide-react';
import { simulateFix, verifyDemo } from '../../lib/api';
import { formatDateShort, safeHref } from '../../lib/format';
import type { Decision, EvidenceRecord } from '../../lib/types';
import { VerdictChip } from '../ui/VerdictChip';
import { TierBadge } from '../ui/TierBadge';
import { CopyButton } from '../ui/CopyButton';

interface DecisionDrawerProps {
  decision: Decision;
  evidence: EvidenceRecord[];
  reportId: string;
  onClose: () => void;
}

export function DecisionDrawer({
  decision: dec,
  evidence: allEvidence,
  reportId,
  onClose,
}: DecisionDrawerProps) {
  const overlayRef = useRef<HTMLDivElement>(null);
  const closeRef = useRef<HTMLButtonElement>(null);
  const [verifyResult, setVerifyResult] = useState<Record<string, unknown> | null>(null);
  const [simResult, setSimResult] = useState<Record<string, unknown> | null>(null);
  const [simLoading, setSimLoading] = useState(false);
  const [unrunExpanded, setUnrunExpanded] = useState(false);

  useEffect(() => {
    closeRef.current?.focus();
    const handleEsc = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', handleEsc);
    return () => document.removeEventListener('keydown', handleEsc);
  }, [onClose]);

  const decEvidence = allEvidence.filter(e => dec.evidence_ids.includes(e.id));

  async function handleSimulate() {
    if (!dec.fixed_version) return;
    setSimLoading(true);
    try {
      const result = (await simulateFix(
        reportId,
        dec.subject,
        dec.fixed_version
      )) as Record<string, unknown>;
      setSimResult(result);
    } catch {
      // ignore
    }
    setSimLoading(false);
  }

  async function handleVerify() {
    const result = (await verifyDemo()) as Record<string, unknown>;
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
        {/* Sticky Header */}
        <div className="drawer-header">
          <div>
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 'var(--space-2)',
                flexWrap: 'wrap',
                marginBottom: 'var(--space-2)',
              }}
            >
              <VerdictChip verdict={dec.verdict} />
              <span
                style={{
                  fontSize: 'var(--text-xs)',
                  color: 'var(--color-muted)',
                  fontWeight: 600,
                  backgroundColor: 'var(--color-bg-subtle)',
                  padding: '2px 8px',
                  borderRadius: 'var(--radius-sm)',
                  border: '1px solid var(--color-border)',
                }}
              >
                {dec.urgency} · {dec.qualifier}
              </span>
            </div>
            <h2 id="drawer-title" style={{ fontSize: 'var(--text-lg)', fontWeight: 800, color: 'var(--color-text)', display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
              <code className="purl" style={{ fontSize: 'var(--text-base)', fontWeight: 700 }}>
                {dec.name}@{dec.version}
              </code>
              <CopyButton text={`${dec.name}@${dec.version}`} label="Copy package purl" />
            </h2>
          </div>
          <button
            ref={closeRef}
            onClick={onClose}
            className="btn btn-ghost btn-icon"
            aria-label="Close details panel"
            style={{ borderRadius: 'var(--radius-md)', border: '1px solid var(--color-border)' }}
          >
            <X size={18} aria-hidden />
          </button>
        </div>

        <div className="drawer-body">
          {/* WHAT (Core Finding Summary) */}
          <section aria-labelledby="drawer-what" className="card" style={{ padding: 'var(--space-4) var(--space-5)' }}>
            <p className="drawer-section-title" id="drawer-what">
              <FileText size={14} style={{ color: 'var(--color-accent)' }} /> What
            </p>
            <p style={{ fontSize: 'var(--text-sm)', lineHeight: 1.65, color: 'var(--color-text)', fontWeight: 500 }}>
              {dec.what}
            </p>
          </section>

          {/* WHY IT MATTERS (Exposure Profile) */}
          <section aria-labelledby="drawer-why" className="card" style={{ padding: 'var(--space-4) var(--space-5)' }}>
            <p className="drawer-section-title" id="drawer-why">
              <Activity size={14} style={{ color: 'var(--color-accent)' }} /> Exposure Profile & Context
            </p>
            <div
              style={{
                display: 'flex',
                flexDirection: 'column',
                gap: 'var(--space-3)',
                fontSize: 'var(--text-sm)',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ color: 'var(--color-muted)', fontWeight: 500 }}>Dependency Scope</span>
                <span style={{ fontWeight: 700, color: dec.exposure.scope === 'prod' ? 'var(--verdict-incident-fg)' : 'var(--color-text)' }}>
                  {dec.exposure.scope.toUpperCase()}
                </span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ color: 'var(--color-muted)', fontWeight: 500 }}>Install Lifecycle Scripts</span>
                <span style={{ fontWeight: 600 }}>
                  {dec.exposure.install_phase === 'observed' ? (
                    <span style={{ color: 'var(--verdict-act-now-fg)', background: 'var(--verdict-act-now-bg)', padding: '2px 8px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--verdict-act-now-border)' }}>
                      ⚠ Install script detected
                    </span>
                  ) : (
                    <span style={{ color: 'var(--color-muted)' }}>Not observed</span>
                  )}
                </span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ color: 'var(--color-muted)', fontWeight: 500 }}>Execution Assumption</span>
                <span style={{ color: 'var(--color-text-secondary)', fontWeight: 600 }}>
                  {dec.exposure.scripts_enabled === 'assumed' ? 'Assumed (runtime)' : 'Declared in manifest'}
                </span>
              </div>
            </div>
          </section>

          {/* HOW WE KNOW (Verifiable Evidence Records) */}
          <section aria-labelledby="drawer-evidence">
            <p className="drawer-section-title" id="drawer-evidence">
              <ShieldAlert size={14} style={{ color: 'var(--color-accent)' }} /> How We Know (Evidence Chain)
            </p>
            {decEvidence.length === 0 ? (
              <div className="card" style={{ padding: 'var(--space-4)', textAlign: 'center' }}>
                <p style={{ fontSize: 'var(--text-sm)', color: 'var(--color-muted)' }}>
                  No evidence records attached to this decision.
                </p>
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
                {decEvidence.map(e => (
                  <div
                    key={e.id}
                    className="card"
                    style={{
                      padding: 'var(--space-4)',
                      background: e.withdrawn ? 'var(--color-bg-subtle)' : 'var(--color-surface)',
                      opacity: e.withdrawn ? 0.65 : 1,
                      borderLeft: e.tier === 'T1' ? '4px solid var(--verdict-incident-fg)' : '1px solid var(--color-border)',
                    }}
                  >
                    <div
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        gap: 'var(--space-2)',
                        marginBottom: 'var(--space-2)',
                        flexWrap: 'wrap',
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
                        <code
                          style={{
                            fontFamily: 'var(--font-sans)',
                            color: 'var(--color-text-secondary)',
                            fontWeight: 700,
                            fontSize: 'var(--text-xs)',
                          }}
                        >
                          {e.id}
                        </code>
                        <TierBadge tier={e.tier} />
                      </div>
                      {e.withdrawn && (
                        <span style={{ color: 'var(--verdict-cannot-fg)', fontWeight: 700, fontSize: 'var(--text-xs)' }}>
                          [WITHDRAWN RECORD]
                        </span>
                      )}
                    </div>

                    <p style={{ fontWeight: 700, fontSize: 'var(--text-sm)', color: 'var(--color-text)', marginBottom: 'var(--space-2)' }}>
                      {e.claim}
                    </p>

                    <div
                      style={{
                        fontSize: 'var(--text-xs)',
                        color: 'var(--color-muted)',
                        display: 'flex',
                        flexWrap: 'wrap',
                        gap: 'var(--space-2)',
                        marginBottom: e.quote || e.url ? 'var(--space-2)' : 0,
                      }}
                    >
                      <span>Source: <strong style={{ color: 'var(--color-text)' }}>{e.source}</strong></span>
                      <span>·</span>
                      <span>Origin: {e.origin}</span>
                      {e.published_at && (
                        <>
                          <span>·</span>
                          <span>Published: {formatDateShort(e.published_at)}</span>
                        </>
                      )}
                    </div>

                    {e.quote && (
                      <blockquote
                        style={{
                          marginTop: 'var(--space-2)',
                          borderLeft: '3px solid var(--color-border-strong)',
                          paddingLeft: 'var(--space-3)',
                          color: 'var(--color-text-secondary)',
                          fontSize: 'var(--text-xs)',
                          fontStyle: 'italic',
                          background: 'var(--color-bg-subtle)',
                          padding: 'var(--space-2) var(--space-3)',
                          borderRadius: '0 var(--radius-sm) var(--radius-sm) 0',
                        }}
                      >
                        "{e.quote}"
                      </blockquote>
                    )}

                    {safeHref(e.url) && (
                      <div style={{ marginTop: 'var(--space-3)' }}>
                        <a
                          href={safeHref(e.url)}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="btn btn-secondary btn-sm"
                          style={{ display: 'inline-flex', gap: '6px' }}
                        >
                          <span>Open Public Advisory</span>
                          <ExternalLink size={12} aria-hidden />
                        </a>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </section>

          {/* HOW CERTAIN (Qualifier & Defeaters) */}
          <section aria-labelledby="drawer-certain" className="card" style={{ padding: 'var(--space-4) var(--space-5)' }}>
            <p className="drawer-section-title" id="drawer-certain">
              <CheckCircle2 size={14} style={{ color: 'var(--color-accent)' }} /> Verification Certainty
            </p>
            <div style={{ fontSize: 'var(--text-sm)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
                <span style={{ color: 'var(--color-muted)' }}>Confidence qualifier:</span>
                <strong style={{ color: 'var(--color-text)', textTransform: 'uppercase', letterSpacing: '0.02em' }}>
                  {dec.qualifier}
                </strong>
              </div>
              {dec.open_defeaters.length > 0 && (
                <div style={{ marginTop: 'var(--space-3)', borderTop: '1px solid var(--color-border-subtle)', paddingTop: 'var(--space-2)' }}>
                  <p style={{ fontWeight: 600, color: 'var(--verdict-act-now-fg)', fontSize: 'var(--text-xs)', marginBottom: 'var(--space-1)' }}>
                    Open defeaters requiring manual review:
                  </p>
                  <ul style={{ paddingLeft: 'var(--space-4)', fontSize: 'var(--text-xs)', color: 'var(--color-text-secondary)', lineHeight: 1.7 }}>
                    {dec.open_defeaters.map((d, i) => (
                      <li key={i}>{d}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </section>

          {/* DEPENDENCY PATH */}
          {dec.exposure.paths.length > 0 && (
            <section aria-labelledby="drawer-path" className="card" style={{ padding: 'var(--space-4) var(--space-5)' }}>
              <p className="drawer-section-title" id="drawer-path">
                <GitBranch size={14} style={{ color: 'var(--color-accent)' }} /> Why is this here? (Dependency Path)
              </p>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
                {dec.exposure.paths.slice(0, 3).map((path, i) => (
                  <div
                    key={i}
                    style={{
                      background: 'var(--color-bg-subtle)',
                      borderRadius: 'var(--radius-md)',
                      padding: 'var(--space-3)',
                      border: '1px solid var(--color-border)',
                    }}
                  >
                    <ol
                      style={{
                        paddingLeft: 'var(--space-4)',
                        fontSize: 'var(--text-xs)',
                        lineHeight: 1.8,
                      }}
                    >
                      {path.map((node, j) => (
                        <li key={j}>
                          <code style={{ fontFamily: 'var(--font-sans)', fontWeight: node.includes(dec.name) ? 700 : 500 }}>
                            {node}
                          </code>
                          {node.includes(dec.name) && dec.exposure.install_phase === 'observed' && (
                            <span
                              style={{
                                marginLeft: 'var(--space-2)',
                                color: 'var(--verdict-act-now-fg)',
                                fontWeight: 700,
                              }}
                            >
                              ⚠ install script
                            </span>
                          )}
                        </li>
                      ))}
                    </ol>
                  </div>
                ))}
              </div>
            </section>
          )}

          {/* CVSS IMPACT PROFILE */}
          {dec.cvss_vector && (
            <section aria-labelledby="drawer-impact" className="card" style={{ padding: 'var(--space-4) var(--space-5)' }}>
              <p className="drawer-section-title" id="drawer-impact">
                <AlertOctagon size={14} style={{ color: 'var(--color-accent)' }} /> CVSS Vector Profile
              </p>
              <code
                style={{
                  fontSize: 'var(--text-xs)',
                  fontFamily: 'var(--font-sans)',
                  color: 'var(--color-text)',
                  wordBreak: 'break-all',
                  display: 'block',
                  background: 'var(--color-bg-subtle)',
                  padding: 'var(--space-2) var(--space-3)',
                  borderRadius: 'var(--radius-sm)',
                  border: '1px solid var(--color-border)',
                }}
              >
                {dec.cvss_vector}
              </code>
              <p
                style={{
                  marginTop: 'var(--space-2)',
                  fontSize: 'var(--text-2xs)',
                  color: 'var(--color-muted)',
                }}
              >
                Read directly from the vulnerability CVSS vector. This describes theoretical vulnerability characteristics, not confirmed host exploitation.
              </p>
            </section>
          )}

          {/* WHAT TO DO / SIMULATE FIX WORKBENCH */}
          <section aria-labelledby="drawer-actions" className="card" style={{ padding: 'var(--space-5)' }}>
            <p className="drawer-section-title" id="drawer-actions">
              <Terminal size={14} style={{ color: 'var(--color-accent)' }} /> Remediation & Simulation
            </p>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
              {dec.response_steps.map((step, i) => (
                <div key={i} style={{ fontSize: 'var(--text-sm)' }}>
                  <p style={{ fontWeight: 600, color: 'var(--color-text)', marginBottom: 'var(--space-1)' }}>
                    {step.text}
                  </p>
                  {step.command && (
                    <div
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: 'var(--space-2)',
                        marginTop: 'var(--space-2)',
                      }}
                    >
                      <pre
                        style={{
                          margin: 0,
                          flex: 1,
                          fontSize: 'var(--text-xs)',
                          overflowX: 'auto',
                          background: 'var(--color-bg-subtle)',
                          padding: '10px 14px',
                          borderRadius: 'var(--radius-md)',
                          border: '1px solid var(--color-border)',
                          fontFamily: 'var(--font-sans)',
                          color: 'var(--color-text)',
                        }}
                      >
                        <code>{step.command}</code>
                      </pre>
                      <CopyButton text={step.command} label="Copy command" />
                    </div>
                  )}
                </div>
              ))}
            </div>

            {/* Simulate Fix Workbench */}
            {dec.fixed_version && (
              <div
                style={{
                  marginTop: 'var(--space-5)',
                  paddingTop: 'var(--space-4)',
                  borderTop: '1px solid var(--color-border)',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 'var(--space-2)', marginBottom: 'var(--space-2)' }}>
                  <div>
                    <p style={{ fontSize: 'var(--text-xs)', fontWeight: 700, color: 'var(--color-text)' }}>
                      Interactive Fix Simulation
                    </p>
                    <p style={{ fontSize: 'var(--text-2xs)', color: 'var(--color-muted)' }}>
                      Re-run deterministic decision rules against target fix {dec.fixed_version}
                    </p>
                  </div>
                  <button
                    onClick={handleSimulate}
                    disabled={simLoading}
                    className="btn btn-primary btn-sm"
                  >
                    <RefreshCw
                      size={14}
                      aria-hidden
                      className={simLoading ? 'animate-spin' : ''}
                    />
                    <span>Simulate Upgrade</span>
                  </button>
                </div>

                {simResult && (
                  <div
                    className="callout callout-info"
                    style={{ marginTop: 'var(--space-3)', borderRadius: 'var(--radius-md)' }}
                  >
                    <p style={{ fontWeight: 700, fontSize: 'var(--text-xs)', marginBottom: 'var(--space-1)' }}>
                      Simulated result (same decision rules, nothing installed):
                    </p>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', margin: 'var(--space-2) 0' }}>
                      <span style={{ fontSize: 'var(--text-xs)', color: 'var(--color-muted)' }}>Before:</span>
                      <VerdictChip
                        verdict={(simResult.before as Record<string, string>)?.verdict || ''}
                      />
                      <span style={{ color: 'var(--color-muted)' }}>➔</span>
                      <span style={{ fontSize: 'var(--text-xs)', color: 'var(--color-muted)' }}>After:</span>
                      <VerdictChip
                        verdict={(simResult.after as Record<string, string>)?.verdict || ''}
                      />
                    </div>
                    {Array.isArray(simResult.new_risks) && simResult.new_risks.length > 0 && (
                      <ul style={{ fontSize: 'var(--text-xs)', margin: '0 0 var(--space-2)', paddingLeft: 'var(--space-4)' }}>
                        {(simResult.new_risks as { id: string; claim: string }[]).slice(0, 5).map(r => (
                          <li key={r.id}>{r.claim}</li>
                        ))}
                      </ul>
                    )}
                    {Array.isArray(simResult.checks_incomplete) && simResult.checks_incomplete.length > 0 && (
                      <p style={{ color: 'var(--verdict-upgrade-fg)', fontSize: 'var(--text-xs)', marginBottom: 'var(--space-1)' }}>
                        Not fully checked: {(simResult.checks_incomplete as string[]).join('; ')}
                      </p>
                    )}
                    <p style={{ color: 'var(--color-text-secondary)', fontSize: 'var(--text-xs)' }}>
                      {String(simResult.note || '')}
                    </p>
                  </div>
                )}
              </div>
            )}
          </section>

          {/* NARRATOR VERIFIER SELF-TEST */}
          <section aria-labelledby="drawer-verifier" className="card" style={{ padding: 'var(--space-5)' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 'var(--space-2)', marginBottom: 'var(--space-2)' }}>
              <div>
                <p className="drawer-section-title" id="drawer-verifier" style={{ margin: 0 }}>
                  <ShieldCheck size={14} style={{ color: 'var(--color-accent)' }} /> Narrator Verifier Self-Test
                </p>
                <p style={{ fontSize: 'var(--text-2xs)', color: 'var(--color-muted)', marginTop: '2px' }}>
                  Injects corrupt claim to verify gate rejection logic before UI rendering.
                </p>
              </div>
              <button onClick={handleVerify} className="btn btn-secondary btn-sm">
                Run Gate Test
              </button>
            </div>

            {verifyResult && (
              <div
                className={`callout ${verifyResult.passed ? 'callout-info' : 'callout-error'}`}
                style={{ marginTop: 'var(--space-3)', borderRadius: 'var(--radius-md)' }}
              >
                <p style={{ fontWeight: 700, fontSize: 'var(--text-xs)' }}>
                  {verifyResult.passed ? '✓ Passed Verification' : '✗ REJECTED by Gate: ' + verifyResult.gate}
                </p>
                <p style={{ fontSize: 'var(--text-xs)', marginTop: 2 }}>{String(verifyResult.detail || '')}</p>
                <p style={{ color: 'var(--color-muted)', fontSize: 'var(--text-2xs)', marginTop: 4 }}>
                  {String(verifyResult.note || '')}
                </p>
              </div>
            )}
          </section>

          {/* NOT CHECKED (Explicit Unknowns) */}
          <section aria-labelledby="drawer-not-checked" className="card" style={{ padding: 'var(--space-3) var(--space-4)' }}>
            <button
              onClick={() => setUnrunExpanded(x => !x)}
              style={{
                background: 'none',
                border: 'none',
                cursor: 'pointer',
                textAlign: 'left',
                width: '100%',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: 'var(--space-1) 0',
              }}
              aria-expanded={unrunExpanded}
              aria-controls="unrun-list"
            >
              <span
                style={{
                  fontSize: 'var(--text-xs)',
                  fontWeight: 700,
                  color: 'var(--color-muted)',
                  textTransform: 'uppercase',
                  letterSpacing: '0.05em',
                }}
              >
                Not checked ({dec.unrun_checks.length} items)
              </span>
              <span style={{ fontSize: 'var(--text-xs)', color: 'var(--color-muted)' }}>
                {unrunExpanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
              </span>
            </button>
            {unrunExpanded && (
              <ul
                id="unrun-list"
                style={{
                  marginTop: 'var(--space-3)',
                  paddingLeft: 'var(--space-4)',
                  fontSize: 'var(--text-xs)',
                  color: 'var(--color-muted)',
                  lineHeight: 1.8,
                  borderTop: '1px solid var(--color-border-subtle)',
                  paddingTop: 'var(--space-2)',
                }}
              >
                {dec.unrun_checks.map((uc, i) => (
                  <li key={i}>{uc}</li>
                ))}
              </ul>
            )}
          </section>
        </div>
      </aside>
    </>
  );
}

export default DecisionDrawer;

