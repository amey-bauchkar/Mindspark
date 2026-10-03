import React, { useState, useEffect, useRef } from 'react';
import { X, ExternalLink, RefreshCw } from 'lucide-react';
import { simulateFix, verifyDemo } from '../../lib/api';
import { formatDateShort } from '../../lib/format';
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
              <span style={{ fontSize: 'var(--text-xs)', color: 'var(--color-muted)' }}>
                {dec.urgency} · {dec.qualifier}
              </span>
            </div>
            <h2 id="drawer-title" style={{ fontSize: 'var(--text-base)', fontWeight: 600 }}>
              <code className="purl">
                {dec.name}@{dec.version}
              </code>
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
            <p className="drawer-section-title" id="drawer-what">
              What
            </p>
            <p style={{ fontSize: 'var(--text-sm)', lineHeight: 1.6 }}>{dec.what}</p>
          </section>

          {/* WHY IT MATTERS */}
          <section aria-labelledby="drawer-why">
            <p className="drawer-section-title" id="drawer-why">
              Why it matters
            </p>
            <div
              style={{
                display: 'flex',
                flexDirection: 'column',
                gap: 'var(--space-2)',
                fontSize: 'var(--text-sm)',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--color-muted)' }}>Scope</span>
                <span style={{ fontWeight: 500 }}>{dec.exposure.scope}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--color-muted)' }}>Install scripts</span>
                <span>
                  {dec.exposure.install_phase === 'observed'
                    ? '⚠ Install script detected'
                    : 'Not observed'}
                </span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--color-muted)' }}>Context</span>
                <span>
                  {dec.exposure.scripts_enabled === 'assumed' ? 'Assumed (skipped)' : 'Declared'}
                </span>
              </div>
            </div>
          </section>

          {/* HOW WE KNOW */}
          <section aria-labelledby="drawer-evidence">
            <p className="drawer-section-title" id="drawer-evidence">
              How we know
            </p>
            {decEvidence.length === 0 ? (
              <p style={{ fontSize: 'var(--text-sm)', color: 'var(--color-muted)' }}>
                No evidence records attached.
              </p>
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
                    <div
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: 'var(--space-2)',
                        marginBottom: 'var(--space-2)',
                        flexWrap: 'wrap',
                      }}
                    >
                      <code
                        style={{
                          fontFamily: 'var(--font-mono)',
                          color: 'var(--color-muted)',
                        }}
                      >
                        {e.id}
                      </code>
                      <TierBadge tier={e.tier} />
                      {e.withdrawn && (
                        <span style={{ color: 'var(--verdict-cannot-fg)', fontWeight: 600 }}>
                          [withdrawn]
                        </span>
                      )}
                    </div>
                    <p style={{ fontWeight: 500, marginBottom: 'var(--space-1)' }}>{e.claim}</p>
                    <p style={{ color: 'var(--color-muted)' }}>
                      Source: {e.source} · Origin: {e.origin}
                      {e.published_at && ` · Published: ${formatDateShort(e.published_at)}`}
                    </p>
                    {e.quote && (
                      <blockquote
                        style={{
                          marginTop: 'var(--space-2)',
                          borderLeft: '3px solid var(--color-border)',
                          paddingLeft: 'var(--space-3)',
                          color: 'var(--color-muted)',
                          fontStyle: 'italic',
                        }}
                      >
                        "{e.quote}"
                      </blockquote>
                    )}
                    {e.url && (
                      <a
                        href={e.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        style={{
                          color: 'var(--color-accent)',
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: 4,
                          marginTop: 'var(--space-1)',
                        }}
                      >
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
            <p className="drawer-section-title" id="drawer-certain">
              How certain
            </p>
            <div style={{ fontSize: 'var(--text-sm)' }}>
              <strong>{dec.qualifier}</strong>
              {dec.open_defeaters.length > 0 && (
                <>
                  {' · '}Open defeaters:
                  <ul style={{ marginTop: 'var(--space-1)', paddingLeft: 'var(--space-4)' }}>
                    {dec.open_defeaters.map((d, i) => (
                      <li key={i}>{d}</li>
                    ))}
                  </ul>
                </>
              )}
            </div>
          </section>

          {/* PATH */}
          {dec.exposure.paths.length > 0 && (
            <section aria-labelledby="drawer-path">
              <p className="drawer-section-title" id="drawer-path">
                Why is this here? (dependency path)
              </p>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}>
                {dec.exposure.paths.slice(0, 3).map((path, i) => (
                  <ol
                    key={i}
                    style={{
                      paddingLeft: 'var(--space-4)',
                      fontSize: 'var(--text-sm)',
                      lineHeight: 2,
                    }}
                  >
                    {path.map((node, j) => (
                      <li key={j}>
                        <code style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)' }}>
                          {node}
                        </code>
                        {node.includes(dec.name) &&
                          dec.exposure.install_phase === 'observed' && (
                            <span
                              style={{
                                marginLeft: 'var(--space-2)',
                                color: 'var(--verdict-act-now-fg)',
                                fontSize: 'var(--text-xs)',
                              }}
                            >
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
              <p className="drawer-section-title" id="drawer-impact">
                Impact profile
              </p>
              <code
                style={{
                  fontSize: 'var(--text-xs)',
                  fontFamily: 'var(--font-mono)',
                  color: 'var(--color-muted)',
                  wordBreak: 'break-all',
                }}
              >
                {dec.cvss_vector}
              </code>
              <p
                style={{
                  marginTop: 'var(--space-2)',
                  fontSize: 'var(--text-xs)',
                  color: 'var(--color-muted)',
                  fontStyle: 'italic',
                }}
              >
                Read directly from the CVSS vector. This is not confirmed exploitability on your
                system.
              </p>
            </section>
          )}

          {/* REMEDIATION / WHAT TO DO */}
          <section aria-labelledby="drawer-actions">
            <p className="drawer-section-title" id="drawer-actions">
              What to do
            </p>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
              {dec.response_steps.map((step, i) => (
                <div key={i} style={{ fontSize: 'var(--text-sm)' }}>
                  <p>{step.text}</p>
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
                          background: 'var(--color-surface)',
                          padding: 'var(--space-2)',
                          borderRadius: 'var(--radius-sm)',
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

            {/* Simulate Fix button */}
            {dec.fixed_version && (
              <div
                style={{
                  marginTop: 'var(--space-4)',
                  paddingTop: 'var(--space-3)',
                  borderTop: '1px solid var(--color-border)',
                }}
              >
                <button
                  onClick={handleSimulate}
                  disabled={simLoading}
                  className="btn btn-secondary btn-sm"
                >
                  <RefreshCw
                    size={14}
                    aria-hidden
                    className={simLoading ? 'animate-spin' : ''}
                  />
                  Simulate fix: upgrade to {dec.fixed_version}
                </button>
                {simResult && (
                  <div
                    className="callout callout-info"
                    style={{ marginTop: 'var(--space-2)', fontSize: 'var(--text-xs)' }}
                  >
                    <p style={{ fontWeight: 600 }}>Simulation result:</p>
                    <p>
                      Before:{' '}
                      <VerdictChip
                        verdict={
                          (simResult.before as Record<string, string>)?.verdict || ''
                        }
                      />{' '}
                      → After:{' '}
                      <VerdictChip
                        verdict={
                          (simResult.after as Record<string, string>)?.verdict || ''
                        }
                      />
                    </p>
                    <p style={{ color: 'var(--color-muted)', marginTop: 4 }}>
                      {String(simResult.note || '')}
                    </p>
                  </div>
                )}
              </div>
            )}
          </section>

          {/* VERIFIER DEMO */}
          <section aria-labelledby="drawer-verifier">
            <p className="drawer-section-title" id="drawer-verifier">
              Narrator Verifier Self-Test
            </p>
            <p
              style={{
                fontSize: 'var(--text-xs)',
                color: 'var(--color-muted)',
                marginBottom: 'var(--space-2)',
              }}
            >
              Tests whether a corrupted/hallucinated claim is rejected before display.
            </p>
            <button onClick={handleVerify} className="btn btn-secondary btn-sm">
              Run Verifier Test
            </button>
            {verifyResult && (
              <div
                className={`callout ${verifyResult.passed ? 'callout-info' : 'callout-error'}`}
                style={{ marginTop: 'var(--space-2)', fontSize: 'var(--text-xs)' }}
              >
                <p style={{ fontWeight: 600 }}>
                  {verifyResult.passed ? '✓ Passed' : '✗ REJECTED by Gate: ' + verifyResult.gate}
                </p>
                <p>{String(verifyResult.detail || '')}</p>
                <p style={{ color: 'var(--color-muted)', marginTop: 4 }}>
                  {String(verifyResult.note || '')}
                </p>
              </div>
            )}
          </section>

          {/* NOT CHECKED */}
          <section aria-labelledby="drawer-not-checked">
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
                padding: 'var(--space-2) 0',
              }}
              aria-expanded={unrunExpanded}
              aria-controls="unrun-list"
            >
              <p
                className="drawer-section-title"
                id="drawer-not-checked"
                style={{ margin: 0 }}
              >
                Not checked ({dec.unrun_checks.length} items)
              </p>
              <span
                style={{
                  fontSize: 'var(--text-xs)',
                  color: 'var(--color-muted)',
                }}
              >
                {unrunExpanded ? '▲ Hide' : '▼ Show'}
              </span>
            </button>
            {unrunExpanded && (
              <ul
                id="unrun-list"
                style={{
                  marginTop: 'var(--space-2)',
                  paddingLeft: 'var(--space-4)',
                  fontSize: 'var(--text-xs)',
                  color: 'var(--color-muted)',
                  lineHeight: 1.8,
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
