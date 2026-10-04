import React, { useState, useEffect } from 'react';
import type { Decision } from '../../lib/types';
import { DecisionCard, isMalwareThreat } from './DecisionCard';
import { 
  AlertTriangle, 
  Clock, 
  ShieldAlert, 
  ChevronDown, 
  ChevronRight, 
  CheckSquare,
  ShieldQuestion,
  FileCheck,
  AlertOctagon,
  Terminal,
  ShieldCheck
} from 'lucide-react';
import { CopyButton } from '../ui/CopyButton';

interface ActionGroupsProps {
  decisions: Decision[];
  onOpenDecision: (d: Decision) => void;
}

export function ActionGroups({ decisions, onOpenDecision }: ActionGroupsProps) {
  // Listen for cross-feature decision opening requests (e.g. from As-Of timeline or Graph HUD)
  useEffect(() => {
    if (typeof window === 'undefined') return;

    const handleOpen = (e: Event) => {
      const customEv = e as CustomEvent<Decision>;
      if (customEv.detail && onOpenDecision) {
        onOpenDecision(customEv.detail);
      }
    };

    window.addEventListener('warrant:open-decision', handleOpen);
    return () => window.removeEventListener('warrant:open-decision', handleOpen);
  }, [onOpenDecision]);

  // Local state for collapsible priority sections (zero mutation of incoming data)
  const [collapsedGroups, setCollapsedGroups] = useState<Set<string>>(() => new Set(['no-known-findings']));

  // Threat & Priority partitioning (segregating malware from standard CVEs)
  const malware = decisions.filter(isMalwareThreat);
  const criticalCves = decisions.filter(d => !isMalwareThreat(d) && ['INCIDENT', 'ACT_NOW'].includes(d.verdict));
  const planRemediation = decisions.filter(d => ['UPGRADE', 'REVIEW'].includes(d.verdict));
  const monitor = decisions.filter(d => ['MONITOR', 'CANNOT_ASSESS'].includes(d.verdict));
  const noKnownFindings = decisions.filter(d => d.verdict === 'NO_KNOWN_FINDING');

  const toggleGroup = (groupId: string) => {
    setCollapsedGroups(prev => {
      const next = new Set(prev);
      if (next.has(groupId)) {
        next.delete(groupId);
      } else {
        next.add(groupId);
      }
      return next;
    });
  };

  const expandAll = () => setCollapsedGroups(new Set());
  const collapseAll = () => setCollapsedGroups(new Set(['malware', 'immediate', 'plan', 'monitor', 'no-known-findings']));

  // Empty state guard
  if (decisions.length === 0) {
    return (
      <div
        className="card"
        style={{
          padding: 'var(--space-12)',
          textAlign: 'center',
          color: 'var(--color-muted)',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          gap: 'var(--space-3)',
        }}
      >
        <ShieldQuestion size={40} style={{ opacity: 0.6 }} aria-hidden />
        <h3 style={{ fontSize: 'var(--text-base)', fontWeight: 600, color: 'var(--color-text)' }}>
          No decisions to display
        </h3>
        <p style={{ fontSize: 'var(--text-sm)', maxWidth: 420 }}>
          No package findings match the active filters or this report contains no analyzed dependencies.
        </p>
      </div>
    );
  }

  const malwarePkgNames = Array.from(new Set(malware.map(m => m.name)));
  const malwareUninstallCmd = `npm uninstall ${malwarePkgNames.join(' ')}`;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-8)' }}>
      {/* Top Accordion Controls */}
      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 'var(--space-2)' }}>
        <button
          onClick={expandAll}
          className="btn btn-ghost btn-sm"
          style={{ fontSize: 'var(--text-xs)' }}
        >
          Expand All
        </button>
        <button
          onClick={collapseAll}
          className="btn btn-ghost btn-sm"
          style={{ fontSize: 'var(--text-xs)' }}
        >
          Collapse All
        </button>
      </div>

      {/* 0. DEDICATED MALWARE QUARANTINE SECTION */}
      {malware.length > 0 && (
        <section
          aria-labelledby="action-group-malware"
          className="quarantine-container"
        >
          {/* Header & Toggle */}
          <div
            style={{
              display: 'flex',
              alignItems: 'flex-start',
              justifyContent: 'space-between',
              gap: 'var(--space-3)',
              cursor: 'pointer',
              userSelect: 'none',
            }}
            onClick={() => toggleGroup('malware')}
          >
            <div style={{ flex: 1 }}>
              <div className="quarantine-header-kicker">
                <span className="quarantine-kicker-tag">CRITICAL SECURITY INCIDENT</span>
                <span className="quarantine-badge">
                  <AlertOctagon size={11} aria-hidden /> Confirmed Malware · Quarantined
                </span>
              </div>

              <h2
                id="action-group-malware"
                style={{
                  fontSize: 'var(--text-base)',
                  fontWeight: 800,
                  margin: '0 0 4px',
                  color: '#991B1B',
                  letterSpacing: '-0.01em',
                }}
              >
                MALICIOUS PACKAGES DETECTED ({malware.length})
              </h2>

              <p
                style={{
                  fontSize: 'var(--text-xs)',
                  color: '#7F1D1D',
                  margin: '0 0 var(--space-2)',
                  lineHeight: 1.45,
                }}
              >
                Active supply-chain backdoor or credential-harvesting code discovered in your dependencies.
                These packages must be purged immediately before running any build or deployment pipelines.
              </p>

              {/* Clean SOC Containment Protocol Box */}
              <div className="quarantine-protocol-box">
                <div className="quarantine-cmd-row">
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <Terminal size={13} style={{ color: '#991B1B', flexShrink: 0 }} />
                    <span style={{ fontWeight: 600 }}>{malwareUninstallCmd}</span>
                  </div>
                  <CopyButton
                    text={malwareUninstallCmd}
                    label="Copy containment command"
                  />
                </div>
                <div className="quarantine-steps-row">
                  <div className="quarantine-step-item">
                    <span className="quarantine-step-num">01</span>
                    <span>Purge malicious package entries from <code>package.json</code> and lockfile</span>
                  </div>
                  <div className="quarantine-step-item">
                    <span className="quarantine-step-num">02</span>
                    <span>Rotate secrets and API tokens exposed in CI/CD runner environment</span>
                  </div>
                  <div className="quarantine-step-item">
                    <span className="quarantine-step-num">03</span>
                    <span>Verify build artifacts for unauthorized outbound network payloads</span>
                  </div>
                </div>
              </div>
            </div>

            <button
              className="btn btn-ghost btn-sm"
              style={{ color: '#991B1B' }}
              aria-label={collapsedGroups.has('malware') ? 'Expand malware group' : 'Collapse malware group'}
            >
              {collapsedGroups.has('malware') ? <ChevronRight size={16} /> : <ChevronDown size={16} />}
            </button>
          </div>

          {!collapsedGroups.has('malware') && (
            <div
              style={{
                display: 'flex',
                flexDirection: 'column',
                gap: 'var(--space-2)',
                marginTop: 'var(--space-3)',
                paddingTop: 'var(--space-3)',
                borderTop: '1px solid #FECDD3',
              }}
            >
              <div className="table-header-row hide-mobile" style={{ background: '#FFF1F2', borderColor: '#FECDD3', color: '#991B1B' }}>
                <span className="th-cell">MALICIOUS PACKAGE / IDENTIFIER ⇅</span>
                <span className="th-cell">CVSS ⇅</span>
                <span className="th-cell">THREAT CLASS ⇅</span>
                <span className="th-cell">ADVISORY / PAYLOAD</span>
                <span className="th-cell">IMPACTED ASSETS</span>
                <span className="th-cell text-right">ACTIONS</span>
              </div>
              {malware.map(dec => (
                <DecisionCard key={dec.subject} decision={dec} onOpen={onOpenDecision} />
              ))}
            </div>
          )}
        </section>
      )}

      {/* 1. URGENT EXPLOITS & ACTIVE ADVISORIES (NON-MALWARE) */}
      {criticalCves.length > 0 && (
        <section
          aria-labelledby="action-group-immediate"
          style={{
            border: '1px solid var(--color-border)',
            borderLeft: '4px solid var(--verdict-act-now-fg)',
            background: '#FFFFFF',
            borderRadius: 0,
            padding: 'var(--space-4) var(--space-5)',
            boxShadow: '0 1px 2px 0 rgba(0, 0, 0, 0.02)',
          }}
        >
          {/* Header & Toggle */}
          <div
            style={{
              display: 'flex',
              alignItems: 'flex-start',
              justifyContent: 'space-between',
              gap: 'var(--space-3)',
              cursor: 'pointer',
              userSelect: 'none',
            }}
            onClick={() => toggleGroup('immediate')}
          >
            <div style={{ flex: 1 }}>
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 'var(--space-2)',
                  flexWrap: 'wrap',
                  marginBottom: '4px',
                }}
              >
                <span
                  style={{
                    fontSize: '11px',
                    fontWeight: 800,
                    letterSpacing: '0.06em',
                    textTransform: 'uppercase',
                    color: 'var(--verdict-act-now-fg)',
                  }}
                >
                  URGENT REMEDIATION
                </span>
                <span
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '4px',
                    padding: '2px 7px',
                    borderRadius: 0,
                    background: 'var(--verdict-act-now-bg)',
                    border: '1px solid var(--verdict-act-now-border)',
                    color: 'var(--verdict-act-now-fg)',
                    fontSize: '11px',
                    fontWeight: 600,
                  }}
                >
                  <ShieldAlert size={12} aria-hidden />
                  Remediation Required
                </span>
              </div>

              <h2
                id="action-group-immediate"
                style={{
                  fontSize: 'var(--text-base)',
                  fontWeight: 700,
                  margin: '0 0 4px',
                  color: 'var(--color-text)',
                }}
              >
                ACTIVE EXPLOITS &amp; HIGH SEVERITY ADVISORIES ({criticalCves.length})
              </h2>

              <p
                style={{
                  fontSize: 'var(--text-xs)',
                  color: 'var(--color-muted)',
                  margin: '0 0 var(--space-2)',
                  lineHeight: 1.4,
                }}
              >
                Known exploited vulnerabilities (CISA KEV) or packages with unvetted install scripts.
                Remediate before next production deployment.
              </p>
            </div>

            <button
              className="btn btn-ghost btn-sm"
              style={{ color: 'var(--color-muted)' }}
              aria-label={collapsedGroups.has('immediate') ? 'Expand immediate group' : 'Collapse immediate group'}
            >
              {collapsedGroups.has('immediate') ? <ChevronRight size={16} /> : <ChevronDown size={16} />}
            </button>
          </div>

          {!collapsedGroups.has('immediate') && (
            <div
              style={{
                display: 'flex',
                flexDirection: 'column',
                gap: 'var(--space-2)',
                marginTop: 'var(--space-3)',
                paddingTop: 'var(--space-3)',
                borderTop: '1px solid var(--color-border-subtle)',
              }}
            >
              <div className="table-header-row hide-mobile">
                <span className="th-cell">PACKAGE / CVE ⇅</span>
                <span className="th-cell">CVSS ⇅</span>
                <span className="th-cell">SEVERITY ⇅</span>
                <span className="th-cell">RISK FACTORS</span>
                <span className="th-cell">IMPACTED ASSETS</span>
                <span className="th-cell text-right">ACTIONS</span>
              </div>
              {criticalCves.map(dec => (
                <DecisionCard key={dec.subject} decision={dec} onOpen={onOpenDecision} />
              ))}
            </div>
          )}
        </section>
      )}

      {/* 2. PLAN REMEDIATION: UPGRADE / REVIEW */}
      {planRemediation.length > 0 && (
        <section
          aria-labelledby="action-group-plan"
          style={{
            border: '1px solid var(--color-border)',
            borderLeft: '4px solid var(--verdict-upgrade-fg)',
            borderRadius: 0,
            padding: 'var(--space-4) var(--space-5)',
            background: '#FFFFFF',
            boxShadow: '0 1px 2px 0 rgba(0, 0, 0, 0.02)',
          }}
        >
          <div
            style={{
              display: 'flex',
              alignItems: 'flex-start',
              justifyContent: 'space-between',
              gap: 'var(--space-3)',
              cursor: 'pointer',
              userSelect: 'none',
            }}
            onClick={() => toggleGroup('plan')}
          >
            <div>
              <div
                style={{
                  fontSize: '11px',
                  fontWeight: 800,
                  letterSpacing: '0.06em',
                  textTransform: 'uppercase',
                  color: 'var(--verdict-upgrade-fg)',
                  marginBottom: '4px',
                }}
              >
                PLAN REMEDIATION
              </div>
              <h2
                id="action-group-plan"
                style={{
                  fontSize: 'var(--text-base)',
                  fontWeight: 700,
                  margin: '0 0 4px',
                  color: 'var(--color-text)',
                }}
              >
                UPGRADE / REVIEW ({planRemediation.length})
              </h2>
              <p
                style={{
                  fontSize: 'var(--text-xs)',
                  color: 'var(--color-muted)',
                  margin: 0,
                  lineHeight: 1.4,
                }}
              >
                Known vulnerability advisories with patches available, or heuristic anomalies requiring
                manual code review.
              </p>
            </div>
            <button
              className="btn btn-ghost btn-sm"
              style={{ color: 'var(--color-muted)' }}
              aria-label={collapsedGroups.has('plan') ? 'Expand plan group' : 'Collapse plan group'}
            >
              {collapsedGroups.has('plan') ? <ChevronRight size={16} /> : <ChevronDown size={16} />}
            </button>
          </div>

          {!collapsedGroups.has('plan') && (
            <div
              style={{
                display: 'flex',
                flexDirection: 'column',
                gap: 'var(--space-2)',
                marginTop: 'var(--space-3)',
                paddingTop: 'var(--space-3)',
                borderTop: '1px solid var(--color-border-subtle)',
              }}
            >
              <div className="table-header-row hide-mobile">
                <span className="th-cell">PACKAGE / CVE ⇅</span>
                <span className="th-cell">CVSS ⇅</span>
                <span className="th-cell">SEVERITY ⇅</span>
                <span className="th-cell">RISK FACTORS</span>
                <span className="th-cell">IMPACTED ASSETS</span>
                <span className="th-cell text-right">ACTIONS</span>
              </div>
              {planRemediation.map(dec => (
                <DecisionCard key={dec.subject} decision={dec} onOpen={onOpenDecision} />
              ))}
            </div>
          )}
        </section>
      )}

      {/* 3. MONITOR: MONITOR / CANNOT ASSESS */}
      {monitor.length > 0 && (
        <section
          aria-labelledby="action-group-monitor"
          style={{
            border: '1px solid var(--color-border)',
            borderLeft: '4px solid var(--verdict-monitor-fg)',
            borderRadius: 0,
            padding: 'var(--space-4) var(--space-5)',
            background: '#FFFFFF',
            boxShadow: '0 1px 2px 0 rgba(0, 0, 0, 0.02)',
          }}
        >
          <div
            style={{
              display: 'flex',
              alignItems: 'flex-start',
              justifyContent: 'space-between',
              gap: 'var(--space-3)',
              cursor: 'pointer',
              userSelect: 'none',
            }}
            onClick={() => toggleGroup('monitor')}
          >
            <div>
              <div
                style={{
                  fontSize: '11px',
                  fontWeight: 800,
                  letterSpacing: '0.06em',
                  textTransform: 'uppercase',
                  color: 'var(--verdict-monitor-fg)',
                  marginBottom: '4px',
                }}
              >
                MONITOR
              </div>
              <h2
                id="action-group-monitor"
                style={{
                  fontSize: 'var(--text-base)',
                  fontWeight: 700,
                  margin: '0 0 4px',
                  color: 'var(--color-text)',
                }}
              >
                MONITOR / CANNOT ASSESS ({monitor.length})
              </h2>
              <p style={{ fontSize: 'var(--text-xs)', color: 'var(--color-muted)', margin: 0, lineHeight: 1.4 }}>
                Low-severity advisories scheduled for standard release cadence, or items where public data
                was insufficient to assess.
              </p>
            </div>
            <button
              className="btn btn-ghost btn-sm"
              style={{ color: 'var(--color-muted)' }}
              aria-label={collapsedGroups.has('monitor') ? 'Expand monitor group' : 'Collapse monitor group'}
            >
              {collapsedGroups.has('monitor') ? <ChevronRight size={16} /> : <ChevronDown size={16} />}
            </button>
          </div>

          {!collapsedGroups.has('monitor') && (
            <div
              style={{
                display: 'flex',
                flexDirection: 'column',
                gap: 'var(--space-2)',
                marginTop: 'var(--space-3)',
                paddingTop: 'var(--space-3)',
                borderTop: '1px solid var(--color-border-subtle)',
              }}
            >
              <div className="table-header-row hide-mobile">
                <span className="th-cell">PACKAGE / CVE ⇅</span>
                <span className="th-cell">CVSS ⇅</span>
                <span className="th-cell">SEVERITY ⇅</span>
                <span className="th-cell">RISK FACTORS</span>
                <span className="th-cell">IMPACTED ASSETS</span>
                <span className="th-cell text-right">ACTIONS</span>
              </div>
              {monitor.map(dec => (
                <DecisionCard key={dec.subject} decision={dec} onOpen={onOpenDecision} />
              ))}
            </div>
          )}
        </section>
      )}

      {/* 4. NO KNOWN FINDING (NEUTRAL SLATE/GREY — ALL CHECKS RAN, NOT SAFE) */}
      {noKnownFindings.length > 0 && (
        <section
          aria-labelledby="action-group-nkf"
          style={{
            border: '1px solid var(--color-border)',
            borderLeft: '4px solid var(--verdict-nkf-border)',
            borderRadius: 0,
            background: '#FFFFFF',
            overflow: 'hidden',
            boxShadow: '0 1px 2px 0 rgba(0, 0, 0, 0.02)',
          }}
        >
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              padding: 'var(--space-3) var(--space-4)',
              cursor: 'pointer',
              userSelect: 'none',
              background: '#FFFFFF',
            }}
            onClick={() => toggleGroup('no-known-findings')}
          >
            <div>
              <div
                style={{
                  fontSize: '11px',
                  fontWeight: 800,
                  letterSpacing: '0.06em',
                  textTransform: 'uppercase',
                  color: 'var(--color-muted)',
                  marginBottom: '2px',
                }}
              >
                NO KNOWN FINDING
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span style={{ fontSize: 'var(--text-sm)', fontWeight: 700, color: 'var(--color-text)' }}>
                  NO KNOWN FINDING ({noKnownFindings.length})
                </span>
                <span
                  style={{
                    fontSize: '11px',
                    padding: '1px 6px',
                    borderRadius: 'var(--radius-xs)',
                    background: 'var(--verdict-nkf-bg)',
                    border: '1px solid var(--verdict-nkf-border)',
                    color: 'var(--verdict-nkf-fg)',
                    fontStyle: 'italic',
                  }}
                >
                  all checks ran · not safe
                </span>
              </div>
            </div>
            <button
              className="btn btn-ghost btn-sm"
              style={{ color: 'var(--color-muted)' }}
              aria-label={collapsedGroups.has('no-known-findings') ? 'Expand no known findings' : 'Collapse no known findings'}
            >
              {collapsedGroups.has('no-known-findings') ? <ChevronRight size={16} /> : <ChevronDown size={16} />}
            </button>
          </div>

          {!collapsedGroups.has('no-known-findings') && (
            <div
              style={{
                padding: 'var(--space-4)',
                display: 'flex',
                flexDirection: 'column',
                gap: 'var(--space-2)',
                borderTop: '1px solid var(--color-border-subtle)',
              }}
            >
              <p style={{ fontSize: 'var(--text-xs)', color: 'var(--color-muted)', margin: '0 0 var(--space-2)' }}>
                These packages had all required checks run with nothing found as of the analysis timestamp.
                Public databases may lag behind actual security events; &ldquo;no known finding&rdquo; does not guarantee safety.
              </p>
              <div className="table-header-row hide-mobile">
                <span className="th-cell">PACKAGE / CVE ⇅</span>
                <span className="th-cell">CVSS ⇅</span>
                <span className="th-cell">SEVERITY ⇅</span>
                <span className="th-cell">RISK FACTORS</span>
                <span className="th-cell">IMPACTED ASSETS</span>
                <span className="th-cell text-right">ACTIONS</span>
              </div>
              {noKnownFindings.map(dec => (
                <DecisionCard key={dec.subject} decision={dec} onOpen={onOpenDecision} />
              ))}
            </div>
          )}
        </section>
      )}
    </div>
  );
}

export default ActionGroups;
