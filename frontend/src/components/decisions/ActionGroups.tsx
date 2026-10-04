import React, { useState, useEffect } from 'react';
import type { Decision } from '../../lib/types';
import { DecisionCard, isMalwareThreat } from './DecisionCard';
import { 
  ChevronDown, 
  ChevronRight, 
  ShieldQuestion,
  AlertOctagon,
  Terminal,
  ShieldAlert
} from 'lucide-react';
import { CopyButton } from '../ui/CopyButton';

interface ActionGroupsProps {
  decisions: Decision[];
  onOpenDecision: (d: Decision) => void;
}

function TableHeader({ variant }: { variant?: 'malware' | 'default' }) {
  const isMal = variant === 'malware';
  return (
    <div
      className="table-header-row hide-mobile"
      style={isMal ? { background: '#FFF1F2', borderColor: '#FECDD3', color: '#991B1B' } : undefined}
    >
      <span className="th-cell">PACKAGE &amp; FINDING</span>
      <span className="th-cell">SEVERITY</span>
      <span className="th-cell">INTRODUCED PATH</span>
      <span className="th-cell">CHECKS &amp; EVIDENCE</span>
      <span className="th-cell text-right">ACTIONS</span>
    </div>
  );
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

  // Local state for collapsible priority sections
  const [collapsedGroups, setCollapsedGroups] = useState<Set<string>>(() => new Set(['no-known-findings']));

  // Threat & Priority partitioning
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
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-6)' }}>
      {/* Top Accordion Controls */}
      <div className="action-groups-top-bar">
        <span className="action-groups-count-label">
          {decisions.length} Findings grouped by priority
        </span>
        <div className="action-groups-expand-controls">
          <button
            type="button"
            onClick={expandAll}
            className="action-control-btn"
          >
            Expand All
          </button>
          <span className="action-control-sep">·</span>
          <button
            type="button"
            onClick={collapseAll}
            className="action-control-btn"
          >
            Collapse All
          </button>
        </div>
      </div>

      {/* 0. DEDICATED MALWARE QUARANTINE SECTION */}
      {malware.length > 0 && (
        <section
          aria-labelledby="action-group-malware"
          className="action-group-card group-malware"
        >
          <div
            className="action-group-header"
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
                className="action-group-title"
                style={{ color: '#991B1B' }}
              >
                MALICIOUS PACKAGES DETECTED ({malware.length})
              </h2>

              <p className="action-group-desc" style={{ color: '#7F1D1D' }}>
                Active supply-chain backdoor or credential-harvesting code discovered in your dependencies.
                These packages must be purged immediately before running any build or deployment pipelines.
              </p>

              {/* Clean SOC Containment Protocol Box */}
              <div className="quarantine-protocol-box" onClick={e => e.stopPropagation()}>
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
              type="button"
              className="action-group-chevron"
              style={{ color: '#991B1B' }}
              aria-label={collapsedGroups.has('malware') ? 'Expand malware group' : 'Collapse malware group'}
            >
              {collapsedGroups.has('malware') ? <ChevronRight size={18} /> : <ChevronDown size={18} />}
            </button>
          </div>

          {!collapsedGroups.has('malware') && (
            <div className="action-group-body">
              <TableHeader variant="malware" />
              <div className="action-group-rows">
                {malware.map(dec => (
                  <DecisionCard key={dec.subject} decision={dec} onOpen={onOpenDecision} />
                ))}
              </div>
            </div>
          )}
        </section>
      )}

      {/* 1. URGENT EXPLOITS & ACTIVE ADVISORIES */}
      {criticalCves.length > 0 && (
        <section
          aria-labelledby="action-group-immediate"
          className="action-group-card group-immediate"
        >
          <div
            className="action-group-header"
            onClick={() => toggleGroup('immediate')}
          >
            <div style={{ flex: 1 }}>
              <div className="action-group-kicker kicker-urgent">
                <span className="kicker-label">URGENT REMEDIATION</span>
                <span className="kicker-pill pill-urgent">
                  <ShieldAlert size={11} aria-hidden /> Remediation Required
                </span>
              </div>

              <h2 id="action-group-immediate" className="action-group-title">
                Active Exploits &amp; High Severity Advisories ({criticalCves.length})
              </h2>

              <p className="action-group-desc">
                Known exploited vulnerabilities (CISA KEV) or packages with unvetted install scripts. Remediate before next production deployment.
              </p>
            </div>

            <button
              type="button"
              className="action-group-chevron"
              aria-label={collapsedGroups.has('immediate') ? 'Expand immediate group' : 'Collapse immediate group'}
            >
              {collapsedGroups.has('immediate') ? <ChevronRight size={18} /> : <ChevronDown size={18} />}
            </button>
          </div>

          {!collapsedGroups.has('immediate') && (
            <div className="action-group-body">
              <TableHeader />
              <div className="action-group-rows">
                {criticalCves.map(dec => (
                  <DecisionCard key={dec.subject} decision={dec} onOpen={onOpenDecision} />
                ))}
              </div>
            </div>
          )}
        </section>
      )}

      {/* 2. PLAN REMEDIATION: UPGRADE / REVIEW */}
      {planRemediation.length > 0 && (
        <section
          aria-labelledby="action-group-plan"
          className="action-group-card group-plan"
        >
          <div
            className="action-group-header"
            onClick={() => toggleGroup('plan')}
          >
            <div style={{ flex: 1 }}>
              <div className="action-group-kicker kicker-plan">
                <span className="kicker-label">PLAN REMEDIATION</span>
              </div>

              <h2 id="action-group-plan" className="action-group-title">
                Recommended Upgrades &amp; Policy Reviews ({planRemediation.length})
              </h2>

              <p className="action-group-desc">
                Known vulnerability advisories with patches available, or heuristic anomalies requiring manual code review.
              </p>
            </div>

            <button
              type="button"
              className="action-group-chevron"
              aria-label={collapsedGroups.has('plan') ? 'Expand plan group' : 'Collapse plan group'}
            >
              {collapsedGroups.has('plan') ? <ChevronRight size={18} /> : <ChevronDown size={18} />}
            </button>
          </div>

          {!collapsedGroups.has('plan') && (
            <div className="action-group-body">
              <TableHeader />
              <div className="action-group-rows">
                {planRemediation.map(dec => (
                  <DecisionCard key={dec.subject} decision={dec} onOpen={onOpenDecision} />
                ))}
              </div>
            </div>
          )}
        </section>
      )}

      {/* 3. MONITOR: MONITOR / CANNOT ASSESS */}
      {monitor.length > 0 && (
        <section
          aria-labelledby="action-group-monitor"
          className="action-group-card group-monitor"
        >
          <div
            className="action-group-header"
            onClick={() => toggleGroup('monitor')}
          >
            <div style={{ flex: 1 }}>
              <div className="action-group-kicker kicker-monitor">
                <span className="kicker-label">MONITOR &amp; COVERAGE</span>
              </div>

              <h2 id="action-group-monitor" className="action-group-title">
                Monitored &amp; Unassessed Dependencies ({monitor.length})
              </h2>

              <p className="action-group-desc">
                Low-severity advisories scheduled for standard cadence, or dependencies where public feed coverage was incomplete.
              </p>
            </div>

            <button
              type="button"
              className="action-group-chevron"
              aria-label={collapsedGroups.has('monitor') ? 'Expand monitor group' : 'Collapse monitor group'}
            >
              {collapsedGroups.has('monitor') ? <ChevronRight size={18} /> : <ChevronDown size={18} />}
            </button>
          </div>

          {!collapsedGroups.has('monitor') && (
            <div className="action-group-body">
              <TableHeader />
              <div className="action-group-rows">
                {monitor.map(dec => (
                  <DecisionCard key={dec.subject} decision={dec} onOpen={onOpenDecision} />
                ))}
              </div>
            </div>
          )}
        </section>
      )}

      {/* 4. NO KNOWN FINDING (NEUTRAL SLATE/GREY) */}
      {noKnownFindings.length > 0 && (
        <section
          aria-labelledby="action-group-nkf"
          className="action-group-card group-nkf"
        >
          <div
            className="action-group-header"
            onClick={() => toggleGroup('no-known-findings')}
          >
            <div style={{ flex: 1 }}>
              <div className="action-group-kicker kicker-nkf">
                <span className="kicker-label">POLICY VERIFIED</span>
                <span className="kicker-pill pill-nkf">
                  all checks ran · not safe
                </span>
              </div>

              <h2 id="action-group-nkf" className="action-group-title">
                No Known Findings ({noKnownFindings.length})
              </h2>

              <p className="action-group-desc">
                These packages had all required checks run with nothing found as of the analysis timestamp. Public databases may lag; &ldquo;no known finding&rdquo; does not guarantee safety.
              </p>
            </div>

            <button
              type="button"
              className="action-group-chevron"
              aria-label={collapsedGroups.has('no-known-findings') ? 'Expand no known findings' : 'Collapse no known findings'}
            >
              {collapsedGroups.has('no-known-findings') ? <ChevronRight size={18} /> : <ChevronDown size={18} />}
            </button>
          </div>

          {!collapsedGroups.has('no-known-findings') && (
            <div className="action-group-body">
              <TableHeader />
              <div className="action-group-rows">
                {noKnownFindings.map(dec => (
                  <DecisionCard key={dec.subject} decision={dec} onOpen={onOpenDecision} />
                ))}
              </div>
            </div>
          )}
        </section>
      )}
    </div>
  );
}

export default ActionGroups;
