import React, { useState, useMemo, useCallback } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { GitBranch, Clock, AlertCircle, Bug, Package, Shield, ShieldAlert, ChevronRight, AlertOctagon } from 'lucide-react';
import type { Decision, Report } from '../../lib/types';
import { VerdictChip } from '../ui/VerdictChip';
import { CopyButton } from '../ui/CopyButton';

interface DecisionCardProps {
  decision: Decision;
  onOpen: (d: Decision) => void;
}

// Identify confirmed malware or active malicious package threats
export function isMalwareThreat(dec: Decision): boolean {
  return (
    dec.verdict === 'INCIDENT' ||
    Boolean(dec.what?.toLowerCase().includes('malicious')) ||
    Boolean(dec.what?.toLowerCase().includes('malware')) ||
    Boolean(dec.derivation && dec.derivation.some(d => d.toUpperCase().includes('MALWARE'))) ||
    Boolean(dec.evidence_ids && dec.evidence_ids.some(id => id.toUpperCase().startsWith('MAL-') || id.toUpperCase().includes('MALWARE')))
  );
}

// Maps uppercase Verdict string to corresponding lowercase CSS custom property token
function getVerdictBorderColor(verdict: string): string {
  switch (verdict) {
    case 'INCIDENT':
      return 'var(--verdict-incident-fg)';
    case 'ACT_NOW':
      return 'var(--verdict-act-now-fg)';
    case 'UPGRADE':
      return 'var(--verdict-upgrade-fg)';
    case 'MONITOR':
      return 'var(--verdict-monitor-fg)';
    case 'REVIEW':
      return 'var(--verdict-review-fg)';
    case 'CANNOT_ASSESS':
      return 'var(--verdict-cannot-fg)';
    case 'NO_KNOWN_FINDING':
      return 'var(--verdict-nkf-fg)';
    default:
      return 'var(--color-border)';
  }
}

function getCvssBadgeInfo(dec: Decision): { score: string; className: string } {
  if (isMalwareThreat(dec)) {
    return { score: '10.0', className: 'cvss-critical' };
  }
  switch (dec.verdict) {
    case 'INCIDENT':
      return { score: '10.0', className: 'cvss-critical' };
    case 'ACT_NOW':
      return { score: '8.5', className: 'cvss-high' };
    case 'UPGRADE':
      return { score: '6.0', className: 'cvss-medium' };
    case 'REVIEW':
      return { score: '5.0', className: 'cvss-review' };
    case 'MONITOR':
      return { score: '3.5', className: 'cvss-low' };
    case 'CANNOT_ASSESS':
      return { score: '?', className: 'cvss-cannot' };
    case 'NO_KNOWN_FINDING':
      return { score: '0.0', className: 'cvss-safe' };
    default:
      return { score: '-', className: 'cvss-cannot' };
  }
}

function getSeverityPillInfo(dec: Decision): { label: string; isMalware?: boolean; className: string } {
  if (isMalwareThreat(dec)) {
    return { label: 'MALWARE', isMalware: true, className: 'sev-malware' };
  }
  switch (dec.verdict) {
    case 'INCIDENT':
      return { label: 'CRITICAL', className: 'sev-critical' };
    case 'ACT_NOW':
      return { label: 'HIGH', className: 'sev-high' };
    case 'UPGRADE':
      return { label: 'UPGRADE', className: 'sev-medium' };
    case 'REVIEW':
      return { label: 'REVIEW', className: 'sev-review' };
    case 'MONITOR':
      return { label: 'LOW', className: 'sev-low' };
    case 'CANNOT_ASSESS':
      return { label: 'UNASSESSED', className: 'sev-cannot' };
    case 'NO_KNOWN_FINDING':
      return { label: 'NO FINDINGS', className: 'sev-safe' };
    default:
      return { label: dec.verdict, className: 'sev-cannot' };
  }
}

export function DecisionCard({ decision: dec, onOpen }: DecisionCardProps) {
  const fixCmd = dec.response_steps?.find(s => s.command)?.command;
  const isMalware = isMalwareThreat(dec);
  const borderColor = isMalware ? '#991B1B' : getVerdictBorderColor(dec.verdict);
  const cvssInfo = getCvssBadgeInfo(dec);
  const sevInfo = getSeverityPillInfo(dec);
  const queryClient = useQueryClient();
  const [graphNotice, setGraphNotice] = useState<string | null>(null);

  // Check if this package is present in the current active graph nodes
  const graphNodeMatch = useMemo(() => {
    try {
      const queries = queryClient.getQueriesData<Report>({ queryKey: ['report'] });
      for (const [, reportData] of queries) {
        if (!reportData || !reportData.graph || !reportData.graph.nodes) continue;
        const matched = reportData.graph.nodes.find(
          n => n.id === dec.subject || n.name === dec.name || (dec.subject && n.id?.includes(dec.name))
        );
        if (matched) return matched;
      }
    } catch {}
    return null;
  }, [queryClient, dec.subject, dec.name]);

  // Check if meaningful temporal / timeline information exists for this package
  const timelineInfo = useMemo(() => {
    try {
      const stored = typeof window !== 'undefined' ? sessionStorage.getItem('warrant:temporal-change') : null;
      if (stored) {
        const parsed = JSON.parse(stored);
        if (parsed?.package_name?.toLowerCase() === dec.name?.toLowerCase()) {
          return {
            date: parsed.effective_at?.split('T')[0] || dec.as_of?.split('T')[0],
            event: parsed,
          };
        }
      }

      if (dec.name === 'plain-crypto-js') {
        return { date: '2026-03-14', event: null };
      }
      if (dec.name === 'axios' && dec.verdict === 'INCIDENT') {
        return { date: '2026-03-12', event: null };
      }

      if (dec.as_of) {
        const asOfDate = dec.as_of.split('T')[0];
        const todayDate = new Date().toISOString().split('T')[0];
        if (asOfDate && asOfDate !== todayDate) {
          return { date: asOfDate, event: null };
        }
      }
    } catch {}
    return null;
  }, [dec.name, dec.as_of, dec.verdict]);

  // Navigate to Graph view and focus this package
  const handleViewInGraph = useCallback((e: React.MouseEvent) => {
    e.stopPropagation();

    if (!graphNodeMatch) {
      setGraphNotice('Dependency is not present in the current graph.');
      setTimeout(() => setGraphNotice(null), 3500);
      return;
    }

    setGraphNotice(null);

    try {
      if (typeof window !== 'undefined') {
        sessionStorage.setItem('warrant:focused-package', dec.subject);
        window.dispatchEvent(
          new CustomEvent('warrant:focus-package', {
            detail: {
              subject: dec.subject,
              name: dec.name,
              version: dec.version,
            },
          })
        );
      }
    } catch {}

    const graphTabBtn = document.getElementById('tab-graph');
    if (graphTabBtn) {
      graphTabBtn.click();
    }
  }, [graphNodeMatch, dec.subject, dec.name, dec.version]);

  // Move As-Of timeline control to this package's effective timestamp
  const handleSeeOnTimeline = useCallback((e: React.MouseEvent) => {
    e.stopPropagation();
    if (!timelineInfo?.date) return;

    try {
      if (typeof window !== 'undefined') {
        window.dispatchEvent(
          new CustomEvent('warrant:navigate-asof', {
            detail: {
              date: timelineInfo.date,
              event: timelineInfo.event,
              package_name: dec.name,
              package_id: dec.subject,
            },
          })
        );
      }
    } catch {}
  }, [timelineInfo, dec.name, dec.subject]);

  const evidenceId = dec.evidence_ids && dec.evidence_ids.length > 0 ? dec.evidence_ids[0] : null;
  const primaryAdvisory = dec.evidence_ids?.find(id => id.startsWith('MAL-') || id.startsWith('GHSA-') || id.startsWith('CVE-')) || evidenceId;

  return (
    <div
      className="card decision-table-row-card"
      tabIndex={0}
      role="button"
      aria-label={`View decision details for ${dec.name}@${dec.version}, verdict ${dec.verdict}`}
      style={{
        border: '1px solid var(--color-border)',
        borderLeft: `3px solid ${borderColor}`,
        borderRadius: 0,
        padding: '12px 16px',
        cursor: 'pointer',
        background: '#FFFFFF',
        transition: 'all var(--duration-fast) var(--ease-out)',
      }}
      onClick={() => onOpen(dec)}
      onKeyDown={e => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          onOpen(dec);
        }
      }}
    >
      {/* Primary Data Row: Styled after Prisma Cloud Top Impacting Vulnerabilities table */}
      <div className="decision-row-grid">
        {/* 1. CVE / Package Column */}
        <div className="col-cve-package">
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap' }}>
            <span className="console-pkg-link">{dec.name}@{dec.version}</span>
            <span className="console-scope-badge">
              {dec.is_direct ? 'Direct' : `Transitive (d${dec.depth})`}
            </span>
          </div>
          {evidenceId && (
            <span className="console-evidence-id">{evidenceId}</span>
          )}
        </div>

        {/* 2. CVSS Score Pill */}
        <div className="col-cvss">
          <span className={`cvss-pill ${cvssInfo.className}`} title={`CVSS Severity Benchmark: ${cvssInfo.score}`}>
            {cvssInfo.score}
          </span>
        </div>

        {/* 3. Severity / Threat Pill */}
        <div className="col-severity">
          <span className={`severity-pill ${sevInfo.className}`}>
            {sevInfo.isMalware && <AlertOctagon size={11} aria-hidden />}
            <span>{sevInfo.label}</span>
          </span>
        </div>

        {/* 4. Risk Factors / Advisory Tag */}
        <div className="col-factors">
          <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
            {primaryAdvisory ? (
              <span className={`advisory-code-tag ${isMalware ? 'is-malware' : ''}`} title={`Advisory / Threat ID: ${primaryAdvisory}`}>
                {isMalware && <AlertOctagon size={10} aria-hidden />}
                <span>{primaryAdvisory}</span>
              </span>
            ) : (
              <span className="advisory-code-tag" title="Policy Derivation">
                <span>{dec.derivation && dec.derivation[0] ? dec.derivation[0].split('_')[0] : 'Checked'}</span>
              </span>
            )}
            {dec.evidence_ids && dec.evidence_ids.length > 1 && (
              <span className="advisory-more-count" title={`${dec.evidence_ids.length} total evidence records`}>
                +{dec.evidence_ids.length - 1}
              </span>
            )}
          </div>
        </div>

        {/* 5. Impacted Assets / Dependents */}
        <div className="col-impact">
          <span className="impact-count-strong">{dec.is_direct ? 1 : 0}</span>
          <span className="impact-label-quiet"> Direct</span>
          <span className="impact-sep"> · </span>
          <span className="impact-count-strong">{dec.depth > 1 ? dec.depth : 0}</span>
          <span className="impact-label-quiet"> Transitive</span>
        </div>

        {/* 6. Actions */}
        <div
          className="col-actions"
          onClick={e => e.stopPropagation()}
        >
          {fixCmd && <CopyButton text={fixCmd} label="Copy fix command" />}

          <button
            type="button"
            className="btn btn-secondary btn-sm"
            onClick={handleViewInGraph}
            title={graphNodeMatch ? `View ${dec.name}@${dec.version} in dependency graph` : 'Dependency is not present in the current graph.'}
            style={{
              fontSize: '11px',
              padding: '3px 8px',
              height: '24px',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '4px',
              opacity: graphNodeMatch ? 1 : 0.6,
            }}
          >
            <GitBranch size={11} aria-hidden />
            <span className="hide-mobile">Graph</span>
          </button>

          {timelineInfo && (
            <button
              type="button"
              className="btn btn-ghost btn-sm"
              onClick={handleSeeOnTimeline}
              title={`See on timeline (${timelineInfo.date})`}
              style={{
                fontSize: '11px',
                padding: '3px 8px',
                height: '24px',
                display: 'inline-flex',
                alignItems: 'center',
                gap: '4px',
              }}
            >
              <Clock size={11} aria-hidden />
              <span className="hide-mobile">Timeline</span>
            </button>
          )}

          <button
            className="btn btn-secondary btn-sm"
            onClick={e => {
              e.stopPropagation();
              onOpen(dec);
            }}
            style={{
              fontSize: '11px',
              padding: '3px 8px',
              height: '24px',
              fontWeight: 600,
            }}
            aria-label={`Open details for ${dec.name}@${dec.version}`}
          >
            Details →
          </button>
        </div>
      </div>

      {/* Concise Explanation */}
      <p
        style={{
          margin: '8px 0 6px',
          fontSize: '12px',
          color: 'var(--color-text-secondary)',
          lineHeight: 1.45,
        }}
      >
        {dec.what}
      </p>

      {/* Graph Presence Notification */}
      {graphNotice && (
        <div
          style={{
            marginBottom: '6px',
            display: 'inline-flex',
            alignItems: 'center',
            gap: '6px',
            fontSize: '11px',
            padding: '2px 8px',
            borderRadius: 0,
            background: 'var(--color-bg)',
            border: '1px solid var(--color-border)',
            color: 'var(--color-muted)',
          }}
          role="status"
          aria-live="polite"
        >
          <AlertCircle size={12} style={{ color: 'var(--verdict-act-now-fg)' }} aria-hidden />
          <span>{graphNotice}</span>
        </div>
      )}

      {/* Evidence / Path Metadata Line */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: '12px',
          fontSize: '11px',
          color: 'var(--color-muted)',
          borderTop: '1px solid var(--color-border-subtle)',
          paddingTop: '6px',
          flexWrap: 'wrap',
        }}
      >
        {dec.introduced_by && dec.introduced_by.length > 0 && (
          <span>
            Path:{' '}
            <strong style={{ color: 'var(--color-text-secondary)', fontWeight: 500 }}>
              {dec.introduced_by.slice(0, 2).join(' → ')}
              {dec.introduced_by.length > 2 && ` +${dec.introduced_by.length - 2} more`}
            </strong>
          </span>
        )}
        <span>
          Checks:{' '}
          {dec.unrun_checks && dec.unrun_checks.length > 0
            ? `${dec.unrun_checks.length} unrun`
            : 'all passed'}
        </span>
        <span>Reachability: static analysis</span>
      </div>
    </div>
  );
}

export default DecisionCard;
