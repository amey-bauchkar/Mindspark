import React, { useState, useMemo, useCallback } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { GitBranch, AlertOctagon, Clock } from 'lucide-react';
import type { Decision, Report } from '../../lib/types';
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
      return { score: '—', className: 'cvss-cannot' };
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
      return { label: 'CLEAN', className: 'sev-safe' };
    default:
      return { label: dec.verdict, className: 'sev-cannot' };
  }
}

export function DecisionCard({ decision: dec, onOpen }: DecisionCardProps) {
  const fixCmd = dec.response_steps?.find(s => s.command)?.command;
  const isMalware = isMalwareThreat(dec);
  const cvssInfo = getCvssBadgeInfo(dec);
  const sevInfo = getSeverityPillInfo(dec);
  const queryClient = useQueryClient();

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

  // Navigate to Graph view and focus this package
  const handleViewInGraph = useCallback((e: React.MouseEvent) => {
    e.stopPropagation();

    if (!graphNodeMatch) return;

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

  const evidenceId = dec.evidence_ids && dec.evidence_ids.length > 0 ? dec.evidence_ids[0] : null;
  const primaryAdvisory = dec.evidence_ids?.find(id => id.startsWith('MAL-') || id.startsWith('GHSA-') || id.startsWith('CVE-')) || evidenceId;

  return (
    <div
      className="decision-table-row"
      tabIndex={0}
      role="button"
      aria-label={`View decision details for ${dec.name}@${dec.version}, verdict ${dec.verdict}`}
      onClick={() => onOpen(dec)}
      onKeyDown={e => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          onOpen(dec);
        }
      }}
    >
      {/* Col 1: Package Identity & Summary */}
      <div className="col-pkg-details">
        <div className="pkg-identity-line">
          <span className="pkg-name">{dec.name}@{dec.version}</span>
          <span className="pkg-scope-tag">
            {dec.is_direct ? 'Direct' : `Transitive (d${dec.depth})`}
          </span>
          {primaryAdvisory ? (
            <span className={`advisory-tag ${isMalware ? 'is-malware' : ''}`} title={`Advisory: ${primaryAdvisory}`}>
              {isMalware && <AlertOctagon size={10} aria-hidden />}
              <span>{primaryAdvisory}</span>
            </span>
          ) : (
            <span className="advisory-tag">
              <span>{dec.derivation && dec.derivation[0] ? dec.derivation[0].split('_')[0] : 'Checked'}</span>
            </span>
          )}
          {dec.evidence_ids && dec.evidence_ids.length > 1 && (
            <span className="advisory-more-count">+{dec.evidence_ids.length - 1}</span>
          )}
        </div>

        <div className="pkg-summary-line" title={dec.what}>
          {dec.what}
        </div>
      </div>

      {/* Col 2: Severity & CVSS Score */}
      <div className="col-severity-cvss">
        <div className="sev-cvss-pair">
          <span className={`cvss-pill ${cvssInfo.className}`} title={`CVSS benchmark: ${cvssInfo.score}`}>
            {cvssInfo.score}
          </span>
          <span className={`severity-pill ${sevInfo.className}`}>
            {sevInfo.isMalware && <AlertOctagon size={10} aria-hidden />}
            <span>{sevInfo.label}</span>
          </span>
        </div>
      </div>

      {/* Col 3: Introduced Path */}
      <div className="col-path">
        <span className="path-text" title={dec.introduced_by?.join(' → ') || 'Root'}>
          {dec.introduced_by && dec.introduced_by.length > 0
            ? dec.introduced_by.slice(0, 2).join(' → ') + (dec.introduced_by.length > 2 ? ` +${dec.introduced_by.length - 2}` : '')
            : 'Direct (__root__)'}
        </span>
        <span className="path-subtext">
          {dec.is_direct ? 'Root dependency' : `${dec.depth} level${dec.depth > 1 ? 's' : ''} deep`}
        </span>
      </div>

      {/* Col 4: Checks & Status */}
      <div className="col-checks">
        <span className="checks-status-text">
          {dec.unrun_checks && dec.unrun_checks.length > 0
            ? `${dec.unrun_checks.length} check${dec.unrun_checks.length > 1 ? 's' : ''} unrun`
            : 'All checks passed'}
        </span>
        <span className="reachability-text">Reachability: static</span>
      </div>

      {/* Col 5: Actions */}
      <div className="col-actions" onClick={e => e.stopPropagation()}>
        {fixCmd && (
          <CopyButton text={fixCmd} label="Copy fix command" />
        )}

        <button
          type="button"
          className="action-icon-btn"
          onClick={handleViewInGraph}
          title={graphNodeMatch ? `View ${dec.name}@${dec.version} in graph` : 'Not in graph'}
          disabled={!graphNodeMatch}
        >
          <GitBranch size={12} aria-hidden />
          <span className="hide-mobile">Graph</span>
        </button>

        <button
          type="button"
          className="action-details-btn"
          onClick={() => onOpen(dec)}
          aria-label={`Open details for ${dec.name}@${dec.version}`}
        >
          Details →
        </button>
      </div>
    </div>
  );
}

export default DecisionCard;
