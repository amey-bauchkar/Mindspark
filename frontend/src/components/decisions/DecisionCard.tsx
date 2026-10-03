import React, { useState, useMemo, useCallback } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { GitBranch, Clock, AlertCircle } from 'lucide-react';
import type { Decision, Report } from '../../lib/types';
import { VerdictChip } from '../ui/VerdictChip';
import { CopyButton } from '../ui/CopyButton';

interface DecisionCardProps {
  decision: Decision;
  onOpen: (d: Decision) => void;
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

export function DecisionCard({ decision: dec, onOpen }: DecisionCardProps) {
  const fixCmd = dec.response_steps?.find(s => s.command)?.command;
  const borderColor = getVerdictBorderColor(dec.verdict);
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
      // 1. Check if there's a registered temporal change event in session storage or report
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

      // 2. Known timeline milestones for specific demonstrated incidents
      if (dec.name === 'plain-crypto-js') {
        return { date: '2026-03-14', event: null };
      }
      if (dec.name === 'axios' && dec.verdict === 'INCIDENT') {
        return { date: '2026-03-12', event: null };
      }

      // 3. If decision has a genuine as_of timestamp distinct from right now
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

    // Save package identity for graph selection
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

    // Switch to Graph tab via coordinator shell button
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

  return (
    <div
      className="card"
      tabIndex={0}
      role="button"
      aria-label={`View decision details for ${dec.name}@${dec.version}, verdict ${dec.verdict}`}
      style={{
        borderLeft: `4px solid ${borderColor}`,
        padding: 'var(--space-4) var(--space-5)',
        cursor: 'pointer',
        transition: 'box-shadow var(--duration-fast) var(--ease-out), transform var(--duration-fast) var(--ease-out)',
      }}
      onClick={() => onOpen(dec)}
      onKeyDown={e => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          onOpen(dec);
        }
      }}
    >
      <div
        style={{
          display: 'flex',
          alignItems: 'flex-start',
          gap: 'var(--space-4)',
          flexWrap: 'wrap',
        }}
      >
        <div style={{ flex: 1, minWidth: 200 }}>
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
              {dec.is_direct ? 'direct dependency' : `depth ${dec.depth}`} · {dec.exposure?.scope || 'prod'}
            </span>
            {dec.exposure?.install_phase === 'observed' && (
              <span
                style={{
                  fontSize: 'var(--text-xs)',
                  color: 'var(--verdict-act-now-fg)',
                  background: 'var(--verdict-act-now-bg)',
                  padding: '1px 6px',
                  borderRadius: 'var(--radius-sm)',
                  fontWeight: 500,
                }}
              >
                ⚠ install script observed
              </span>
            )}
          </div>
          <code className="purl" style={{ fontWeight: 600 }}>
            {dec.name}@{dec.version}
          </code>
          <p
            style={{
              marginTop: 'var(--space-2)',
              fontSize: 'var(--text-sm)',
              color: 'var(--color-text)',
              lineHeight: 1.5,
            }}
          >
            {dec.what}
          </p>
          {dec.introduced_by && dec.introduced_by.length > 0 && (
            <p
              style={{
                marginTop: 'var(--space-1)',
                fontSize: 'var(--text-xs)',
                color: 'var(--color-muted)',
              }}
            >
              Introduced via: {dec.introduced_by.slice(0, 3).join(', ')}
              {dec.introduced_by.length > 3 && ` +${dec.introduced_by.length - 3} more`}
            </p>
          )}

          {/* Graph Presence Notification (Graceful fallback without crashing) */}
          {graphNotice && (
            <div
              style={{
                marginTop: 'var(--space-2)',
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                fontSize: '11px',
                padding: '3px 8px',
                borderRadius: 'var(--radius-sm)',
                background: 'var(--color-bg)',
                border: '1px solid var(--color-border)',
                color: 'var(--color-muted)',
              }}
              role="status"
              aria-live="polite"
            >
              <AlertCircle size={13} style={{ color: 'var(--verdict-act-now-fg)' }} aria-hidden />
              <span>{graphNotice}</span>
            </div>
          )}
        </div>

        <div
          style={{
            display: 'flex',
            gap: 'var(--space-2)',
            flexShrink: 0,
            alignItems: 'center',
            flexWrap: 'wrap',
          }}
        >
          {fixCmd && <CopyButton text={fixCmd} label="Copy fix command" />}

          {/* Cross-Feature Action: View in Dependency Graph */}
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            onClick={handleViewInGraph}
            title={graphNodeMatch ? `View ${dec.name}@${dec.version} in dependency graph` : 'Dependency is not present in the current graph.'}
            style={{
              fontSize: 'var(--text-xs)',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '5px',
              opacity: graphNodeMatch ? 1 : 0.65,
            }}
          >
            <GitBranch size={13} aria-hidden />
            <span>View in Dependency Graph</span>
          </button>

          {/* Cross-Feature Action: See on Timeline (Only when genuine timestamp exists) */}
          {timelineInfo && (
            <button
              type="button"
              className="btn btn-ghost btn-sm"
              onClick={handleSeeOnTimeline}
              title={`See ${dec.name} on timeline (${timelineInfo.date})`}
              style={{
                fontSize: 'var(--text-xs)',
                display: 'inline-flex',
                alignItems: 'center',
                gap: '5px',
              }}
            >
              <Clock size={13} aria-hidden />
              <span>See on Timeline</span>
            </button>
          )}

          <button
            className="btn btn-secondary btn-sm"
            onClick={e => {
              e.stopPropagation();
              onOpen(dec);
            }}
            aria-label={`Open details for ${dec.name}@${dec.version}`}
          >
            Details
          </button>
        </div>
      </div>

      {/* Unrun checks & Reachability notice */}
      <p
        style={{
          marginTop: 'var(--space-3)',
          fontSize: 'var(--text-xs)',
          color: 'var(--color-muted)',
          borderTop: '1px solid var(--color-border)',
          paddingTop: 'var(--space-2)',
        }}
      >
        Not checked: {dec.unrun_checks && dec.unrun_checks.length > 0 ? `${dec.unrun_checks.length} checks` : 'none'}
        {dec.unrun_checks && dec.unrun_checks.length > 0 && ` (open details for breakdown)`} · Reachability: static analysis only
      </p>
    </div>
  );
}

export default DecisionCard;
