import React, { useState } from 'react';
import type { Decision } from '../../lib/types';
import { DecisionCard } from './DecisionCard';
import { 
  AlertTriangle, 
  Clock, 
  ShieldAlert, 
  ChevronDown, 
  ChevronRight, 
  CheckSquare,
  ShieldQuestion,
  FileCheck
} from 'lucide-react';

interface ActionGroupsProps {
  decisions: Decision[];
  onOpenDecision: (d: Decision) => void;
}

export function ActionGroups({ decisions, onOpenDecision }: ActionGroupsProps) {
  // Local state for collapsible priority sections (zero mutation of incoming data)
  const [collapsedGroups, setCollapsedGroups] = useState<Set<string>>(() => new Set(['no-known-findings']));

  // Priority partitioning
  const immediate = decisions.filter(d => ['INCIDENT', 'ACT_NOW'].includes(d.verdict));
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
  const collapseAll = () => setCollapsedGroups(new Set(['immediate', 'plan', 'monitor', 'no-known-findings']));

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

      {/* 1. DO THIS FIRST: IMMEDIATE CONTAINMENT (HIGH VISIBILITY CONTAINER) */}
      {immediate.length > 0 && (
        <section
          aria-labelledby="action-group-immediate"
          style={{
            border: '2px solid var(--verdict-incident-border)',
            background: 'var(--verdict-incident-bg)',
            borderRadius: 'var(--radius-lg)',
            padding: 'var(--space-5)',
            boxShadow: 'var(--shadow-sm)',
            transition: 'border-color var(--duration-fast) var(--ease-out)',
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
                  marginBottom: 'var(--space-2)',
                }}
              >
                {/* Static Professional Containment Badge */}
                <span
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '4px',
                    padding: '3px 8px',
                    borderRadius: 'var(--radius-full)',
                    background: 'var(--color-surface)',
                    border: '1px solid var(--verdict-incident-border)',
                    color: 'var(--verdict-incident-fg)',
                    fontSize: '11px',
                    fontWeight: 700,
                    letterSpacing: '0.04em',
                    textTransform: 'uppercase',
                  }}
                >
                  <ShieldAlert size={14} aria-hidden />
                  Containment Required
                </span>
                <span style={{ fontSize: 'var(--text-xs)', fontWeight: 600, color: 'var(--verdict-incident-fg)' }}>
                  P0 Action Group
                </span>
              </div>

              <h2
                id="action-group-immediate"
                style={{
                  fontSize: 'var(--text-lg)',
                  fontWeight: 700,
                  margin: 0,
                  color: 'var(--verdict-incident-fg)',
                }}
              >
                Do This First: Immediate Containment ({immediate.length})
              </h2>

              <p
                style={{
                  fontSize: 'var(--text-xs)',
                  color: 'var(--color-text)',
                  opacity: 0.85,
                  marginTop: 'var(--space-1)',
                  marginBottom: 'var(--space-3)',
                }}
              >
                Active malware, known exploited vulnerabilities (CISA KEV), or untrusted packages
                executing unvetted install scripts. Contain before proceeding with builds.
              </p>

              {/* Containment Checklist Badges */}
              <div
                style={{
                  display: 'flex',
                  flexWrap: 'wrap',
                  gap: 'var(--space-2)',
                  marginBottom: 'var(--space-2)',
                }}
              >
                <span
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '4px',
                    padding: '3px 8px',
                    borderRadius: 'var(--radius-sm)',
                    background: 'var(--color-surface)',
                    border: '1px solid var(--verdict-incident-border)',
                    color: 'var(--verdict-incident-fg)',
                    fontSize: '11px',
                    fontWeight: 500,
                  }}
                >
                  <CheckSquare size={12} /> 1. Quarantine package / pin version
                </span>
                <span
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '4px',
                    padding: '3px 8px',
                    borderRadius: 'var(--radius-sm)',
                    background: 'var(--color-surface)',
                    border: '1px solid var(--verdict-incident-border)',
                    color: 'var(--verdict-incident-fg)',
                    fontSize: '11px',
                    fontWeight: 500,
                  }}
                >
                  <CheckSquare size={12} /> 2. Revoke impacted build & deploy secrets
                </span>
                <span
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '4px',
                    padding: '3px 8px',
                    borderRadius: 'var(--radius-sm)',
                    background: 'var(--color-surface)',
                    border: '1px solid var(--verdict-incident-border)',
                    color: 'var(--verdict-incident-fg)',
                    fontSize: '11px',
                    fontWeight: 500,
                  }}
                >
                  <CheckSquare size={12} /> 3. Audit production lockfiles
                </span>
              </div>
            </div>

            <button
              className="btn btn-ghost btn-sm"
              style={{ color: 'var(--verdict-incident-fg)' }}
              aria-label={collapsedGroups.has('immediate') ? 'Expand immediate group' : 'Collapse immediate group'}
            >
              {collapsedGroups.has('immediate') ? <ChevronRight size={18} /> : <ChevronDown size={18} />}
            </button>
          </div>

          {!collapsedGroups.has('immediate') && (
            <div
              style={{
                display: 'flex',
                flexDirection: 'column',
                gap: 'var(--space-3)',
                marginTop: 'var(--space-4)',
              }}
            >
              {immediate.map(dec => (
                <DecisionCard key={dec.subject} decision={dec} onOpen={onOpenDecision} />
              ))}
            </div>
          )}
        </section>
      )}

      {/* 2. PLAN REMEDIATION */}
      {planRemediation.length > 0 && (
        <section
          aria-labelledby="action-group-plan"
          style={{
            border: '1px solid var(--verdict-upgrade-border)',
            borderRadius: 'var(--radius-lg)',
            padding: 'var(--space-5)',
            background: 'var(--color-surface)',
          }}
        >
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              cursor: 'pointer',
              userSelect: 'none',
            }}
            onClick={() => toggleGroup('plan')}
          >
            <div>
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 'var(--space-2)',
                  color: 'var(--verdict-upgrade-fg)',
                  marginBottom: 'var(--space-1)',
                }}
              >
                <Clock size={18} aria-hidden />
                <h2
                  id="action-group-plan"
                  style={{ fontSize: 'var(--text-base)', fontWeight: 700, margin: 0 }}
                >
                  Plan Upgrades & Reviews ({planRemediation.length})
                </h2>
              </div>
              <p
                style={{
                  fontSize: 'var(--text-xs)',
                  color: 'var(--color-muted)',
                  margin: 0,
                }}
              >
                Known vulnerability advisories with patches available, or heuristic anomalies requiring
                manual code review.
              </p>
            </div>
            <button
              className="btn btn-ghost btn-sm"
              aria-label={collapsedGroups.has('plan') ? 'Expand plan group' : 'Collapse plan group'}
            >
              {collapsedGroups.has('plan') ? <ChevronRight size={18} /> : <ChevronDown size={18} />}
            </button>
          </div>

          {!collapsedGroups.has('plan') && (
            <div
              style={{
                display: 'flex',
                flexDirection: 'column',
                gap: 'var(--space-3)',
                marginTop: 'var(--space-4)',
              }}
            >
              {planRemediation.map(dec => (
                <DecisionCard key={dec.subject} decision={dec} onOpen={onOpenDecision} />
              ))}
            </div>
          )}
        </section>
      )}

      {/* 3. MONITOR & UNASSESSED */}
      {monitor.length > 0 && (
        <section
          aria-labelledby="action-group-monitor"
          style={{
            border: '1px solid var(--color-border)',
            borderRadius: 'var(--radius-lg)',
            padding: 'var(--space-5)',
            background: 'var(--color-surface)',
          }}
        >
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              cursor: 'pointer',
              userSelect: 'none',
            }}
            onClick={() => toggleGroup('monitor')}
          >
            <div>
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 'var(--space-2)',
                  color: 'var(--verdict-monitor-fg)',
                  marginBottom: 'var(--space-1)',
                }}
              >
                <AlertTriangle size={18} aria-hidden />
                <h2
                  id="action-group-monitor"
                  style={{ fontSize: 'var(--text-base)', fontWeight: 600, margin: 0 }}
                >
                  Monitor & Unassessed ({monitor.length})
                </h2>
              </div>
              <p style={{ fontSize: 'var(--text-xs)', color: 'var(--color-muted)', margin: 0 }}>
                Low-severity advisories scheduled for standard release cadence, or items where public data
                was insufficient to assess.
              </p>
            </div>
            <button
              className="btn btn-ghost btn-sm"
              aria-label={collapsedGroups.has('monitor') ? 'Expand monitor group' : 'Collapse monitor group'}
            >
              {collapsedGroups.has('monitor') ? <ChevronRight size={18} /> : <ChevronDown size={18} />}
            </button>
          </div>

          {!collapsedGroups.has('monitor') && (
            <div
              style={{
                display: 'flex',
                flexDirection: 'column',
                gap: 'var(--space-3)',
                marginTop: 'var(--space-4)',
              }}
            >
              {monitor.map(dec => (
                <DecisionCard key={dec.subject} decision={dec} onOpen={onOpenDecision} />
              ))}
            </div>
          )}
        </section>
      )}

      {/* 4. NO KNOWN FINDINGS (NEUTRAL SLATE/GREY — ALL CHECKS RAN, NOT SAFE) */}
      {noKnownFindings.length > 0 && (
        <section
          aria-labelledby="action-group-nkf"
          style={{
            border: '1px solid var(--color-border)',
            borderRadius: 'var(--radius-md)',
            background: 'var(--color-surface)',
            overflow: 'hidden',
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
              background: 'var(--color-bg)',
            }}
            onClick={() => toggleGroup('no-known-findings')}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
              <FileCheck size={16} style={{ color: 'var(--verdict-nkf-fg)' }} aria-hidden />
              <span style={{ fontSize: 'var(--text-sm)', fontWeight: 600, color: 'var(--color-text)' }}>
                No Known Findings ({noKnownFindings.length})
              </span>
              <span
                style={{
                  fontSize: '11px',
                  padding: '2px 6px',
                  borderRadius: 'var(--radius-full)',
                  background: 'var(--verdict-nkf-bg)',
                  border: '1px solid var(--verdict-nkf-border)',
                  color: 'var(--verdict-nkf-fg)',
                  fontStyle: 'italic',
                }}
              >
                all checks ran · not safe
              </span>
            </div>
            <button
              className="btn btn-ghost btn-sm"
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
                gap: 'var(--space-3)',
                borderTop: '1px solid var(--color-border)',
              }}
            >
              <p style={{ fontSize: 'var(--text-xs)', color: 'var(--color-muted)' }}>
                These packages had all required checks run with nothing found as of the analysis timestamp.
                Public databases may lag behind actual security events; &ldquo;no known finding&rdquo; does not guarantee safety.
              </p>
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
