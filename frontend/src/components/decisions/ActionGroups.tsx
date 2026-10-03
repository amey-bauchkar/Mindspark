import React from 'react';
import type { Decision } from '../../lib/types';
import { DecisionCard } from './DecisionCard';
import { AlertTriangle, Clock, ShieldCheck, ShieldAlert } from 'lucide-react';

interface ActionGroupsProps {
  decisions: Decision[];
  onOpenDecision: (d: Decision) => void;
}

export function ActionGroups({ decisions, onOpenDecision }: ActionGroupsProps) {
  // Separate into priority groups
  const immediate = decisions.filter(d => ['INCIDENT', 'ACT_NOW'].includes(d.verdict));
  const planRemediation = decisions.filter(d => ['UPGRADE', 'REVIEW'].includes(d.verdict));
  const monitor = decisions.filter(d => ['MONITOR', 'CANNOT_ASSESS'].includes(d.verdict));
  const clean = decisions.filter(d => d.verdict === 'NO_KNOWN_FINDING');

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-8)' }}>
      {/* 1. DO THIS FIRST */}
      {immediate.length > 0 && (
        <section aria-labelledby="action-group-immediate">
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 'var(--space-2)',
              marginBottom: 'var(--space-3)',
              color: 'var(--verdict-incident-fg)',
            }}
          >
            <ShieldAlert size={20} aria-hidden />
            <h2
              id="action-group-immediate"
              style={{ fontSize: 'var(--text-base)', fontWeight: 700, margin: 0 }}
            >
              Do This First — Containment & Immediate Action ({immediate.length})
            </h2>
          </div>
          <p
            style={{
              fontSize: 'var(--text-xs)',
              color: 'var(--color-muted)',
              marginBottom: 'var(--space-3)',
            }}
          >
            Confirmed malware, actively exploited vulnerabilities (CISA KEV), or fresh packages
            executing install scripts. Contain before continuing development.
          </p>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
            {immediate.map(dec => (
              <DecisionCard key={dec.subject} decision={dec} onOpen={onOpenDecision} />
            ))}
          </div>
        </section>
      )}

      {/* 2. PLAN REMEDIATION */}
      {planRemediation.length > 0 && (
        <section aria-labelledby="action-group-plan">
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 'var(--space-2)',
              marginBottom: 'var(--space-3)',
              color: 'var(--verdict-upgrade-fg)',
            }}
          >
            <Clock size={20} aria-hidden />
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
              marginBottom: 'var(--space-3)',
            }}
          >
            Known vulnerability advisories with patches available, or heuristic anomalies requiring
            code review.
          </p>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
            {planRemediation.map(dec => (
              <DecisionCard key={dec.subject} decision={dec} onOpen={onOpenDecision} />
            ))}
          </div>
        </section>
      )}

      {/* 3. MONITOR & CANNOT ASSESS */}
      {monitor.length > 0 && (
        <section aria-labelledby="action-group-monitor">
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 'var(--space-2)',
              marginBottom: 'var(--space-3)',
              color: 'var(--color-muted)',
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
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
            {monitor.map(dec => (
              <DecisionCard key={dec.subject} decision={dec} onOpen={onOpenDecision} />
            ))}
          </div>
        </section>
      )}

      {/* 4. NO KNOWN FINDINGS */}
      {clean.length > 0 && (
        <details style={{ marginTop: 'var(--space-4)' }}>
          <summary
            style={{
              fontSize: 'var(--text-sm)',
              fontWeight: 500,
              cursor: 'pointer',
              padding: 'var(--space-3)',
              background: 'var(--color-surface)',
              border: '1px solid var(--color-border)',
              borderRadius: 'var(--radius-md)',
            }}
          >
            {clean.length} package{clean.length !== 1 ? 's' : ''} with no known finding —{' '}
            <em>not safe, all checks ran</em>
          </summary>
          <div style={{ padding: 'var(--space-3)', display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}>
            <p style={{ fontSize: 'var(--text-xs)', color: 'var(--color-muted)' }}>
              These packages had all required checks run with nothing found as of the analysis timestamp.
              Public data may lag behind actual events.
            </p>
            {clean.map(dec => (
              <DecisionCard key={dec.subject} decision={dec} onOpen={onOpenDecision} />
            ))}
          </div>
        </details>
      )}
    </div>
  );
}

export default ActionGroups;
