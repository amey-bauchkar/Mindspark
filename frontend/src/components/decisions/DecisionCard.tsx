import React from 'react';
import type { Decision } from '../../lib/types';
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
        </div>
        <div
          style={{
            display: 'flex',
            gap: 'var(--space-2)',
            flexShrink: 0,
            alignItems: 'flex-start',
          }}
        >
          {fixCmd && <CopyButton text={fixCmd} label="Copy fix command" />}
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
