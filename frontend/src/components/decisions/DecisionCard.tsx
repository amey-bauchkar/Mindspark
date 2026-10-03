import React from 'react';
import type { Decision } from '../../lib/types';
import { VerdictChip } from '../ui/VerdictChip';
import { CopyButton } from '../ui/CopyButton';

interface DecisionCardProps {
  decision: Decision;
  onOpen: (d: Decision) => void;
}

export function DecisionCard({ decision: dec, onOpen }: DecisionCardProps) {
  const fixCmd = dec.response_steps.find(s => s.command)?.command;

  return (
    <div
      className="card"
      style={{
        borderLeft: `4px solid var(--verdict-${dec.verdict}-fg, var(--color-border))`,
        padding: 'var(--space-4) var(--space-5)',
        cursor: 'pointer',
        transition: 'box-shadow var(--duration-fast) var(--ease-out)',
      }}
      onClick={() => onOpen(dec)}
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
              {dec.is_direct ? 'direct' : `depth ${dec.depth}`} · {dec.exposure.scope}
            </span>
            {dec.exposure.install_phase === 'observed' && (
              <span style={{ fontSize: 'var(--text-xs)', color: 'var(--verdict-act-now-fg)' }}>
                ⚠ install script
              </span>
            )}
          </div>
          <code className="purl">
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
          {dec.introduced_by.length > 0 && (
            <p
              style={{
                marginTop: 'var(--space-1)',
                fontSize: 'var(--text-xs)',
                color: 'var(--color-muted)',
              }}
            >
              Via: {dec.introduced_by.slice(0, 2).join(', ')}
              {dec.introduced_by.length > 2 && ` +${dec.introduced_by.length - 2} more`}
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

      {/* Not checked count — always visible */}
      <p
        style={{
          marginTop: 'var(--space-3)',
          fontSize: 'var(--text-xs)',
          color: 'var(--color-muted)',
          borderTop: '1px solid var(--color-border)',
          paddingTop: 'var(--space-2)',
        }}
      >
        Not checked: {dec.unrun_checks.length > 0 ? dec.unrun_checks.length : 'none'} items
        {dec.unrun_checks.length > 0 && ` (open details for list)`} · Reachability: not assessed
      </p>
    </div>
  );
}

export default DecisionCard;
