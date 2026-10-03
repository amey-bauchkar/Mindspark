import React from 'react';
import { AlertCircle, CheckCircle2, HelpCircle, AlertTriangle, ShieldCheck } from 'lucide-react';
import type { LicenseResult } from '../../lib/types';

interface LicensesTabProps {
  licenses: LicenseResult[];
}

export function LicensesTab({ licenses }: LicensesTabProps) {
  const counts = { CONFLICT: 0, REVIEW: 0, UNKNOWN: 0, CANNOT_ASSESS: 0, OK: 0 };
  licenses.forEach(l => {
    if (l.license_status in counts) {
      (counts as Record<string, number>)[l.license_status]++;
    }
  });

  const statusConfigs: Record<string, { label: string; icon: React.ReactNode; color: string; bg: string; border: string }> = {
    CONFLICT: {
      label: 'Conflict',
      icon: <AlertCircle size={15} style={{ color: 'var(--license-conflict-fg)' }} />,
      color: 'var(--license-conflict-fg)',
      bg: 'var(--license-conflict-bg)',
      border: 'var(--license-conflict-border)',
    },
    REVIEW: {
      label: 'Review Needed',
      icon: <AlertTriangle size={15} style={{ color: 'var(--license-review-fg)' }} />,
      color: 'var(--license-review-fg)',
      bg: 'var(--license-review-bg)',
      border: 'var(--license-review-border)',
    },
    OK: {
      label: 'Permissive / OK',
      icon: <CheckCircle2 size={15} style={{ color: 'var(--license-ok-fg)' }} />,
      color: 'var(--license-ok-fg)',
      bg: 'var(--license-ok-bg)',
      border: 'var(--license-ok-border)',
    },
    UNKNOWN: {
      label: 'Unknown Expression',
      icon: <HelpCircle size={15} style={{ color: 'var(--license-unknown-fg)' }} />,
      color: 'var(--license-unknown-fg)',
      bg: 'var(--license-unknown-bg)',
      border: 'var(--license-unknown-border)',
    },
    CANNOT_ASSESS: {
      label: 'Cannot Assess',
      icon: <HelpCircle size={15} style={{ color: 'var(--license-unknown-fg)' }} />,
      color: 'var(--license-unknown-fg)',
      bg: 'var(--license-unknown-bg)',
      border: 'var(--license-unknown-border)',
    },
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-6)' }}>
      {/* Metric Tiles */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))',
          gap: 'var(--space-4)',
        }}
      >
        {Object.entries(counts).map(([k, v]) => {
          const config = statusConfigs[k] || {
            label: k,
            icon: null,
            color: 'var(--color-text)',
            bg: 'var(--color-surface)',
            border: 'var(--color-border)',
          };

          return (
            <div
              key={k}
              className="card"
              style={{
                padding: 'var(--space-4)',
                background: config.bg,
                border: `1px solid ${config.border}`,
                borderRadius: 'var(--radius-lg)',
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'space-between',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 'var(--space-2)' }}>
                <span
                  style={{
                    fontSize: 'var(--text-2xs)',
                    fontWeight: 700,
                    textTransform: 'uppercase',
                    letterSpacing: '0.06em',
                    color: config.color,
                  }}
                >
                  {config.label}
                </span>
                {config.icon}
              </div>
              <p style={{ fontSize: 'var(--text-2xl)', fontWeight: 800, color: config.color, lineHeight: 1 }}>
                {v}
              </p>
            </div>
          );
        })}
      </div>

      {/* License Breakdown Table */}
      <div className="table-wrapper">
        <table>
          <caption className="visually-hidden">License classification results table</caption>
          <thead>
            <tr>
              <th scope="col">Package Name & Version</th>
              <th scope="col">Declared License</th>
              <th scope="col">Compliance Status</th>
              <th scope="col">Rule Triggered</th>
              <th scope="col">Context & Notes</th>
            </tr>
          </thead>
          <tbody>
            {licenses.map(l => (
              <tr key={l.subject}>
                <td style={{ fontWeight: 600 }}>
                  <code className="purl" style={{ fontWeight: 600 }}>
                    {l.name}@{l.version}
                  </code>
                </td>
                <td style={{ fontSize: 'var(--text-xs)', fontFamily: 'var(--font-mono)', color: 'var(--color-text)' }}>
                  {l.license_expr || <span style={{ color: 'var(--color-muted)' }}>UNKNOWN</span>}
                </td>
                <td>
                  <span className={`license-badge license-${l.license_status}`}>
                    {l.license_status.replace('_', ' ')}
                  </span>
                </td>
                <td style={{ fontSize: 'var(--text-xs)', fontFamily: 'var(--font-mono)', color: 'var(--color-muted)' }}>
                  {l.rule_fired || '—'}
                </td>
                <td style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-secondary)', lineHeight: 1.5 }}>
                  {l.note || '—'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default LicensesTab;

