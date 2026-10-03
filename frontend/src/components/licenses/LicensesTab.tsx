import React from 'react';
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

  return (
    <div>
      <div
        style={{
          display: 'flex',
          gap: 'var(--space-3)',
          flexWrap: 'wrap',
          marginBottom: 'var(--space-6)',
        }}
      >
        {Object.entries(counts).map(([k, v]) => (
          <div
            key={k}
            style={{
              padding: 'var(--space-3) var(--space-4)',
              background: 'var(--color-surface)',
              border: '1px solid var(--color-border)',
              borderRadius: 'var(--radius-md)',
              textAlign: 'center',
              minWidth: 80,
            }}
          >
            <p style={{ fontSize: 'var(--text-xl)', fontWeight: 700 }}>{v}</p>
            <p
              style={{
                fontSize: 'var(--text-xs)',
                color: 'var(--color-muted)',
                textTransform: 'uppercase',
                letterSpacing: '0.05em',
              }}
            >
              {k.replace('_', ' ')}
            </p>
          </div>
        ))}
      </div>
      <div className="table-wrapper">
        <table>
          <caption className="visually-hidden">License classification results</caption>
          <thead>
            <tr>
              <th scope="col">Package</th>
              <th scope="col">License</th>
              <th scope="col">Status</th>
              <th scope="col">Rule</th>
              <th scope="col">Note</th>
            </tr>
          </thead>
          <tbody>
            {licenses.map(l => (
              <tr key={l.subject}>
                <td>
                  <code className="purl">
                    {l.name}@{l.version}
                  </code>
                </td>
                <td style={{ fontSize: 'var(--text-xs)', fontFamily: 'var(--font-mono)' }}>
                  {l.license_expr || 'UNKNOWN'}
                </td>
                <td>
                  <span className={`license-badge license-${l.license_status}`}>
                    {l.license_status.replace('_', ' ')}
                  </span>
                </td>
                <td style={{ fontSize: 'var(--text-xs)', color: 'var(--color-muted)' }}>
                  {l.rule_fired || '—'}
                </td>
                <td style={{ fontSize: 'var(--text-xs)', color: 'var(--color-muted)' }}>
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
