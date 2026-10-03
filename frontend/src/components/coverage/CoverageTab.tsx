import React from 'react';
import type { CoverageCheck } from '../../lib/types';

interface CoverageTabProps {
  coverage: CoverageCheck[];
}

export function CoverageTab({ coverage }: CoverageTabProps) {
  return (
    <div>
      <div style={{ marginBottom: 'var(--space-4)' }}>
        <h2 style={{ fontSize: 'var(--text-base)', fontWeight: 600 }}>Analysis Coverage</h2>
        <p
          style={{
            fontSize: 'var(--text-xs)',
            color: 'var(--color-muted)',
            marginTop: 'var(--space-1)',
          }}
        >
          Every row corresponds to real code that ran. "Not run" items are never treated as clean.
        </p>
      </div>
      <div className="table-wrapper">
        <table>
          <caption className="visually-hidden">Analysis coverage</caption>
          <thead>
            <tr>
              <th scope="col">Check</th>
              <th scope="col">Status</th>
              <th scope="col">Count</th>
              <th scope="col">Notes</th>
            </tr>
          </thead>
          <tbody>
            {coverage.map(c => (
              <tr key={c.check}>
                <td style={{ fontSize: 'var(--text-sm)' }}>{c.check}</td>
                <td>
                  <span
                    style={{
                      fontSize: 'var(--text-xs)',
                      fontWeight: 600,
                      padding: '2px 8px',
                      borderRadius: 'var(--radius-full)',
                      background:
                        c.status === 'Ran'
                          ? '#DCFCE7'
                          : c.status === 'Partial'
                          ? 'var(--verdict-upgrade-bg)'
                          : 'var(--color-bg)',
                      color:
                        c.status === 'Ran'
                          ? '#15803D'
                          : c.status === 'Partial'
                          ? 'var(--verdict-upgrade-fg)'
                          : 'var(--color-muted)',
                    }}
                  >
                    {c.status}
                  </span>
                </td>
                <td style={{ fontSize: 'var(--text-sm)', color: 'var(--color-muted)' }}>
                  {c.count !== undefined ? c.count : '—'}
                </td>
                <td style={{ fontSize: 'var(--text-xs)', color: 'var(--color-muted)' }}>
                  {c.reason || '—'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default CoverageTab;
