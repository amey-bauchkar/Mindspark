import React from 'react';
import type { LicenseResult, AnalysisContext } from '../../lib/types';
import { ShieldAlert, Building2 } from 'lucide-react';

interface LicensesTabProps {
  licenses: LicenseResult[];
  context?: AnalysisContext;
}

export function LicensesTab({ licenses, context }: LicensesTabProps) {
  const counts = { CONFLICT: 0, REVIEW: 0, UNKNOWN: 0, CANNOT_ASSESS: 0, OK: 0 };
  licenses.forEach(l => {
    if (l.license_status in counts) {
      (counts as Record<string, number>)[l.license_status]++;
    }
  });

  const company = context?.company_policy;
  const bannedCount = licenses.filter(l => l.rule_fired === 'LR8' || l.rule_fired === 'LR-BANNED-PKG').length;

  return (
    <div>
      {/* Corporate Policy Active Banner */}
      {company && (
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: 'var(--space-4)',
            padding: 'var(--space-4)',
            background: 'rgba(59, 130, 246, 0.08)',
            border: '1px solid rgba(59, 130, 246, 0.3)',
            borderRadius: 'var(--radius-md)',
            marginBottom: 'var(--space-6)',
            flexWrap: 'wrap',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
            <Building2 size={24} style={{ color: '#3b82f6', flexShrink: 0 }} aria-hidden />
            <div>
              <p style={{ fontWeight: 600, fontSize: 'var(--text-sm)' }}>
                Corporate Policy Enforced: <span style={{ textTransform: 'capitalize', color: '#3b82f6' }}>{company}</span>
              </p>
              <p style={{ fontSize: 'var(--text-xs)', color: 'var(--color-muted)', marginTop: 2 }}>
                Evaluating dependencies against {company.toUpperCase()}'s real-world open source license whitelist and prohibited license lists.
              </p>
            </div>
          </div>
          {bannedCount > 0 && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
              <ShieldAlert size={18} style={{ color: '#ef4444' }} aria-hidden />
              <span style={{ fontSize: 'var(--text-xs)', fontWeight: 700, color: '#ef4444' }}>
                {bannedCount} {bannedCount === 1 ? 'dependency' : 'dependencies'} banned by this policy!
              </span>
            </div>
          )}
        </div>
      )}

      {/* Counts */}
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
            {licenses.map(l => {
              const isBanned = l.rule_fired === 'LR8' || l.rule_fired === 'LR-BANNED-PKG';
              return (
                <tr key={l.subject} style={isBanned ? { background: 'rgba(239, 68, 68, 0.05)' } : {}}>
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
                    {isBanned && (
                      <span
                        style={{
                          marginLeft: 6,
                          fontSize: '10px',
                          fontWeight: 700,
                          background: '#ef4444',
                          color: '#fff',
                          padding: '2px 6px',
                          borderRadius: 4,
                          letterSpacing: '0.04em',
                        }}
                      >
                        BANNED
                      </span>
                    )}
                  </td>
                  <td style={{ fontSize: 'var(--text-xs)', color: 'var(--color-muted)' }}>
                    {l.rule_fired || '—'}
                  </td>
                  <td style={{ fontSize: 'var(--text-xs)', color: isBanned ? 'var(--color-text)' : 'var(--color-muted)' }}>
                    {l.note || '—'}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default LicensesTab;
