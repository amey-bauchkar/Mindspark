import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { getMethodology } from '../lib/api';
import { ChevronDown, ChevronRight } from 'lucide-react';

function Section({ id, title, children, defaultOpen = false }: {
  id: string;
  title: string;
  children: React.ReactNode;
  defaultOpen?: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div style={{ borderBottom: '1px solid var(--color-border)' }}>
      <button
        onClick={() => setOpen(x => !x)}
        style={{
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          width: '100%', padding: 'var(--space-5) 0',
          background: 'none', border: 'none', cursor: 'pointer',
          textAlign: 'left',
        }}
        aria-expanded={open}
        aria-controls={`section-${id}`}
        id={`heading-${id}`}
      >
        <h2 style={{ fontSize: 'var(--text-lg)', fontWeight: 700, letterSpacing: '-0.01em' }}>{title}</h2>
        {open ? <ChevronDown size={20} aria-hidden /> : <ChevronRight size={20} aria-hidden />}
      </button>
      {open && (
        <div id={`section-${id}`} role="region" aria-labelledby={`heading-${id}`} style={{ paddingBottom: 'var(--space-8)' }}>
          {children}
        </div>
      )}
    </div>
  );
}

export default function Methodology() {
  const { data, isLoading } = useQuery({
    queryKey: ['methodology'],
    queryFn: getMethodology,
    staleTime: 5 * 60 * 1000,
  });

  const rules = (data?.rules as any[]) || [];
  const licenseRules = (data?.license_rules as any[]) || [];
  const companyPolicies = (data?.company_policies as Record<string, any>) || {};
  const evidenceTiers = (data?.evidence_tiers as any[]) || [];
  const verdictDefs = (data?.verdict_definitions as any[]) || [];
  const dataSources = (data?.data_sources as any[]) || [];
  const limitations = (data?.limitations as string[]) || [];
  const currentParams = (data?.current_parameters as any) || {};

  if (isLoading) {
    return (
      <div className="container" style={{ paddingTop: 'var(--space-12)' }}>
        {[1, 2, 3].map(i => (
          <div key={i} className="skeleton" style={{ height: 60, marginBottom: 'var(--space-4)' }} />
        ))}
      </div>
    );
  }

  return (
    <div className="container" style={{ paddingTop: 'var(--space-10)', paddingBottom: 'var(--space-16)' }}>
      <div style={{ maxWidth: 820 }}>
        <div
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '8px',
            fontSize: 'var(--text-2xs)',
            fontWeight: 800,
            textTransform: 'uppercase',
            letterSpacing: '0.12em',
            color: 'var(--color-text)',
            marginBottom: 'var(--space-3)',
          }}
        >
          <span>✦</span>
          <span>Policy Engine Architecture</span>
        </div>

        <h1
          className="font-serif"
          style={{
            fontSize: 'clamp(2.25rem, 3.5vw, 3rem)',
            fontWeight: 500,
            letterSpacing: '-0.025em',
            lineHeight: 1.15,
            marginBottom: 'var(--space-4)',
          }}
        >
          How decisions are <span className="italic-accent">derived</span>
        </h1>

        <p style={{ fontSize: 'var(--text-base)', color: 'var(--color-muted)', lineHeight: 1.7, marginBottom: 'var(--space-10)' }}>
          Every verdict you see in a report is derived by applying the rule table on this page to the evidence collected.
          Rules are applied top-down, first match wins. No machine learning, no composite score, no black box.
          This page is the exact source code of what runs — the rules table in the UI is generated from the backend engine.
        </p>

        {/* Decision rules */}
        <Section id="rules" title="Decision rule table (R1–R7)" defaultOpen>
          <div className="callout callout-info" style={{ marginBottom: 'var(--space-6)' }}>
            <p style={{ fontSize: 'var(--text-sm)' }}>
              Rules are applied <strong>top-down per package</strong>. First matching rule wins.
              Current EPSS threshold: <code style={{ fontFamily: 'var(--font-mono)' }}>{currentParams.epss_threshold ?? '—'}</code> · 
              Freshness horizon: <code style={{ fontFamily: 'var(--font-mono)' }}>{currentParams.freshness_hours ?? '—'}h</code>
            </p>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
            {rules.map((rule: any) => (
              <div
                key={rule.id}
                style={{
                  padding: 'var(--space-5)',
                  border: '1px solid var(--color-border)',
                  borderRadius: 'var(--radius-md)',
                  background: 'var(--color-surface)',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'flex-start', gap: 'var(--space-4)', flexWrap: 'wrap' }}>
                  <code style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, fontSize: 'var(--text-sm)', color: 'var(--color-accent)', minWidth: 36 }}>
                    {rule.id}
                  </code>
                  <div style={{ flex: 1, minWidth: 200 }}>
                    <p style={{ fontWeight: 600, marginBottom: 'var(--space-2)' }}>{rule.name}</p>
                    <p style={{ fontSize: 'var(--text-sm)', color: 'var(--color-muted)', lineHeight: 1.6, marginBottom: 'var(--space-3)' }}>
                      {rule.condition}
                    </p>
                    {rule.verdict && (
                      <div style={{ display: 'flex', gap: 'var(--space-2)', flexWrap: 'wrap' }}>
                        <span className={`verdict-chip verdict-${rule.verdict}`}>{rule.verdict.replace('_', ' ')}</span>
                        {rule.qualifier && (
                          <span style={{ fontSize: 'var(--text-xs)', padding: '2px 8px', borderRadius: 'var(--radius-full)', background: 'var(--color-bg)', color: 'var(--color-muted)', border: '1px solid var(--color-border)' }}>
                            {rule.qualifier}
                          </span>
                        )}
                        {rule.urgency && (
                          <span style={{ fontSize: 'var(--text-xs)', padding: '2px 8px', borderRadius: 'var(--radius-full)', background: 'var(--color-bg)', color: 'var(--color-muted)', border: '1px solid var(--color-border)' }}>
                            {rule.urgency}
                          </span>
                        )}
                      </div>
                    )}
                    {rule.note && (
                      <p style={{ marginTop: 'var(--space-2)', fontSize: 'var(--text-xs)', color: 'var(--color-muted)', fontStyle: 'italic' }}>
                        {rule.note}
                      </p>
                    )}
                    {rule.response_steps?.length > 0 && (
                      <div style={{ marginTop: 'var(--space-3)' }}>
                        <p style={{ fontSize: 'var(--text-xs)', fontWeight: 600, color: 'var(--color-muted)', marginBottom: 'var(--space-1)' }}>Response steps:</p>
                        <ol style={{ paddingLeft: 'var(--space-4)', fontSize: 'var(--text-xs)', color: 'var(--color-muted)', lineHeight: 1.8 }}>
                          {rule.response_steps.map((s: string, i: number) => <li key={i}>{s}</li>)}
                        </ol>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </Section>

        {/* Evidence tiers */}
        <Section id="tiers" title="Evidence tiers" defaultOpen>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
            {evidenceTiers.map((t: any) => (
              <div key={t.tier} style={{ display: 'flex', alignItems: 'flex-start', gap: 'var(--space-4)', padding: 'var(--space-4)', border: '1px solid var(--color-border)', borderRadius: 'var(--radius-md)' }}>
                <span className={`tier-badge tier-${t.tier}`} style={{ minWidth: 60, textAlign: 'center' }}>{t.tier}</span>
                <div>
                  <p style={{ fontWeight: 600, fontSize: 'var(--text-sm)', marginBottom: 'var(--space-1)' }}>{t.name}</p>
                  <p style={{ fontSize: 'var(--text-sm)', color: 'var(--color-muted)' }}>{t.description}</p>
                </div>
              </div>
            ))}
          </div>
        </Section>

        {/* Verdict definitions */}
        <Section id="verdicts" title="Verdict definitions">
          <div className="table-wrapper">
            <table>
              <caption className="visually-hidden">Verdict definitions</caption>
              <thead>
                <tr>
                  <th scope="col">Verdict</th>
                  <th scope="col">Meaning</th>
                </tr>
              </thead>
              <tbody>
                {verdictDefs.map((v: any) => (
                  <tr key={v.verdict}>
                    <td><span className={`verdict-chip verdict-${v.verdict}`}>{v.verdict.replace(/_/g, ' ')}</span></td>
                    <td style={{ fontSize: 'var(--text-sm)' }}>{v.meaning}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Section>

        {/* License rules */}
        <Section id="licenses" title="License rule table (LR1–LR7)">
          <div className="table-wrapper">
            <table>
              <caption className="visually-hidden">License rules</caption>
              <thead>
                <tr>
                  <th scope="col">Rule</th>
                  <th scope="col">Category</th>
                  <th scope="col">Examples</th>
                  <th scope="col">Status</th>
                  <th scope="col">Notes</th>
                </tr>
              </thead>
              <tbody>
                {licenseRules.map((r: any) => (
                  <tr key={r.id}>
                    <td><code style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', fontWeight: 700, color: 'var(--color-accent)' }}>{r.id}</code></td>
                    <td style={{ fontSize: 'var(--text-sm)', fontWeight: 500 }}>{r.category}</td>
                    <td style={{ fontSize: 'var(--text-xs)', color: 'var(--color-muted)', fontFamily: 'var(--font-mono)' }}>{r.examples}</td>
                    <td style={{ fontSize: 'var(--text-xs)' }}>{r.status}</td>
                    <td style={{ fontSize: 'var(--text-xs)', color: 'var(--color-muted)' }}>{r.note}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p style={{ marginTop: 'var(--space-3)', fontSize: 'var(--text-xs)', color: 'var(--color-muted)', fontStyle: 'italic' }}>
            Results depend on the context answers (distribution mode, project license). Not legal advice.
          </p>
        </Section>

        {/* Corporate License Policies & Banned Dependencies */}
        <Section id="corporate-policies" title="Real-World Corporate Policies & Banned Dependencies" defaultOpen>
          <p style={{ fontSize: 'var(--text-sm)', color: 'var(--color-muted)', marginBottom: 'var(--space-4)', lineHeight: 1.6 }}>
            Major technology companies maintain strict internal open-source licensing whitelists and prohibited (banned) lists. Warrant allows evaluating your dependency graph directly against these documented corporate standards:
          </p>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
            {Object.values(companyPolicies).map((p: any) => (
              <div
                key={p.id}
                style={{
                  padding: 'var(--space-5)',
                  border: '1px solid var(--color-border)',
                  borderRadius: 'var(--radius-md)',
                  background: 'var(--color-surface)',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 'var(--space-2)', flexWrap: 'wrap', gap: 'var(--space-2)' }}>
                  <h3 style={{ fontSize: 'var(--text-base)', fontWeight: 700 }}>{p.company_name}</h3>
                  <a
                    href={p.source_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    style={{ fontSize: 'var(--text-xs)', color: 'var(--color-accent)', textDecoration: 'none', fontWeight: 600 }}
                  >
                    {p.official_policy_name} ↗
                  </a>
                </div>
                <p style={{ fontSize: 'var(--text-sm)', color: 'var(--color-muted)', marginBottom: 'var(--space-3)', lineHeight: 1.5 }}>
                  {p.summary}
                </p>

                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 'var(--space-3)', marginTop: 'var(--space-3)' }}>
                  {/* Allowed */}
                  <div style={{ padding: 'var(--space-3)', background: 'rgba(34, 197, 94, 0.05)', border: '1px solid rgba(34, 197, 94, 0.2)', borderRadius: 'var(--radius-sm)' }}>
                    <p style={{ fontSize: 'var(--text-xs)', fontWeight: 700, color: '#16a34a', textTransform: 'uppercase', marginBottom: 4 }}>
                      ✓ Permitted / Uses
                    </p>
                    <p style={{ fontSize: 'var(--text-xs)', fontFamily: 'var(--font-mono)', lineHeight: 1.6 }}>
                      {p.allowed_licenses.join(', ')}
                    </p>
                  </div>

                  {/* Banned */}
                  <div style={{ padding: 'var(--space-3)', background: 'rgba(239, 68, 68, 0.05)', border: '1px solid rgba(239, 68, 68, 0.2)', borderRadius: 'var(--radius-sm)' }}>
                    <p style={{ fontSize: 'var(--text-xs)', fontWeight: 700, color: '#ef4444', textTransform: 'uppercase', marginBottom: 4 }}>
                      ⛔ Prohibited / Banned
                    </p>
                    <p style={{ fontSize: 'var(--text-xs)', fontFamily: 'var(--font-mono)', lineHeight: 1.6, color: '#b91c1c' }}>
                      {p.banned_licenses.slice(0, 8).join(', ')}{p.banned_licenses.length > 8 ? ` (+${p.banned_licenses.length - 8} more)` : ''}
                    </p>
                  </div>

                  {/* Restricted */}
                  <div style={{ padding: 'var(--space-3)', background: 'rgba(234, 179, 8, 0.05)', border: '1px solid rgba(234, 179, 8, 0.2)', borderRadius: 'var(--radius-sm)' }}>
                    <p style={{ fontSize: 'var(--text-xs)', fontWeight: 700, color: '#ca8a04', textTransform: 'uppercase', marginBottom: 4 }}>
                      ⚠ Restricted / Approval
                    </p>
                    <p style={{ fontSize: 'var(--text-xs)', fontFamily: 'var(--font-mono)', lineHeight: 1.6 }}>
                      {p.restricted_licenses.slice(0, 6).join(', ')}
                    </p>
                  </div>
                </div>

                <p style={{ marginTop: 'var(--space-3)', fontSize: 'var(--text-xs)', color: 'var(--color-muted)', fontStyle: 'italic' }}>
                  <strong>Compliance Rationale:</strong> {p.banned_rationale}
                </p>
              </div>
            ))}
          </div>
        </Section>

        {/* Data sources */}
        <Section id="sources" title="Data sources">
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: 'var(--space-4)' }}>
            {dataSources.map((s: any) => (
              <div key={s.name} style={{ padding: 'var(--space-4)', border: '1px solid var(--color-border)', borderRadius: 'var(--radius-md)', background: 'var(--color-surface)' }}>
                <a href={s.url} target="_blank" rel="noopener noreferrer" style={{ fontWeight: 600, color: 'var(--color-accent)', textDecoration: 'none', fontSize: 'var(--text-sm)' }}>
                  {s.name} ↗
                </a>
                <p style={{ fontSize: 'var(--text-xs)', color: 'var(--color-muted)', marginTop: 'var(--space-1)' }}>{s.type}</p>
              </div>
            ))}
          </div>
        </Section>

        {/* Limitations */}
        <Section id="limitations" title="Known limitations">
          <ul style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)', paddingLeft: 'var(--space-4)' }}>
            {limitations.map((l: string, i: number) => (
              <li key={i} style={{ fontSize: 'var(--text-sm)', color: 'var(--color-muted)', lineHeight: 1.6 }}>{l}</li>
            ))}
          </ul>
        </Section>

        {/* Honest footer */}
        <div className="callout" style={{ marginTop: 'var(--space-8)', background: 'var(--color-bg)' }}>
          <p style={{ fontSize: 'var(--text-sm)', fontWeight: 500, marginBottom: 'var(--space-2)' }}>Important reminders</p>
          <ul style={{ paddingLeft: 'var(--space-4)', fontSize: 'var(--text-sm)', color: 'var(--color-muted)', lineHeight: 2 }}>
            <li>No function-level reachability — we only compute package-level paths.</li>
            <li>Heuristic signals (lookalike, staleness) are never decisive alone — always REVIEW tier.</li>
            <li>CANNOT ASSESS ≠ safe. A required check did not run.</li>
            <li>NO KNOWN FINDING ≠ safe. All required checks ran with nothing found, <em>as of this timestamp</em>.</li>
            <li>Public data may lag behind actual events.</li>
            <li>This tool does not execute any code from your lockfile.</li>
          </ul>
        </div>
      </div>
    </div>
  );
}
