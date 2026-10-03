import React from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Shield, GitBranch, Database, CheckCircle2, AlertTriangle, HelpCircle, ArrowRight, Lock } from 'lucide-react';
import { analyzeSample } from '../lib/api';

function VerdictChip({ verdict, label }: { verdict: string; label: string }) {
  return (
    <span className={`verdict-chip verdict-${verdict}`}>
      {label}
    </span>
  );
}

function ExampleCard() {
  return (
    <div className="card" style={{ maxWidth: 560, margin: '0 auto' }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 'var(--space-4)', flexWrap: 'wrap' }}>
        <div style={{ flex: 1, minWidth: 200 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginBottom: 'var(--space-2)' }}>
            <VerdictChip verdict="INCIDENT" label="INCIDENT" />
            <span className="tier-badge tier-T1">T1</span>
          </div>
          <code className="purl">plain-crypto-js@4.2.1</code>
          <p style={{ marginTop: 'var(--space-2)', fontSize: 'var(--text-sm)', color: 'var(--color-text)' }}>
            Reported malicious (Amazon Inspector MAL-2026-2306)
          </p>
          <p style={{ marginTop: 'var(--space-1)', fontSize: 'var(--text-xs)', color: 'var(--color-muted)' }}>
            Via: <code style={{ fontFamily: 'var(--font-mono)' }}>my-app → axios → plain-crypto-js</code> ⚠ install script
          </p>
        </div>
        <div style={{ borderLeft: '1px solid var(--color-border)', paddingLeft: 'var(--space-4)', minWidth: 180 }}>
          <p className="drawer-section-title" style={{ marginBottom: 'var(--space-2)' }}>Not checked</p>
          <ul style={{ fontSize: 'var(--text-xs)', color: 'var(--color-muted)', listStyle: 'none', lineHeight: 1.8 }}>
            <li>Reachability: not assessed</li>
            <li>Provenance: not in this version</li>
          </ul>
          <div style={{ marginTop: 'var(--space-3)', padding: 'var(--space-2)', background: 'var(--verdict-incident-bg)', borderRadius: 'var(--radius-sm)', fontSize: 'var(--text-xs)', color: 'var(--verdict-incident-fg)' }}>
            Derivation: R1 ← E0001
          </div>
        </div>
      </div>
      <p style={{ marginTop: 'var(--space-4)', fontSize: 'var(--text-xs)', color: 'var(--color-muted)', fontStyle: 'italic', borderTop: '1px solid var(--color-border)', paddingTop: 'var(--space-3)' }}>
        Example output format — not from a live analysis
      </p>
    </div>
  );
}

export default function Landing() {
  const navigate = useNavigate();

  async function handleTryAxios() {
    try {
      const { report_id } = await analyzeSample('axios-replay', {});
      navigate(`/report/${report_id}`);
    } catch {
      navigate('/analyze');
    }
  }

  return (
    <div>
      {/* ── Hero ─────────────────────────────────────────────────────── */}
      <section
        style={{
          padding: 'var(--space-16) 0 var(--space-12)',
          background: `linear-gradient(180deg, var(--color-surface) 0%, var(--color-bg) 100%)`,
          borderBottom: '1px solid var(--color-border)',
        }}
        aria-labelledby="hero-heading"
      >
        <div className="container" style={{ textAlign: 'center' }}>
          <div
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 'var(--space-2)',
              padding: 'var(--space-1) var(--space-3)',
              background: 'var(--color-accent-bg)',
              color: 'var(--color-accent)',
              borderRadius: 'var(--radius-full)',
              fontSize: 'var(--text-xs)',
              fontWeight: 600,
              marginBottom: 'var(--space-6)',
              border: '1px solid var(--color-border)',
            }}
          >
            <Shield size={12} aria-hidden />
            Software Supply Chain Risk Analyzer
          </div>

          <h1
            id="hero-heading"
            style={{
              fontSize: 'clamp(2rem, 5vw, 3.5rem)',
              fontWeight: 700,
              lineHeight: 1.15,
              letterSpacing: '-0.03em',
              color: 'var(--color-text)',
              maxWidth: 720,
              margin: '0 auto var(--space-6)',
            }}
          >
            Know what your software is really built from — and what to fix first.
          </h1>

          <p
            style={{
              fontSize: 'var(--text-lg)',
              color: 'var(--color-muted)',
              maxWidth: 560,
              margin: '0 auto var(--space-8)',
              lineHeight: 1.6,
            }}
          >
            Drop a lockfile and get one evidence-backed decision per risky dependency,
            computed from a printed rule table — not a black-box score.
          </p>

          <div style={{ display: 'flex', gap: 'var(--space-3)', justifyContent: 'center', flexWrap: 'wrap' }}>
            <Link to="/analyze" className="btn btn-primary">
              Analyze a lockfile
              <ArrowRight size={16} aria-hidden />
            </Link>
            <button onClick={handleTryAxios} className="btn btn-secondary">
              Try the incident replay
            </button>
          </div>
        </div>
      </section>

      {/* ── How it works ─────────────────────────────────────────────── */}
      <section style={{ padding: 'var(--space-16) 0' }} aria-labelledby="how-heading">
        <div className="container">
          <h2
            id="how-heading"
            style={{ fontSize: 'var(--text-xl)', fontWeight: 700, letterSpacing: '-0.02em', marginBottom: 'var(--space-10)', textAlign: 'center' }}
          >
            How it works
          </h2>

          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
              gap: 'var(--space-6)',
            }}
          >
            {[
              {
                icon: <GitBranch size={22} aria-hidden />,
                step: '01',
                title: 'Drop a lockfile',
                desc: 'Upload package-lock.json (npm) or a pinned requirements.txt (Python — limited). Up to 5,000 packages.',
              },
              {
                icon: <Database size={22} aria-hidden />,
                step: '02',
                title: 'Rebuild the full tree',
                desc: 'The dependency graph is reconstructed, including transitive deps, scopes, and install-script flags.',
              },
              {
                icon: <Shield size={22} aria-hidden />,
                step: '03',
                title: 'Check public evidence',
                desc: 'OSV vulnerabilities, malware reports (MAL-*), CISA KEV, EPSS scores, license data, and heuristic signals — all real, all keyless.',
              },
              {
                icon: <CheckCircle2 size={22} aria-hidden />,
                step: '04',
                title: 'Get decisions with proof',
                desc: 'One verdict per risky dependency, computed from a printed rule table. Evidence shown, unknowns explicit.',
              },
            ].map(item => (
              <div key={item.step} className="card" style={{ position: 'relative' }}>
                <div
                  style={{
                    width: 40, height: 40,
                    borderRadius: 'var(--radius-md)',
                    background: 'var(--color-accent-bg)',
                    color: 'var(--color-accent)',
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    marginBottom: 'var(--space-4)',
                  }}
                >
                  {item.icon}
                </div>
                <p style={{ fontSize: 'var(--text-xs)', color: 'var(--color-muted)', fontFamily: 'var(--font-mono)', marginBottom: 'var(--space-2)' }}>
                  Step {item.step}
                </p>
                <h3 style={{ fontSize: 'var(--text-base)', fontWeight: 600, marginBottom: 'var(--space-2)' }}>
                  {item.title}
                </h3>
                <p style={{ fontSize: 'var(--text-sm)', color: 'var(--color-muted)', lineHeight: 1.6 }}>
                  {item.desc}
                </p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── Example output ────────────────────────────────────────────── */}
      <section
        style={{ padding: 'var(--space-12) 0', background: 'var(--color-surface)', borderTop: '1px solid var(--color-border)', borderBottom: '1px solid var(--color-border)' }}
        aria-labelledby="example-heading"
      >
        <div className="container">
          <h2
            id="example-heading"
            style={{ fontSize: 'var(--text-xl)', fontWeight: 700, letterSpacing: '-0.02em', marginBottom: 'var(--space-2)', textAlign: 'center' }}
          >
            Example output format
          </h2>
          <p style={{ textAlign: 'center', fontSize: 'var(--text-sm)', color: 'var(--color-muted)', marginBottom: 'var(--space-8)' }}>
            Each card shows verdict, evidence tier, dependency path, and what wasn't checked.
          </p>
          <ExampleCard />
        </div>
      </section>

      {/* ── What we check / don't check ───────────────────────────────── */}
      <section style={{ padding: 'var(--space-16) 0' }} aria-labelledby="scope-heading">
        <div className="container">
          <h2
            id="scope-heading"
            style={{ fontSize: 'var(--text-xl)', fontWeight: 700, letterSpacing: '-0.02em', marginBottom: 'var(--space-8)', textAlign: 'center' }}
          >
            What we check — and what we don't
          </h2>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 'var(--space-8)' }}>
            <div>
              <h3 style={{ fontSize: 'var(--text-base)', fontWeight: 600, color: 'var(--color-accent)', marginBottom: 'var(--space-4)', display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
                <CheckCircle2 size={18} aria-hidden /> We check
              </h3>
              <ul style={{ listStyle: 'none', display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
                {[
                  'Known vulnerabilities (OSV, GHSA, CVE)',
                  'Malware reports (OSV MAL-*, OpenSSF)',
                  'CISA Known Exploited Vulnerabilities',
                  'EPSS exploitation probability scores',
                  'Transitive dependency paths',
                  'Lookalike package names (heuristic)',
                  'Package freshness and staleness',
                  'License conflicts with your project context',
                  'Install-script flags in the lockfile',
                ].map(item => (
                  <li key={item} style={{ display: 'flex', alignItems: 'flex-start', gap: 'var(--space-2)', fontSize: 'var(--text-sm)', color: 'var(--color-text)' }}>
                    <CheckCircle2 size={16} style={{ color: '#15803D', marginTop: 2, flexShrink: 0 }} aria-hidden />
                    {item}
                  </li>
                ))}
              </ul>
            </div>

            <div>
              <h3 style={{ fontSize: 'var(--text-base)', fontWeight: 600, color: 'var(--color-muted)', marginBottom: 'var(--space-4)', display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
                <HelpCircle size={18} aria-hidden /> We don't check
              </h3>
              <ul style={{ listStyle: 'none', display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
                {[
                  'Function-level reachability (code not executed)',
                  'Exploit confirmation on your system',
                  'Provenance / SLSA attestations',
                  'Release diff / version comparison',
                  'Maintainer identity or history',
                  'Malware sandbox execution',
                  'Maven, Poetry, Go modules (future)',
                  'Private registry packages',
                ].map(item => (
                  <li key={item} style={{ display: 'flex', alignItems: 'flex-start', gap: 'var(--space-2)', fontSize: 'var(--text-sm)', color: 'var(--color-muted)' }}>
                    <AlertTriangle size={16} style={{ color: 'var(--color-muted)', marginTop: 2, flexShrink: 0 }} aria-hidden />
                    {item}
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      </section>

      {/* ── Data sources ─────────────────────────────────────────────── */}
      <section
        style={{ padding: 'var(--space-10) 0', background: 'var(--color-surface)', borderTop: '1px solid var(--color-border)' }}
        aria-labelledby="sources-heading"
      >
        <div className="container" style={{ textAlign: 'center' }}>
          <h2 id="sources-heading" style={{ fontSize: 'var(--text-sm)', color: 'var(--color-muted)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 'var(--space-6)' }}>
            Public data sources — all keyless
          </h2>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--space-4)', justifyContent: 'center', alignItems: 'center' }}>
            {['OSV.dev', 'CISA KEV', 'EPSS (first.org)', 'deps.dev', 'npm registry'].map(src => (
              <span
                key={src}
                style={{
                  padding: 'var(--space-2) var(--space-4)',
                  border: '1px solid var(--color-border)',
                  borderRadius: 'var(--radius-md)',
                  fontSize: 'var(--text-sm)',
                  fontWeight: 500,
                  color: 'var(--color-text)',
                  background: 'var(--color-bg)',
                }}
              >
                {src}
              </span>
            ))}
          </div>
        </div>
      </section>
    </div>
  );
}
