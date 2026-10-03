import React from 'react';
import { Link } from 'react-router-dom';
import {
  Shield,
  CheckCircle2,
  AlertTriangle,
  HelpCircle,
  ArrowRight,
  Lock,
  Layers,
  Sparkles,
  Database,
  ExternalLink,
} from 'lucide-react';
export default function Landing() {
  return (
    <div style={{ backgroundColor: 'var(--color-bg)' }}>
      {/* ─── Hero Section (Architectural Editorial Inspiration) ──────────── */}
      <section className="hero-editorial-section" aria-labelledby="hero-heading">
        <div className="container">
          <div className="hero-editorial-container">
            {/* Left Content */}
            <div className="hero-editorial-content">
              <p className="hero-editorial-overline">
                Crafting Dependable Software Ecosystems
              </p>

              <h1 id="hero-heading" className="hero-editorial-title">
                Set New Standards in{' '}
                <span className="italic-accent">Software Supply Chain</span> Verification
              </h1>

              <p className="hero-editorial-desc" style={{ marginBottom: 0 }}>
                Know what your software is really built from — and what to fix first.
                Drop a lockfile and derive unambiguous verdicts per risky dependency from a printed
                top-down rule table, never an opaque composite score.
              </p>
            </div>

            {/* Right Architectural Software Visual */}
            <div className="hero-editorial-visual">
              <img
                src="/hero-architecture.jpg"
                alt="Warrant Software Architecture and Security Monolith"
                className="hero-editorial-img"
              />
            </div>
          </div>
        </div>
      </section>

      {/* ─── Signature Statement Section ───────────────────────────────────── */}
      <section className="editorial-statement-section" aria-label="Core Philosophy and Capabilities">
        <div className="container">
          <div className="statement-center-container">
            <span className="editorial-diamond-icon" aria-hidden="true">
              ✦
            </span>

            <h2 className="statement-serif-heading">
              If it runs in <span className="italic-accent">production</span>, we can{' '}
              <span className="italic-accent">verify</span> it.
            </h2>

            <p className="statement-body-text">
              We adapt a uniquely deterministic perspective to each project to deliver
              verifiable spaces of optimal security. Renowned for zero-telemetry derivation tables
              and masterful audit trails, our engine eliminates speculative heuristics.
            </p>

            <Link to="/analyze" className="btn-pill-dark">
              <span>Analyze a lockfile</span>
              <ArrowRight size={15} aria-hidden />
            </Link>
          </div>
        </div>
      </section>

      {/* ─── Public Data Feeds Bar ───────────────────────────────────────────── */}
      <section
        style={{
          padding: 'var(--space-6) 0',
          borderTop: '1px solid var(--color-border)',
          borderBottom: '1px solid var(--color-border)',
          backgroundColor: 'var(--color-surface)',
        }}
        aria-labelledby="feeds-heading"
      >
        <div className="container">
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              flexWrap: 'wrap',
              gap: 'var(--space-4)',
            }}
          >
            <p
              id="feeds-heading"
              style={{
                fontSize: 'var(--text-xs)',
                fontWeight: 700,
                textTransform: 'uppercase',
                letterSpacing: '0.12em',
                color: 'var(--color-muted)',
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
              }}
            >
              <span style={{ color: '#0F172A' }}>✦</span>
              Real-time Public Feeds — 100% Keyless
            </p>
            <div
              style={{
                display: 'flex',
                flexWrap: 'wrap',
                gap: 'var(--space-3)',
                alignItems: 'center',
              }}
            >
              {[
                { name: 'OSV.dev', desc: 'Vulnerabilities & MAL-*' },
                { name: 'CISA KEV', desc: 'Active Exploitation' },
                { name: 'EPSS (first.org)', desc: 'Probability Metric' },
                { name: 'deps.dev', desc: 'Dependency Trees' },
                { name: 'npm Registry', desc: 'Package Metadata' },
              ].map(f => (
                <div
                  key={f.name}
                  style={{
                    padding: '8px 16px',
                    borderRadius: 'var(--radius-full)',
                    backgroundColor: 'var(--color-bg-subtle)',
                    border: '1px solid var(--color-border)',
                    fontSize: 'var(--text-xs)',
                    boxShadow: 'var(--shadow-xs)',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                  }}
                >
                  <span style={{ fontWeight: 700, color: 'var(--color-text)' }}>{f.name}</span>{' '}
                  <span style={{ color: 'var(--color-muted)' }}>({f.desc})</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* ─── How It Works (4 Simple Steps) ─────────────────────────────────── */}
      <section style={{ padding: 'var(--space-20) 0' }} aria-labelledby="how-heading">
        <div className="container">
          {/* Header row with Title and horizontal divider line */}
          <div
            style={{
              display: 'flex',
              alignItems: 'flex-end',
              justifyContent: 'space-between',
              gap: 'var(--space-8)',
              marginBottom: 'var(--space-12)',
            }}
          >
            <div>
              <div
                style={{
                  display: 'flex',
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
                <span>4 Simple Steps</span>
              </div>
              <h2
                id="how-heading"
                className="font-serif"
                style={{
                  fontSize: 'clamp(2rem, 3.8vw, 3rem)',
                  fontWeight: 500,
                  letterSpacing: '-0.025em',
                  lineHeight: 1.15,
                  color: 'var(--color-text)',
                }}
              >
                Effortless Process,
                <br />
                <span className="italic-accent">Deterministic Verification</span>
              </h2>
            </div>
            <div
              style={{
                flex: 1,
                height: 1,
                backgroundColor: 'var(--color-border)',
                marginBottom: 'var(--space-4)',
                maxWidth: 480,
              }}
              className="hide-mobile"
            />
          </div>

          {/* 4 Tall Cards with generous rounded corners */}
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
              gap: 'var(--space-6)',
              marginBottom: 'var(--space-8)',
            }}
          >
            {[
              {
                step: '01.',
                title: 'Drop a\nLockfile',
                desc: 'Upload your package-lock.json or pinned requirements.txt. Parsed fully in memory with zero code execution.',
              },
              {
                step: '02.',
                title: 'Reconstruct\nTree',
                desc: 'Rebuilds exact dependency graph edges, production scopes, lifecycle install scripts, and blast-radius paths.',
              },
              {
                step: '03.',
                title: 'Collect Live\nEvidence',
                desc: 'Queries public OSV vulnerabilities, MAL-* reports, CISA KEV, EPSS scores, and license compliance rules.',
              },
              {
                step: '04.',
                title: 'Derive Plain\nDecisions',
                desc: 'Applies deterministic rule table (R1–R7). Produces unambiguous verdicts with evidence and remediation.',
              },
            ].map(item => (
              <div
                key={item.step}
                className="card"
                style={{
                  borderRadius: 'var(--radius-xl)',
                  padding: 'var(--space-8) var(--space-6)',
                  minHeight: 300,
                  display: 'flex',
                  flexDirection: 'column',
                  justifyContent: 'space-between',
                  backgroundColor: 'var(--color-surface)',
                  border: '1px solid var(--color-border)',
                  boxShadow: 'var(--shadow-card)',
                  transition: 'all 0.3s cubic-bezier(0.16, 1, 0.3, 1)',
                }}
              >
                {/* Top: Step Number & Title */}
                <div>
                  <p
                    className="font-serif"
                    style={{
                      fontSize: '1.75rem',
                      fontWeight: 600,
                      color: 'var(--color-text)',
                      marginBottom: 'var(--space-3)',
                      letterSpacing: '-0.02em',
                    }}
                  >
                    {item.step}
                  </p>
                  <h3
                    style={{
                      fontSize: 'var(--text-lg)',
                      fontWeight: 700,
                      color: 'var(--color-text)',
                      lineHeight: 1.3,
                      whiteSpace: 'pre-line',
                    }}
                  >
                    {item.title}
                  </h3>
                </div>

                {/* Bottom: Description Text */}
                <p
                  style={{
                    fontSize: 'var(--text-xs)',
                    color: 'var(--color-muted)',
                    lineHeight: 1.7,
                  }}
                >
                  {item.desc}
                </p>
              </div>
            ))}
          </div>

          {/* Bottom Proof Banner with Pill Button */}
          <div
            className="card"
            style={{
              borderRadius: 'var(--radius-xl)',
              padding: 'var(--space-5) var(--space-8)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              flexWrap: 'wrap',
              gap: 'var(--space-4)',
              backgroundColor: 'var(--color-surface)',
              border: '1px solid var(--color-border)',
              boxShadow: 'var(--shadow-card)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-4)' }}>
              <div style={{ display: 'flex', alignItems: 'center', marginLeft: 4 }}>
                <div
                  style={{
                    width: 36,
                    height: 36,
                    borderRadius: '50%',
                    backgroundColor: 'var(--color-accent-bg)',
                    color: 'var(--color-accent)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    border: '2px solid #ffffff',
                    boxShadow: 'var(--shadow-xs)',
                  }}
                >
                  <Shield size={18} />
                </div>
                <div
                  style={{
                    width: 36,
                    height: 36,
                    borderRadius: '50%',
                    backgroundColor: '#ECFDF5',
                    color: '#047857',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    marginLeft: -10,
                    border: '2px solid #ffffff',
                    boxShadow: 'var(--shadow-xs)',
                  }}
                >
                  <CheckCircle2 size={18} />
                </div>
                <div
                  style={{
                    width: 36,
                    height: 36,
                    borderRadius: '50%',
                    backgroundColor: '#0F172A',
                    color: '#ffffff',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    marginLeft: -10,
                    border: '2px solid #ffffff',
                    boxShadow: 'var(--shadow-xs)',
                  }}
                >
                  <Lock size={16} />
                </div>
              </div>
              <p style={{ fontSize: 'var(--text-sm)', color: 'var(--color-text-secondary)', fontWeight: 500 }}>
                Align with security teams that <strong style={{ color: 'var(--color-text)' }}>choose mathematical proof</strong>
              </p>
            </div>

            <Link
              to="/analyze"
              className="btn-pill-dark"
              style={{
                padding: '10px 22px',
                fontSize: 'var(--text-xs)',
              }}
            >
              <span>Start Now</span>
              <ArrowRight size={14} />
            </Link>
          </div>
        </div>
      </section>

      {/* ─── Scope & Boundary Definition ("What We Check vs What We Don't") ──── */}
      <section
        style={{
          padding: 'var(--space-20) 0',
          backgroundColor: 'var(--color-surface)',
          borderTop: '1px solid var(--color-border)',
          borderBottom: '1px solid var(--color-border)',
        }}
        aria-labelledby="scope-heading"
      >
        <div className="container">
          <div style={{ textAlign: 'center', maxWidth: 680, margin: '0 auto var(--space-12)' }}>
            <span style={{ fontSize: '1.25rem', color: '#0F172A', marginBottom: 12, display: 'inline-block' }}>
              ✦
            </span>
            <h2
              id="scope-heading"
              className="font-serif"
              style={{
                fontSize: 'clamp(2rem, 3.5vw, 2.75rem)',
                fontWeight: 500,
                letterSpacing: '-0.025em',
                marginBottom: 'var(--space-3)',
                color: 'var(--color-text)',
              }}
            >
              Honest Boundaries & <span className="italic-accent">Verifiable Scope</span>
            </h2>
            <p style={{ fontSize: 'var(--text-base)', color: 'var(--color-muted)', lineHeight: 1.65 }}>
              Security tools must be transparent about what they can and cannot prove.
            </p>
          </div>

          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
              gap: 'var(--space-8)',
            }}
          >
            {/* Verified Scope */}
            <div
              className="card"
              style={{
                borderRadius: 'var(--radius-xl)',
                borderTop: '4px solid #047857',
                padding: 'var(--space-8)',
              }}
            >
              <h3
                style={{
                  fontSize: 'var(--text-lg)',
                  fontWeight: 700,
                  color: 'var(--color-text)',
                  marginBottom: 'var(--space-5)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 'var(--space-2)',
                }}
              >
                <CheckCircle2 size={20} style={{ color: '#047857' }} />
                <span>What Warrant Checks</span>
              </h3>
              <ul style={{ listStyle: 'none', display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
                {[
                  'Known security flaws & vulnerabilities (CVEs)',
                  'Active malware & malicious packages',
                  'Exploits in the wild & attack probability',
                  'Deep dependency trees & blast radius',
                  'License compliance & legal restrictions',
                ].map(item => (
                  <li
                    key={item}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: 'var(--space-2)',
                      fontSize: 'var(--text-sm)',
                      color: 'var(--color-text-secondary)',
                      lineHeight: 1.5,
                    }}
                  >
                    <CheckCircle2 size={16} style={{ color: '#047857', flexShrink: 0 }} />
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </div>

            {/* Out of Scope / Unchecked */}
            <div
              className="card"
              style={{
                borderRadius: 'var(--radius-xl)',
                borderTop: '4px solid var(--color-muted)',
                padding: 'var(--space-8)',
              }}
            >
              <h3
                style={{
                  fontSize: 'var(--text-lg)',
                  fontWeight: 700,
                  color: 'var(--color-text)',
                  marginBottom: 'var(--space-5)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 'var(--space-2)',
                }}
              >
                <HelpCircle size={20} style={{ color: 'var(--color-muted)' }} />
                <span>What Warrant Does NOT Check</span>
              </h3>
              <ul style={{ listStyle: 'none', display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
                {[
                  'Your private application code (never executed or uploaded)',
                  'Unknown zero-day flaws with no public advisories',
                  'Private internal packages without public feeds',
                  'Host server or operating system setup',
                  'Dynamic sandbox exploit detonation',
                ].map(item => (
                  <li
                    key={item}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: 'var(--space-2)',
                      fontSize: 'var(--text-sm)',
                      color: 'var(--color-muted)',
                      lineHeight: 1.5,
                    }}
                  >
                    <AlertTriangle size={16} style={{ color: 'var(--color-muted)', flexShrink: 0 }} />
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      </section>

      {/* ─── Bottom Call to Action ───────────────────────────────────────────── */}
      <section style={{ padding: 'var(--space-20) 0' }}>
        <div className="container">
          <div
            className="card-elevated"
            style={{
              backgroundColor: 'var(--color-surface)',
              border: '1px solid var(--color-border)',
              borderRadius: 'var(--radius-2xl)',
              padding: 'var(--space-16) var(--space-8)',
              textAlign: 'center',
              maxWidth: 920,
              margin: '0 auto',
              boxShadow: 'var(--shadow-floating)',
            }}
          >
            <div
              style={{
                width: 52,
                height: 52,
                borderRadius: 'var(--radius-full)',
                backgroundColor: 'var(--color-bg-subtle)',
                color: '#0F172A',
                display: 'inline-flex',
                alignItems: 'center',
                justifyContent: 'center',
                marginBottom: 'var(--space-5)',
                border: '1px solid var(--color-border)',
              }}
            >
              <Shield size={26} />
            </div>

            <h2
              className="font-serif"
              style={{
                fontSize: 'clamp(2rem, 3.5vw, 2.75rem)',
                fontWeight: 500,
                letterSpacing: '-0.025em',
                marginBottom: 'var(--space-4)',
                color: 'var(--color-text)',
              }}
            >
              Start analyzing software dependencies with{' '}
              <span className="italic-accent">mathematical certainty</span>
            </h2>

            <p
              style={{
                fontSize: 'var(--text-base)',
                color: 'var(--color-muted)',
                lineHeight: 1.7,
                maxWidth: 580,
                margin: '0 auto var(--space-8)',
              }}
            >
              Inspect package risk, transitive chains, and license compatibility with reproducible evidence.
              Never guess which vulnerability to patch next.
            </p>

            <div style={{ display: 'flex', gap: 'var(--space-4)', justifyContent: 'center', flexWrap: 'wrap' }}>
              <Link to="/analyze" className="btn-pill-dark" style={{ padding: '14px 32px', fontSize: 'var(--text-base)' }}>
                <span>Upload a Lockfile</span>
                <ArrowRight size={17} aria-hidden />
              </Link>
              <Link to="/methodology" className="btn btn-secondary btn-lg" style={{ borderRadius: 'var(--radius-full)' }}>
                <span>Explore Methodology (R1–R7)</span>
              </Link>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}
