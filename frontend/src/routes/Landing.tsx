import React from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  Shield,
  GitBranch,
  Database,
  CheckCircle2,
  AlertTriangle,
  HelpCircle,
  ArrowRight,
  Terminal,
  Activity,
  Layers,
  FileCode,
  Lock,
  Search,
  ExternalLink,
} from 'lucide-react';
import { analyzeSample } from '../lib/api';

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
    <div style={{ backgroundColor: 'var(--color-bg)' }}>
      {/* ─── Hero Banner Section (Faithful to RealestateRoyal reference design) ──────────── */}
      <section className="hero-banner-section" aria-labelledby="hero-heading">
        <div className="container">
          <div className="hero-banner-container">
            {/* The 3D folder visual banner where the folder naturally sticks up past the rounded box */}
            <img
              src="/hero-banner.png"
              alt="Warrant Supply Chain Intelligence Banner"
              className="hero-banner-img"
            />

            {/* Left Content positioned neatly inside the blue box area */}
            <div className="hero-banner-overlay">
              <p className="hero-banner-overline">
                Deterministic Supply Chain Intelligence:
              </p>

              <h1 id="hero-heading" className="hero-banner-title">
                Know what your software is really built from — and what to fix first.
              </h1>

              <p className="hero-banner-desc">
                Drop a lockfile and get one evidence-backed decision per risky dependency,
                computed from a printed top-down rule table — not a black-box composite score.
              </p>

              <div className="hero-banner-actions">
                <Link to="/analyze" className="hero-btn-primary">
                  <span>Analyze a lockfile</span>
                  <ArrowRight size={15} aria-hidden />
                </Link>
                <button onClick={handleTryAxios} className="hero-btn-secondary">
                  <span>Try incident replay</span>
                </button>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ─── Public Data Feeds Bar ───────────────────────────────────────────── */}
      <section
        style={{
          padding: 'var(--space-8) 0',
          borderBottom: '1px solid var(--color-border)',
          backgroundColor: 'var(--color-bg-subtle)',
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
                letterSpacing: '0.08em',
                color: 'var(--color-muted)',
              }}
            >
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
                    padding: '6px 12px',
                    borderRadius: 'var(--radius-md)',
                    backgroundColor: 'var(--color-surface)',
                    border: '1px solid var(--color-border)',
                    fontSize: 'var(--text-xs)',
                    boxShadow: 'var(--shadow-xs)',
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
                  letterSpacing: '0.1em',
                  color: 'var(--color-accent)',
                  marginBottom: 'var(--space-3)',
                }}
              >
                <span
                  style={{
                    width: 8,
                    height: 8,
                    borderRadius: '50%',
                    backgroundColor: 'var(--color-accent)',
                    display: 'inline-block',
                  }}
                />
                <span>4 Simple Steps</span>
              </div>
              <h2
                id="how-heading"
                style={{
                  fontSize: 'clamp(2rem, 4vw, 2.75rem)',
                  fontWeight: 800,
                  letterSpacing: '-0.035em',
                  lineHeight: 1.15,
                  color: 'var(--color-text)',
                }}
              >
                Effortless Process,
                <br />
                Deterministic Verification
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

          {/* 4 Tall Cards */}
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(230px, 1fr))',
              gap: 'var(--space-5)',
              marginBottom: 'var(--space-6)',
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
                  minHeight: 290,
                  display: 'flex',
                  flexDirection: 'column',
                  justifyContent: 'space-between',
                  backgroundColor: 'var(--color-surface)',
                  border: '1px solid var(--color-border)',
                  boxShadow: 'var(--shadow-card)',
                }}
              >
                {/* Top: Step Number & Title */}
                <div>
                  <p
                    style={{
                      fontSize: 'var(--text-xl)',
                      fontWeight: 800,
                      color: 'var(--color-text)',
                      fontFamily: 'var(--font-heading)',
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
                    lineHeight: 1.65,
                  }}
                >
                  {item.desc}
                </p>
              </div>
            ))}
          </div>

          {/* Bottom Bar / Banner */}
          <div
            className="card"
            style={{
              borderRadius: 'var(--radius-xl)',
              padding: 'var(--space-4) var(--space-6)',
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
            <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
              <div style={{ display: 'flex', alignItems: 'center', marginLeft: 4 }}>
                <div
                  style={{
                    width: 32,
                    height: 32,
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
                  <Shield size={16} />
                </div>
                <div
                  style={{
                    width: 32,
                    height: 32,
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
                  <CheckCircle2 size={16} />
                </div>
                <div
                  style={{
                    width: 32,
                    height: 32,
                    borderRadius: '50%',
                    backgroundColor: 'var(--color-primary)',
                    color: '#ffffff',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    marginLeft: -10,
                    border: '2px solid #ffffff',
                    boxShadow: 'var(--shadow-xs)',
                  }}
                >
                  <Lock size={14} />
                </div>
              </div>
              <p style={{ fontSize: 'var(--text-sm)', color: 'var(--color-text-secondary)', fontWeight: 500 }}>
                Align with Security Teams that <strong style={{ color: 'var(--color-text)' }}>Choose Mathematical Proof</strong>
              </p>
            </div>

            <Link
              to="/analyze"
              className="btn btn-primary"
              style={{
                borderRadius: 'var(--radius-full)',
                padding: '8px 20px',
                display: 'inline-flex',
                alignItems: 'center',
                gap: '10px',
              }}
            >
              <span
                style={{
                  width: 22,
                  height: 22,
                  borderRadius: '50%',
                  backgroundColor: 'rgba(255,255,255,0.2)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                }}
              >
                <ArrowRight size={13} strokeWidth={2.6} />
              </span>
              <span>Start Now</span>
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
          <div style={{ textAlign: 'center', maxWidth: 640, margin: '0 auto var(--space-12)' }}>
            <h2
              id="scope-heading"
              style={{
                fontSize: 'var(--text-3xl)',
                fontWeight: 800,
                letterSpacing: '-0.03em',
                marginBottom: 'var(--space-3)',
                color: 'var(--color-text)',
              }}
            >
              Honest Boundaries & Scope
            </h2>
            <p style={{ fontSize: 'var(--text-base)', color: 'var(--color-muted)', lineHeight: 1.6 }}>
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
            <div className="card" style={{ borderLeft: '4px solid #047857' }}>
              <h3
                style={{
                  fontSize: 'var(--text-lg)',
                  fontWeight: 700,
                  color: 'var(--color-text)',
                  marginBottom: 'var(--space-4)',
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
                  'Known vulnerabilities with exact version ranges (OSV, GHSA, CVE)',
                  'Active malware reports (OSV MAL-*, OpenSSF malicious packages)',
                  'CISA Known Exploited Vulnerabilities catalog (in-the-wild attacks)',
                  'EPSS machine-learning exploitation probability scoring',
                  'Transitive dependency paths & upstream blast radius',
                  'Lookalike package typosquatting signals',
                  'Package staleness and suspicious sudden releases',
                  'License compliance conflicts and viral license triggers',
                  'Lifecycle install-script flags in dependency metadata',
                ].map(item => (
                  <li
                    key={item}
                    style={{
                      display: 'flex',
                      alignItems: 'flex-start',
                      gap: 'var(--space-2)',
                      fontSize: 'var(--text-sm)',
                      color: 'var(--color-text-secondary)',
                    }}
                  >
                    <CheckCircle2 size={16} style={{ color: '#047857', marginTop: 3, flexShrink: 0 }} />
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </div>

            {/* Out of Scope / Unchecked */}
            <div className="card" style={{ borderLeft: '4px solid var(--color-muted)' }}>
              <h3
                style={{
                  fontSize: 'var(--text-lg)',
                  fontWeight: 700,
                  color: 'var(--color-text)',
                  marginBottom: 'var(--space-4)',
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
                  'Function-level reachability (source code is never executed or instrumented)',
                  'Exploit confirmation on your specific host architecture',
                  'SLSA cryptographic build provenance & hardware attestations',
                  'Binary / bytecode decompilation analysis',
                  'Maintainer identity verification or commit signing audits',
                  'Dynamic malware sandbox detonation',
                  'Private internal registry dependencies without public feeds',
                  'Zero-day vulnerabilities without public advisories or heuristics',
                ].map(item => (
                  <li
                    key={item}
                    style={{
                      display: 'flex',
                      alignItems: 'flex-start',
                      gap: 'var(--space-2)',
                      fontSize: 'var(--text-sm)',
                      color: 'var(--color-muted)',
                    }}
                  >
                    <AlertTriangle size={16} style={{ color: 'var(--color-muted)', marginTop: 3, flexShrink: 0 }} />
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
              padding: 'var(--space-12) var(--space-8)',
              textAlign: 'center',
              maxWidth: 840,
              margin: '0 auto',
            }}
          >
            <div
              style={{
                width: 48,
                height: 48,
                borderRadius: 'var(--radius-md)',
                backgroundColor: 'var(--color-accent-bg)',
                color: 'var(--color-accent)',
                display: 'inline-flex',
                alignItems: 'center',
                justifyContent: 'center',
                marginBottom: 'var(--space-4)',
              }}
            >
              <Shield size={24} />
            </div>

            <h2
              style={{
                fontSize: 'var(--text-2xl)',
                fontWeight: 800,
                letterSpacing: '-0.03em',
                marginBottom: 'var(--space-3)',
                color: 'var(--color-text)',
              }}
            >
              Start analyzing software dependencies today
            </h2>

            <p
              style={{
                fontSize: 'var(--text-base)',
                color: 'var(--color-muted)',
                lineHeight: 1.6,
                maxWidth: 540,
                margin: '0 auto var(--space-6)',
              }}
            >
              Inspect package risk, transitive chains, and license compatibility with reproducible evidence.
            </p>

            <div style={{ display: 'flex', gap: 'var(--space-3)', justifyContent: 'center', flexWrap: 'wrap' }}>
              <Link to="/analyze" className="btn btn-primary btn-lg">
                <span>Upload a Lockfile</span>
                <ArrowRight size={16} aria-hidden />
              </Link>
              <Link to="/methodology" className="btn btn-secondary btn-lg">
                <span>Explore Methodology (R1–R7)</span>
              </Link>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}

