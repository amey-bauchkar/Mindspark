import React, { useEffect, useState } from 'react';
import { BrowserRouter, Routes, Route, NavLink, Link } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Shield, ArrowRight, Lock, CheckCircle2 } from 'lucide-react';
import './styles/index.css';
import Landing from './routes/Landing';
import Analyze from './routes/Analyze';
import ReportPage from './routes/Report';
import Methodology from './routes/Methodology';
import NotFound from './routes/NotFound';
import { getHealth } from './lib/api';

const queryClient = new QueryClient({
  defaultOptions: { queries: { retry: 2, staleTime: 30_000 } },
});

function Nav() {
  const [offline, setOffline] = useState(false);

  useEffect(() => {
    getHealth().then(h => setOffline(h.offline)).catch(() => {});
  }, []);

  return (
    <nav className="nav" aria-label="Main navigation">
      <div className="container nav-inner">
        <div className="nav-brand-group">
          <Link to="/" className="nav-logo" aria-label="Warrant — Supply Chain Risk Analyzer">
            <div className="nav-logo-icon" aria-hidden="true">
              <Shield size={18} strokeWidth={2.4} />
            </div>
            <span>Warrant</span>
          </Link>
          <span className="nav-tagline hide-mobile">
            Supply Chain Risk Analyzer
          </span>
        </div>

        <ul className="nav-links" role="list">
          <li>
            <NavLink to="/analyze" className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}>
              Analyze
            </NavLink>
          </li>
          <li>
            <NavLink to="/methodology" className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}>
              Methodology
            </NavLink>
          </li>
          <li>
            <span
              className={`nav-badge ${offline ? 'recorded' : 'live'}`}
              title={offline ? 'Using recorded fixture database' : 'Live data from public security feeds'}
            >
              {offline ? 'Fixture Cache' : 'Live Feeds'}
            </span>
          </li>
        </ul>
      </div>
    </nav>
  );
}

function Footer() {
  return (
    <footer className="footer" role="contentinfo">
      <div className="container footer-inner">
        <div className="footer-top">
          <div className="footer-brand">
            <div className="nav-logo-icon" style={{ width: 24, height: 24, borderRadius: 6 }}>
              <Shield size={14} />
            </div>
            <span>Warrant</span>
            <span style={{ fontSize: 'var(--text-xs)', color: 'var(--color-muted)', fontWeight: 500 }}>
              — Deterministic Software Supply Chain Intelligence
            </span>
          </div>
          <ul className="footer-links">
            <li>
              <Link to="/analyze">Scan Lockfile</Link>
            </li>
            <li>
              <Link to="/methodology">Rule Engine (R1–R7)</Link>
            </li>
            <li>
              <a href="https://osv.dev" target="_blank" rel="noopener noreferrer">
                OSV Feeds
              </a>
            </li>
            <li>
              <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" rel="noopener noreferrer">
                CISA KEV
              </a>
            </li>
          </ul>
        </div>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 'var(--space-4)' }}>
          <p className="footer-text">
            Package-level deterministic verification across OSV, CISA KEV, EPSS, deps.dev, and registry feeds.
            <br />
            Strict top-down derivation table. Zero telemetry and no proprietary opaque scoring.
            <br />
            <span style={{ color: 'var(--color-text-secondary)', fontWeight: 600 }}>
              Cannot-assess statuses are explicitly untrusted. Never-green rule strictly honored.
            </span>
          </p>
          <p style={{ fontSize: 'var(--text-xs)', color: 'var(--color-muted)', textAlign: 'right' }}>
            © {new Date().getFullYear()} Warrant Security · Enterprise Defense
          </p>
        </div>
      </div>
    </footer>
  );
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <div id="app-root">
          <Nav />
          <main className="main-content" id="main-content">
            <Routes>
              <Route path="/" element={<Landing />} />
              <Route path="/analyze" element={<Analyze />} />
              <Route path="/report/:id" element={<ReportPage />} />
              <Route path="/methodology" element={<Methodology />} />
              <Route path="*" element={<NotFound />} />
            </Routes>
          </main>
          <Footer />
        </div>
      </BrowserRouter>
    </QueryClientProvider>
  );
}

