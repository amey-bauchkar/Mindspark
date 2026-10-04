import React, { useEffect, useState } from 'react';
import { BrowserRouter, Routes, Route, NavLink, Link } from 'react-router-dom';
import { QueryClient, QueryClientProvider, useQuery } from '@tanstack/react-query';
import { Shield, ArrowRight, Lock, CheckCircle2 } from 'lucide-react';
import './styles/index.css';
import Landing from './routes/Landing';
import Analyze from './routes/Analyze';
import ReportPage from './routes/Report';
import PrintReportPage from './routes/PrintReportPage';
import Methodology from './routes/Methodology';
import NotFound from './routes/NotFound';
import WatchPage from './routes/Watch';
import { WatchAlerts } from './components/watch/WatchAlerts';
import { ApiKeyGate } from './components/ApiKeyGate';
import { getWatchAlerts } from './lib/api';

const queryClient = new QueryClient({
  defaultOptions: { queries: { retry: 2, staleTime: 30_000 } },
});

function Nav() {
  const { data: alerts } = useQuery({
    queryKey: ['watch-alerts'],
    queryFn: getWatchAlerts,
    refetchInterval: 10_000,
    retry: false,
  });

  return (
    <nav className="nav no-print" aria-label="Main navigation">
      <div className="container nav-inner">
        <div className="nav-brand-group">
          <Link to="/" className="nav-logo" aria-label="Warrant — Supply Chain Risk Analyzer">
            <img src="/logo.png" alt="Warrant" className="nav-logo-img" />
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
            <NavLink to="/watch" className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}>
              Watch
              {alerts && alerts.unacknowledged > 0 && (
                <span className="nav-count" aria-label={`${alerts.unacknowledged} new security changes`}>
                  {alerts.unacknowledged}
                </span>
              )}
            </NavLink>
          </li>
          <li>
            <NavLink to="/methodology" className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}>
              Methodology
            </NavLink>
          </li>
        </ul>
      </div>
    </nav>
  );
}

function Footer() {
  return (
    <footer className="footer no-print" role="contentinfo">
      <div className="container footer-inner">
        <div className="footer-grid">
          {/* Column 1: Brand & Intelligence Mandate */}
          <div className="footer-col footer-col-brand">
            <div className="footer-brand">
              <img src="/logo.png" alt="Warrant" className="footer-logo-img" />
              <span className="footer-brand-name">Warrant</span>
            </div>
            <p className="footer-brand-desc">
              Deterministic Software Supply Chain Intelligence. Real-time correlation of OSV malware records, CISA KEV active exploits, and FIRST.org EPSS scores without opaque composite estimations.
            </p>
            <div className="footer-badges">
              <span className="footer-pill">
                <span className="footer-pill-dot" /> Live Public Feeds
              </span>
              <span className="footer-pill">Zero Telemetry</span>
              <span className="footer-pill">R1–R7 Rules Engine</span>
            </div>
          </div>

          {/* Column 2: Platform Capabilities */}
          <div className="footer-col">
            <h4 className="footer-col-title">Platform</h4>
            <ul className="footer-link-list">
              <li><Link to="/analyze">Scan Lockfile</Link></li>
              <li><Link to="/watch">Continuous Watch</Link></li>
              <li><Link to="/methodology">Rule Engine (R1–R7)</Link></li>
              <li><Link to="/analyze?sample=axios-compromise">Axios 2026 Replay</Link></li>
              <li><Link to="/analyze?sample=lodash-kev">CISA KEV Exploit</Link></li>
            </ul>
          </div>

          {/* Column 3: Live Threat Intelligence */}
          <div className="footer-col">
            <h4 className="footer-col-title">Intelligence Sources</h4>
            <ul className="footer-link-list">
              <li><a href="https://osv.dev" target="_blank" rel="noopener noreferrer">OSV Open Source Feeds ↗</a></li>
              <li><a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" rel="noopener noreferrer">CISA KEV Catalog ↗</a></li>
              <li><a href="https://www.first.org/epss" target="_blank" rel="noopener noreferrer">FIRST.org EPSS Model ↗</a></li>
              <li><a href="https://deps.dev" target="_blank" rel="noopener noreferrer">OpenSSF & deps.dev ↗</a></li>
              <li><a href="https://registry.npmjs.org" target="_blank" rel="noopener noreferrer">Official NPM Registry ↗</a></li>
            </ul>
          </div>

          {/* Column 4: Enterprise Operations */}
          <div className="footer-col">
            <h4 className="footer-col-title">Enterprise Ops</h4>
            <ul className="footer-link-list">
              <li><span className="footer-spec-item">Atomic SQLite WAL Claims</span></li>
              <li><span className="footer-spec-item">SSRF-Protected Webhooks</span></li>
              <li><span className="footer-spec-item">Slack & Teams Connectors</span></li>
              <li><span className="footer-spec-item">CI/CD Merge Synchronization</span></li>
              <li><span className="footer-spec-item">Deterministic Audit Triage</span></li>
            </ul>
          </div>
        </div>

        {/* Bottom Bar */}
        <div className="footer-bottom">
          <p className="footer-bottom-copy">
            © {new Date().getFullYear()} Warrant Security · Enterprise Defense Console
          </p>
          <p className="footer-bottom-mantra">
            Cannot-assess statuses are explicitly untrusted. Never-green rule strictly honored.
          </p>
        </div>
      </div>
    </footer>
  );
}

function ThemedShell() {
  useEffect(() => {
    // Enforce crisp enterprise light console theme globally
    document.documentElement.removeAttribute('data-theme');
  }, []);

  return (
    <div id="app-root">
      <Nav />
      <WatchAlerts />
      <ApiKeyGate />
      <main className="main-content" id="main-content">
        <Routes>
          <Route path="/" element={<Landing />} />
          <Route path="/analyze" element={<Analyze />} />
          <Route path="/report/:id" element={<ReportPage />} />
          <Route path="/report/:id/print" element={<PrintReportPage />} />
          <Route path="/methodology" element={<Methodology />} />
          <Route path="/watch" element={<WatchPage />} />
          <Route path="*" element={<NotFound />} />
        </Routes>
      </main>
      <Footer />
    </div>
  );
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <ThemedShell />
      </BrowserRouter>
    </QueryClientProvider>
  );
}


