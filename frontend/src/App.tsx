import React, { useEffect, useState } from 'react';
import { BrowserRouter, Routes, Route, NavLink, Link } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
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
        <Link to="/" className="nav-logo" aria-label="Warrant — home">
          <span className="logo-dot" aria-hidden="true" />
          Warrant
        </Link>
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
              title={offline ? 'Using recorded fixture data' : 'Live data from public APIs'}
            >
              {offline ? 'Recorded' : 'Live'}
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
      <div className="container">
        <p className="footer-text">
          Package-level analysis. Public data sources (OSV, EPSS, CISA KEV, deps.dev, npm registry).
          <br />
          Not legal advice. No code is executed. Counts are unique package versions.
          <br />
          Cannot-assess items are not safe items.
          <br />
          <span style={{ color: 'var(--color-border)' }}>
            Warrant prototype — evidence-backed decisions, not guarantees.
          </span>
        </p>
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
