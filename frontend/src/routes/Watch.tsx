import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useMutation, useQuery } from '@tanstack/react-query';
import { Eye, FastForward } from 'lucide-react';
import { getWatchHealth, getWatchScenarios, getWatches, startWatchDemo } from '../lib/api';
import { CopyButton } from '../components/ui/CopyButton';
import { formatDate } from '../lib/format';
import { VerdictChip } from '../components/ui/VerdictChip';

const STATUS_TEXT: Record<string, string> = { active: 'Active', paused: 'Paused', disabled: 'Disabled' };

export default function WatchPage() {
  const navigate = useNavigate();
  const [error, setError] = useState<string | null>(null);
  const { data } = useQuery({ queryKey: ['watches'], queryFn: getWatches, refetchInterval: 10_000 });
  const { data: scenarios } = useQuery({ queryKey: ['watch-scenarios'], queryFn: getWatchScenarios });
  const { data: health } = useQuery({ queryKey: ['watch-health'], queryFn: getWatchHealth, refetchInterval: 30_000 });
  const apiBase = `${window.location.origin}/api`;
  const ciSnippet = `- name: Update Warrant Watch
  if: github.ref == 'refs/heads/main'
  run: |
    curl --fail-with-body -sS -X POST "${apiBase}/watch/sync" \\
      -H "X-Warrant-Key: \${{ secrets.WARRANT_API_KEY }}" \\
      -F "project=\${{ github.repository }}" \\
      -F "file=@package-lock.json"`;

  const demo = useMutation({
    mutationFn: startWatchDemo,
    onSuccess: w => navigate(`/report/${w.baseline_report_id}`),
    onError: (e: Error) => setError(e.message),
  });

  const watches = data?.watches || [];

  return (
    <div className="container" style={{ paddingTop: 'var(--space-8)', paddingBottom: 'var(--space-16)', maxWidth: 960 }}>
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
          marginBottom: 'var(--space-2)',
        }}
      >
        <span>✦</span>
        <span>Continuous Security Monitor</span>
      </div>

      <h1
        className="font-serif"
        style={{
          fontSize: 'clamp(2.25rem, 3.5vw, 3rem)',
          fontWeight: 500,
          letterSpacing: '-0.025em',
          lineHeight: 1.15,
          display: 'flex',
          alignItems: 'center',
          gap: 'var(--space-3)',
          marginBottom: 'var(--space-3)',
        }}
      >
        <Eye size={28} aria-hidden /> Warrant <span className="italic-accent">Watch</span>
      </h1>
      <p style={{ color: 'var(--color-muted)', marginTop: 'var(--space-2)', maxWidth: 720 }}>
        A continuous security-evidence monitor for the exact dependency versions already analysed by Warrant.
        It re-checks OSV (incl. OpenSSF MAL-* reports), CISA KEV and EPSS, re-runs the same decision rules, and tells you
        when a verdict changes. It does not scan code, install packages or run anything.
      </p>

      {health && (
        <p className={health.failing_projects.length || !health.scheduler_running ? 'watch-check watch-check-failed' : 'watch-meta'}
           role="status" style={{ marginTop: 'var(--space-4)' }}>
          {health.scheduler_running ? 'Scheduler running' : 'Scheduler NOT running — no automatic checks'}
          {health.last_tick_at && ` · last run ${formatDate(health.last_tick_at)}`}
          {` · ${health.projects} project${health.projects === 1 ? '' : 's'}`}
          {health.failing_projects.length > 0 &&
            ` · ${health.failing_projects.length} failing: ${health.failing_projects.map(f => f.name).join(', ')}`}
          {(health.notifications.failed ?? 0) > 0 && ` · ${health.notifications.failed} notification(s) could not be delivered`}
          {(health.notifications.pending ?? 0) > 0 && ` · ${health.notifications.pending} retrying`}
        </p>
      )}

      <h2 className="watch-section-title">Monitored projects</h2>
      {watches.length === 0 ? (
        <p className="watch-meta">
          Nothing monitored yet. Analyze a lockfile, then choose <strong>Monitor this project</strong> on the report.{' '}
          <Link to="/analyze">Analyze a lockfile →</Link>
        </p>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
          {watches.map(w => (
            <div key={w.id} className="card" style={{ padding: 'var(--space-4) var(--space-5)' }}>
              <div style={{ display: 'flex', gap: 'var(--space-3)', alignItems: 'center', flexWrap: 'wrap' }}>
                <span className={`watch-status watch-status-${w.status}`}>{STATUS_TEXT[w.status]}</span>
                {w.simulated && <span className="watch-sim-badge">{w.label}</span>}
                <strong>{w.name}</strong>
                <span className="watch-meta" style={{ margin: 0 }}>
                  {w.package_count} dependencies · last checked {w.last_checked_at ? formatDate(w.last_checked_at) : 'not yet'}
                </span>
                <Link to={`/report/${w.latest_report_id}`} className="btn btn-secondary btn-sm" style={{ marginLeft: 'auto' }}>
                  Open latest analysis
                </Link>
              </div>
              {w.last_check && <p className={`watch-check watch-check-${w.last_check.status}`}>{w.last_check.summary}</p>}
              {w.latest_event && (
                <p className="watch-meta" style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center', flexWrap: 'wrap' }}>
                  Latest change: <code className="font-mono">{w.latest_event.package}@{w.latest_event.version}</code>
                  <VerdictChip verdict={w.latest_event.previous.verdict} /> →
                  <VerdictChip verdict={w.latest_event.current.verdict} />
                  · {formatDate(w.latest_event.detected_at)} · {w.event_count} change{w.event_count === 1 ? '' : 's'} total
                </p>
              )}
            </div>
          ))}
        </div>
      )}

      <h2 className="watch-section-title">Connect CI</h2>
      <p className="watch-meta" style={{ maxWidth: 720 }}>
        Keep monitoring in step with what you ship: send the lockfile on every merge to main. The first call creates
        the project; later calls update its dependencies and keep its history and alerts. Store the API key as a CI secret.
      </p>
      <div className="watch-ci">
        <CopyButton text={ciSnippet} label="Copy GitHub Actions step" />
        <pre className="font-mono"><code>{ciSnippet}</code></pre>
      </div>

      <h2 className="watch-section-title">Replay demo</h2>
      <p className="watch-meta" style={{ maxWidth: 720 }}>
        Shows monitoring without waiting days for a real advisory. A replay starts from a recorded project state, then
        releases <strong>real recorded</strong> security evidence on a simulated clock; Warrant Watch detects it on its own.
        Everything it produces is labelled <span className="watch-sim-badge">{scenarios?.label || 'DEMO / REPLAY / SIMULATED EVENT'}</span>.
      </p>
      {error && <p className="watch-message">{error}</p>}
      <div style={{ display: 'grid', gap: 'var(--space-3)', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', marginTop: 'var(--space-3)' }}>
        {(scenarios?.scenarios || []).map(s => (
          <div key={s.id} className="card" style={{ padding: 'var(--space-4) var(--space-5)', display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}>
            <strong>{s.title}</strong>
            <p className="watch-meta" style={{ margin: 0 }}>{s.description}</p>
            <p className="watch-meta" style={{ margin: 0 }}>Project: {s.project.authenticity}</p>
            <p className="watch-meta" style={{ margin: 0 }}>
              Starts {formatDate(s.start)} · {s.steps.length} recorded evidence release{s.steps.length === 1 ? '' : 's'}
            </p>
            <button
              className="btn btn-accent btn-sm"
              style={{ alignSelf: 'flex-start', marginTop: 'auto' }}
              onClick={() => demo.mutate(s.id)}
              disabled={demo.isPending}
            >
              <FastForward size={14} aria-hidden /> Start replay
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}
