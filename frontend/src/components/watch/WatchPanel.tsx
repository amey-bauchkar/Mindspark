import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { AlertOctagon, Eye, FastForward, Pause, Play, Radio, RefreshCw, Square } from 'lucide-react';
import {
  acknowledgeWatchEvents, advanceReplay, checkWatchNow, enableWatch, getWatchForReport, watchAction,
} from '../../lib/api';
import { formatDate } from '../../lib/format';
import type { Watch } from '../../lib/types';
import { VERDICT_LABELS, type Verdict } from '../../lib/types';
import { SecurityChangeCard } from './SecurityChangeCard';
import { WatchManage } from './WatchManage';

const STATUS_TEXT: Record<string, string> = {
  active: 'Monitoring Active',
  paused: 'Monitoring Paused',
  disabled: 'Monitoring Disabled',
};

function every(seconds: number): string {
  if (seconds < 120) return `${seconds} s`;
  if (seconds < 7200) return `${Math.round(seconds / 60)} min`;
  return `${Math.round(seconds / 3600)} h`;
}

export function WatchPanel({ reportId }: { reportId: string }) {
  const queryClient = useQueryClient();
  const [showAll, setShowAll] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  const { data, error } = useQuery({
    queryKey: ['watch-for-report', reportId],
    queryFn: () => getWatchForReport(reportId),
    refetchInterval: q => {
      const w = q.state.data?.watch;
      if (q.state.status === 'error') return 60_000;
      if (!w || w.status !== 'active') return false;
      return w.mode === 'replay' ? 3000 : 15000;
    },
  });

  const refresh = (w?: Watch) => {
    if (w) queryClient.setQueryData(['watch-for-report', reportId], { watch: w, eligibility: { eligible: true, reason: null } });
    queryClient.invalidateQueries({ queryKey: ['watch-for-report', reportId] });
    queryClient.invalidateQueries({ queryKey: ['watch-alerts'] });
  };

  const run = useMutation({
    mutationFn: async (action: 'enable' | 'check' | 'pause' | 'resume' | 'disable' | 'advance' | 'ack') => {
      const w = data?.watch;
      setMessage(null);
      switch (action) {
        case 'enable':
          return { watch: await enableWatch(reportId) };
        case 'check': {
          const r = await checkWatchNow(w!.id);
          setMessage(r.check.summary);
          return { watch: r.watch };
        }
        case 'advance': {
          const r = await advanceReplay(w!.id);
          setMessage(
            `Simulated clock moved to ${formatDate(r.clock)}; recorded evidence released: ${r.released.map(x => x.id).join(', ') || 'none'}. ` +
            'Warrant Watch will detect it on its next automatic check.',
          );
          return { watch: r.watch };
        }
        case 'ack':
          await acknowledgeWatchEvents(w!.id);
          return {};
        default:
          return { watch: await watchAction(w!.id, action) };
      }
    },
    onSuccess: r => refresh(r.watch),
    onError: (e: Error) => setMessage(e.message),
  });

  if (error || !data) return null;
  const w = data.watch;

  if (!w) {
    return (
      <section className="watch-panel" aria-label="Warrant Watch">
        <div className="watch-panel-row">
          <div className="watch-panel-info">
            <div className="watch-title-group">
              <Eye size={15} className="watch-eye-icon" aria-hidden />
              <h2 className="watch-panel-title">Warrant Watch</h2>
              <span className="watch-live-badge">Continuous Surveillance</span>
            </div>
            <p className="watch-meta">
              Continuous automated intelligence: alerts on new OSV, CISA KEV exploits, and OpenSSF malware disclosed for these exact package versions.
            </p>
            {!data.eligibility.eligible && (
              <p className="watch-meta watch-ineligible">{data.eligibility.reason}</p>
            )}
          </div>
          {data.eligibility.eligible && (
            <button className="btn btn-primary btn-sm watch-enable-btn" onClick={() => run.mutate('enable')} disabled={run.isPending}>
              <Eye size={13} aria-hidden /> Monitor this project
            </button>
          )}
        </div>
        {message && <p className="watch-message">{message}</p>}
      </section>
    );
  }

  const events = w.events || [];
  const shown = showAll ? events : events.slice(0, 3);
  const lc = w.last_check;
  const busy = run.isPending;
  const hasVerdicts = Object.keys(w.current_verdicts || {}).length > 0;

  return (
    <section className={`watch-panel-active status-${w.status}`} aria-label="Warrant Watch" aria-live="polite">
      {/* 1. Header Row */}
      <div className="watch-active-header">
        <div className="watch-identity-block">
          <span className={`watch-status-pill status-${w.status}`}>
            <span className="watch-pulse-indicator" />
            {STATUS_TEXT[w.status]}
          </span>
          {w.simulated && (
            <span className="watch-sim-tag">{w.label || 'Scenario Replay'}</span>
          )}
          <h2 className="watch-project-name">{w.name}</h2>
        </div>

        {/* Action Toolbar */}
        <div className="watch-toolbar">
          {w.status === 'active' && (
            <button
              className="watch-action-btn primary"
              onClick={() => run.mutate('check')}
              disabled={busy}
              title="Trigger an immediate vulnerability & malware intelligence query"
            >
              <RefreshCw size={12} className={busy ? 'spin' : ''} aria-hidden />
              <span>Check now</span>
            </button>
          )}
          {w.status === 'active' ? (
            <button
              className="watch-action-btn secondary"
              onClick={() => run.mutate('pause')}
              disabled={busy}
              title="Pause recurring monitoring scans"
            >
              <Pause size={12} aria-hidden />
              <span>Pause</span>
            </button>
          ) : (
            <button
              className="watch-action-btn secondary"
              onClick={() => run.mutate('resume')}
              disabled={busy}
              title="Resume scheduled surveillance"
            >
              <Play size={12} aria-hidden />
              <span>Resume</span>
            </button>
          )}
          {w.status !== 'disabled' && (
            <button
              className="watch-action-btn ghost"
              onClick={() => run.mutate('disable')}
              disabled={busy}
              title="Stop monitoring this project"
            >
              <Square size={12} aria-hidden />
              <span>Stop monitoring</span>
            </button>
          )}
        </div>
      </div>

      {/* 2. Telemetry Metric Grid */}
      <div className="watch-telemetry-grid">
        <div className="watch-telemetry-card">
          <div className="telemetry-label">Scope Monitored</div>
          <div className="telemetry-value">
            <span className="telemetry-number">{w.package_count}</span>
            <span className="telemetry-unit">packages</span>
          </div>
          <div className="telemetry-footer">
            {w.event_count === 0 ? 'Zero drift detected' : `${w.event_count} security change${w.event_count === 1 ? '' : 's'}`}
          </div>
        </div>

        <div className="watch-telemetry-card">
          <div className="telemetry-label">Surveillance Cadence</div>
          <div className="telemetry-value">
            <span className="telemetry-highlight">
              {w.mode === 'replay' ? 'Scenario Driven' : `Every ${every(w.interval_seconds)}`}
            </span>
          </div>
          <div className="telemetry-footer">
            Next: {w.next_check_at ? formatDate(w.next_check_at) : 'On event release'}
          </div>
        </div>

        <div className="watch-telemetry-card">
          <div className="telemetry-label">Last Audit</div>
          <div className="telemetry-value">
            <span className="telemetry-highlight">
              {w.last_checked_at ? formatDate(w.last_checked_at) : 'Initial scan pending'}
            </span>
          </div>
          <div className="telemetry-footer">
            Last change: {w.last_change_at ? formatDate(w.last_change_at) : 'None recorded'}
          </div>
        </div>

        <div className="watch-telemetry-card">
          <div className="telemetry-label">Evidence Feeds</div>
          <div className="telemetry-value">
            <span className="telemetry-feeds">OSV · CISA KEV · EPSS</span>
          </div>
          <div className="telemetry-footer">
            Snapshot: {formatDate(w.evidence_as_of)}
          </div>
        </div>
      </div>

      {/* 3. Live Status & Baseline Findings Strip */}
      <div className="watch-status-strip">
        <div className="status-strip-left">
          <Radio size={13} className="status-strip-icon" aria-hidden />
          <span className="status-strip-msg">
            {lc ? lc.summary : 'Continuous feed listener active. Waiting for the first automated scan cycle.'}
          </span>
        </div>
        {hasVerdicts && (
          <div className="status-strip-findings">
            <span className="findings-label">Baseline Findings:</span>
            {Object.entries(w.current_verdicts)
              .filter(([v]) => v !== 'NO_KNOWN_FINDING')
              .map(([v, n]) => (
                <span key={v} className={`baseline-verdict-pill verdict-${v.toLowerCase()}`}>
                  {n} {VERDICT_LABELS[v as Verdict] || v}
                </span>
              ))}
          </div>
        )}
      </div>

      {/* 4. Failure Alert */}
      {(w.failure_streak ?? 0) >= 3 && (
        <div className="watch-alert-banner" role="alert">
          <AlertOctagon size={15} style={{ flexShrink: 0 }} />
          <span>
            Monitoring has failed {w.failure_streak} checks in a row — this project is currently NOT being monitored.
            Check provider connectivity; notification channels were alerted.
          </span>
        </div>
      )}

      {/* 5. Project Configuration Accordion */}
      <WatchManage watch={w} onChanged={refresh} />

      {/* 6. Replay Mode Banner (if simulated) */}
      {w.replay && (
        <div className="watch-replay-banner">
          <div className="replay-info">
            <div className="replay-badge">REPLAY CONTROLLER</div>
            <div className="replay-title">
              <strong>{w.replay.label}</strong> — {w.replay.title}
            </div>
            <div className="replay-meta">
              Simulated clock: <span className="font-mono">{formatDate(w.replay.clock)}</span>
              {w.replay.next_release_at
                ? ` · next recorded evidence at ${formatDate(w.replay.next_release_at)} (${w.replay.remaining_steps} left)`
                : ' · replay complete'}
            </div>
          </div>
          {!w.replay.complete && (
            <button
              className="btn btn-accent btn-sm"
              onClick={() => run.mutate('advance')}
              disabled={busy || w.status !== 'active'}
            >
              <FastForward size={13} aria-hidden /> Release next recorded evidence
            </button>
          )}
        </div>
      )}

      {/* 7. Newer Analysis Banner */}
      {w.latest_report_id !== reportId && (
        <div className="watch-update-banner">
          <span>Warrant Watch generated an updated analysis for this project.</span>
          <Link to={`/report/${w.latest_report_id}`} className="watch-update-link">
            View updated analysis →
          </Link>
        </div>
      )}

      {message && <div className="watch-feedback-toast">{message}</div>}

      {/* 8. Security Events Feed */}
      {events.length > 0 && (
        <div style={{ marginTop: 'var(--space-4)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginBottom: 'var(--space-2)' }}>
            <h3 className="watch-label" style={{ margin: 0 }}>Security changes ({events.length})</h3>
            {w.unacknowledged_count > 0 && (
              <button className="btn btn-ghost btn-sm" onClick={() => run.mutate('ack')} disabled={busy}>
                Mark {w.unacknowledged_count} as seen
              </button>
            )}
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
            {shown.map(ev => <SecurityChangeCard key={ev.id} event={ev} currentReportId={reportId} onTriaged={() => refresh()} />)}
          </div>
          {events.length > 3 && (
            <button className="btn btn-ghost btn-sm" style={{ marginTop: 'var(--space-2)' }} onClick={() => setShowAll(x => !x)}>
              {showAll ? 'Show fewer' : `Show all ${events.length} changes`}
            </button>
          )}
        </div>
      )}
    </section>
  );
}

export default WatchPanel;
