import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Eye, FastForward, Pause, Play, RefreshCw, Square } from 'lucide-react';
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
          <div style={{ flex: 1, minWidth: 240 }}>
            <h2 className="watch-panel-title"><Eye size={16} aria-hidden /> Warrant Watch</h2>
            <p className="watch-meta" style={{ marginTop: 'var(--space-1)' }}>
              Keep checking OSV (incl. OpenSSF MAL-*), CISA KEV and EPSS for <em>new</em> security evidence affecting the
              exact dependency versions in this analysis — no re-upload, nothing installed or executed.
            </p>
            {!data.eligibility.eligible && (
              <p className="watch-meta" style={{ marginTop: 'var(--space-1)' }}>{data.eligibility.reason}</p>
            )}
          </div>
          {data.eligibility.eligible && (
            <button className="btn btn-primary" onClick={() => run.mutate('enable')} disabled={run.isPending}>
              <Eye size={16} aria-hidden /> Monitor this project
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
  const verdicts = Object.entries(w.current_verdicts)
    .filter(([v]) => v !== 'NO_KNOWN_FINDING')
    .map(([v, n]) => `${n} ${VERDICT_LABELS[v as Verdict] || v}`)
    .join(' · ');

  return (
    <section className="watch-panel" aria-label="Warrant Watch" aria-live="polite">
      <div className="watch-panel-row">
        <div style={{ flex: 1, minWidth: 260 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', flexWrap: 'wrap' }}>
            <span className={`watch-status watch-status-${w.status}`}>{STATUS_TEXT[w.status]}</span>
            {w.simulated && <span className="watch-sim-badge">{w.label}</span>}
            <h2 className="watch-panel-title" style={{ margin: 0 }}>{w.name}</h2>
          </div>
          <dl className="watch-stats">
            <div><dt>Dependencies monitored</dt><dd>{w.package_count}</dd></div>
            <div><dt>Last checked</dt><dd>{w.last_checked_at ? formatDate(w.last_checked_at) : 'Not yet'}</dd></div>
            <div>
              <dt>Next check</dt>
              <dd>
                {w.next_check_at ? formatDate(w.next_check_at) : '—'}
                {w.mode === 'replay'
                  ? ` (within ${every(w.interval_seconds)} of each recorded release)`
                  : ` (every ${every(w.interval_seconds)})`}
              </dd>
            </div>
            <div><dt>Evidence as of</dt><dd>{formatDate(w.evidence_as_of)}</dd></div>
            <div><dt>Security changes</dt><dd>{w.event_count}</dd></div>
            <div><dt>Last change detected</dt><dd>{w.last_change_at ? formatDate(w.last_change_at) : 'None yet'}</dd></div>
          </dl>
          <p className={`watch-check watch-check-${lc?.status || 'none'}`}>
            {lc ? lc.summary : 'Waiting for the first automatic check.'}
          </p>
          {verdicts && <p className="watch-meta">Current findings: {verdicts}</p>}
          <p className="watch-meta">Sources: {w.sources.join(' · ')}</p>
        </div>
        <div className="watch-actions">
          {w.status === 'active' && (
            <button className="btn btn-secondary btn-sm" onClick={() => run.mutate('check')} disabled={busy}>
              <RefreshCw size={14} aria-hidden /> Check now
            </button>
          )}
          {w.status === 'active' ? (
            <button className="btn btn-ghost btn-sm" onClick={() => run.mutate('pause')} disabled={busy}>
              <Pause size={14} aria-hidden /> Pause
            </button>
          ) : (
            <button className="btn btn-secondary btn-sm" onClick={() => run.mutate('resume')} disabled={busy}>
              <Play size={14} aria-hidden /> Resume
            </button>
          )}
          {w.status !== 'disabled' && (
            <button className="btn btn-ghost btn-sm" onClick={() => run.mutate('disable')} disabled={busy}>
              <Square size={14} aria-hidden /> Stop monitoring
            </button>
          )}
        </div>
      </div>

      {(w.failure_streak ?? 0) >= 3 && (
        <p className="watch-check watch-check-failed" role="alert">
          Monitoring has failed {w.failure_streak} checks in a row — this project is currently NOT being monitored.
          Check provider connectivity; notification channels were alerted.
        </p>
      )}

      <WatchManage watch={w} onChanged={refresh} />

      {w.replay && (
        <div className="watch-replay">
          <div style={{ flex: 1, minWidth: 240 }}>
            <strong>{w.replay.label}</strong> — {w.replay.title}
            <p className="watch-meta">
              Simulated clock: <span className="font-mono">{formatDate(w.replay.clock)}</span>
              {w.replay.next_release_at
                ? ` · next recorded evidence at ${formatDate(w.replay.next_release_at)} (${w.replay.remaining_steps} left)`
                : ' · replay complete'}
            </p>
            <p className="watch-meta">Project: {w.replay.project.authenticity}. Evidence: real recorded OSV / OpenSSF / KEV / EPSS data.</p>
          </div>
          {!w.replay.complete && (
            <button className="btn btn-accent btn-sm" onClick={() => run.mutate('advance')} disabled={busy || w.status !== 'active'}>
              <FastForward size={14} aria-hidden /> Release next recorded evidence
            </button>
          )}
        </div>
      )}

      {w.latest_report_id !== reportId && (
        <p className="watch-newer">
          Warrant Watch generated a newer analysis for this project.{' '}
          <Link to={`/report/${w.latest_report_id}`}>View updated analysis →</Link>
        </p>
      )}

      {message && <p className="watch-message">{message}</p>}

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
