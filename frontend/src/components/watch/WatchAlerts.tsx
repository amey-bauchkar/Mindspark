import React from 'react';
import { Link } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { BellRing, X } from 'lucide-react';
import { acknowledgeWatchEvents, getWatchAlerts } from '../../lib/api';
import { VERDICT_LABELS, type Verdict } from '../../lib/types';

/** In-app notification: unacknowledged security-change events from any monitored project. */
export function WatchAlerts() {
  const queryClient = useQueryClient();
  const { data } = useQuery({
    queryKey: ['watch-alerts'],
    queryFn: getWatchAlerts,
    refetchInterval: 10_000,
    retry: false,
  });
  const dismiss = useMutation({
    mutationFn: (ids: { watchId: string; eventIds: string[] }) => acknowledgeWatchEvents(ids.watchId, ids.eventIds),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['watch-alerts'] });
      queryClient.invalidateQueries({ queryKey: ['watch-for-report'] });
    },
  });

  const ev = data?.events?.[0];
  if (!data || !ev) return null;
  const more = data.unacknowledged - 1;
  const label = (v: string) => VERDICT_LABELS[v as Verdict] || v;

  return (
    <div className={`watch-alert watch-alert-${ev.priority}`} role="alert">
      <div className="container watch-alert-inner">
        <BellRing size={16} aria-hidden style={{ flexShrink: 0 }} />
        <span className="watch-alert-text">
          <strong>SECURITY CHANGE DETECTED</strong>
          {ev.simulated && <span className="watch-sim-badge" style={{ marginLeft: 8 }}>{ev.label}</span>}
          {' · '}
          <code className="font-mono">{ev.package}@{ev.version}</code>
          {' · '}
          {label(ev.previous.verdict)} → <strong>{label(ev.current.verdict)}</strong>
          <span className="hide-mobile">{' · '}{ev.project}</span>
          {more > 0 && ` · +${more} more`}
        </span>
        <Link to={`/report/${ev.report_id}`} className="btn btn-primary btn-sm">View updated analysis</Link>
        <button
          className="btn btn-ghost btn-sm btn-icon"
          aria-label="Dismiss notification"
          onClick={() => dismiss.mutate({ watchId: ev.watch_id, eventIds: [ev.id] })}
        >
          <X size={14} aria-hidden />
        </button>
      </div>
    </div>
  );
}

export default WatchAlerts;
