import React, { useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { Bell, FileUp, Settings2, Trash2 } from 'lucide-react';
import {
  addWatchChannel, deleteWatch, removeWatchChannel, testWatchChannel, updateWatchSettings, uploadWatchLockfile,
} from '../../lib/api';
import { formatDate } from '../../lib/format';
import type { Watch, WatchChannelKind } from '../../lib/types';

const INTERVALS: { label: string; minutes: number | null }[] = [
  { label: 'Every 15 min', minutes: 15 },
  { label: 'Every 30 min', minutes: 30 },
  { label: 'Hourly (default)', minutes: null },
  { label: 'Every 4 h', minutes: 240 },
  { label: 'Daily', minutes: 1440 },
];

const KIND_HINT: Record<WatchChannelKind, string> = {
  slack: 'https://hooks.slack.com/services/…',
  teams: 'https://<tenant>.webhook.office.com/…',
  webhook: 'https://your-service.example.com/warrant',
};

/** Project management for a monitored project: notifications, lockfile updates, cadence, deletion. */
export function WatchManage({ watch: w, onChanged }: { watch: Watch; onChanged: (w?: Watch) => void }) {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const fileRef = useRef<HTMLInputElement>(null);
  const [kind, setKind] = useState<WatchChannelKind>('slack');
  const [url, setUrl] = useState('');
  const [minPriority, setMinPriority] = useState('medium');
  const [message, setMessage] = useState<{ text: string; error?: boolean } | null>(null);
  const [secret, setSecret] = useState<string | null>(null);
  const live = w.mode === 'live';

  const act = useMutation({
    mutationFn: async (fn: () => Promise<string | void>) => fn(),
    onSuccess: text => {
      if (text) setMessage({ text });
      onChanged();
    },
    onError: (e: Error) => setMessage({ text: e.message, error: true }),
  });

  const addChannel = (e: React.FormEvent) => {
    e.preventDefault();
    act.mutate(async () => {
      const ch = await addWatchChannel(w.id, { kind, url, min_priority: minPriority });
      setUrl('');
      setSecret(ch.signing_secret ?? null);
      return `${kind === 'webhook' ? 'Webhook' : kind === 'slack' ? 'Slack' : 'Teams'} channel added.`;
    });
  };

  const channels = w.channels ?? [];
  const deliveries = w.deliveries ?? [];
  const failedDeliveries = deliveries.filter(d => d.status === 'failed').length;
  const intervalValue = w.interval_minutes ?? null;

  return (
    <details className="watch-manage">
      <summary><Settings2 size={14} aria-hidden /> Manage project — notifications, lockfile, schedule</summary>

      {message && (
        <p className={message.error ? 'watch-check watch-check-failed' : 'watch-message'} role="status">{message.text}</p>
      )}

      <section className="watch-manage-section" aria-labelledby={`notify-${w.id}`}>
        <h3 id={`notify-${w.id}`} className="watch-label"><Bell size={12} aria-hidden /> Notifications</h3>
        {channels.length === 0 ? (
          <p className="watch-meta">
            No channels yet — security changes only appear inside Warrant. Add Slack, Microsoft Teams or a signed
            webhook (Jira, PagerDuty, your SIEM) so the team is told without opening the app.
          </p>
        ) : (
          <ul className="watch-channel-list">
            {channels.map(c => (
              <li key={c.id}>
                <span className="watch-tag">{c.kind}</span>
                <span className="font-mono watch-channel-url">{c.url}</span>
                <span className="watch-meta" style={{ margin: 0 }}>
                  {c.min_priority}+ {c.signed ? '· signed' : ''} {c.source === 'global' ? '· server-wide' : ''}
                </span>
                {c.source === 'project' && (
                  <span style={{ display: 'inline-flex', gap: 4, marginLeft: 'auto' }}>
                    <button type="button" className="btn btn-ghost btn-sm" disabled={act.isPending}
                            onClick={() => act.mutate(async () => {
                              const r = await testWatchChannel(w.id, c.id);
                              return r.delivered ? 'Test message delivered.' : `Test failed: ${r.error}`;
                            })}>Send test</button>
                    <button type="button" className="btn btn-ghost btn-sm" disabled={act.isPending}
                            aria-label={`Remove ${c.kind} channel`}
                            onClick={() => act.mutate(async () => { await removeWatchChannel(w.id, c.id); return 'Channel removed.'; })}>
                      Remove
                    </button>
                  </span>
                )}
              </li>
            ))}
          </ul>
        )}
        {secret && (
          <p className="watch-newer" role="alert">
            Signing secret (shown once — store it in the receiving service to verify <code>X-Warrant-Signature</code>):{' '}
            <code className="font-mono" style={{ wordBreak: 'break-all' }}>{secret}</code>
          </p>
        )}
        <form className="watch-channel-form" onSubmit={addChannel}>
          <select className="input" value={kind} onChange={e => setKind(e.target.value as WatchChannelKind)} aria-label="Channel type">
            <option value="slack">Slack</option>
            <option value="teams">Microsoft Teams</option>
            <option value="webhook">Webhook (signed JSON)</option>
          </select>
          <input className="input" type="url" required placeholder={KIND_HINT[kind]} value={url}
                 onChange={e => setUrl(e.target.value)} aria-label="Webhook URL" />
          <select className="input" value={minPriority} onChange={e => setMinPriority(e.target.value)} aria-label="Minimum priority">
            <option value="high">High only (INCIDENT, ACT NOW)</option>
            <option value="medium">Medium and above</option>
            <option value="low">Low and above</option>
            <option value="info">Everything (incl. resolved)</option>
          </select>
          <button className="btn btn-secondary btn-sm" type="submit" disabled={!url || act.isPending}>Add channel</button>
        </form>
        {deliveries.length > 0 && (
          <p className="watch-meta">
            Recent deliveries: {deliveries.filter(d => d.status === 'sent').length} sent
            {deliveries.some(d => d.status === 'pending') && `, ${deliveries.filter(d => d.status === 'pending').length} retrying`}
            {failedDeliveries > 0 && `, ${failedDeliveries} failed (${deliveries.find(d => d.status === 'failed')?.last_error})`}.
          </p>
        )}
      </section>

      {live && (
        <section className="watch-manage-section">
          <h3 className="watch-label"><FileUp size={12} aria-hidden /> Dependencies</h3>
          <p className="watch-meta">
            Monitoring {w.package_count} package versions
            {w.lockfile_updated_at ? ` · lockfile updated ${formatDate(w.lockfile_updated_at)}` : ' from the original analysis'}.
            Upload the current package-lock.json when dependencies change (or let CI do it — see the Watch page).
          </p>
          <input ref={fileRef} type="file" accept=".json,application/json" hidden
                 onChange={e => {
                   const f = e.target.files?.[0];
                   e.target.value = '';
                   if (!f) return;
                   act.mutate(async () => {
                     const r = await uploadWatchLockfile(w.id, f);
                     onChanged(r.watch);
                     queryClient.invalidateQueries({ queryKey: ['watch-alerts'] });
                     return r.check.summary;
                   });
                 }} />
          <button type="button" className="btn btn-secondary btn-sm" disabled={act.isPending}
                  onClick={() => fileRef.current?.click()}>
            {act.isPending ? 'Working…' : 'Update lockfile'}
          </button>
        </section>
      )}

      {live && (
        <section className="watch-manage-section">
          <h3 className="watch-label">Check frequency</h3>
          <select className="input" style={{ maxWidth: 220 }} aria-label="Check frequency"
                  value={String(intervalValue)}
                  disabled={act.isPending}
                  onChange={e => {
                    const minutes = e.target.value === 'null' ? null : Number(e.target.value);
                    act.mutate(async () => {
                      onChanged(await updateWatchSettings(w.id, { interval_minutes: minutes }));
                      return 'Check frequency updated.';
                    });
                  }}>
            {INTERVALS.map(i => <option key={String(i.minutes)} value={String(i.minutes)}>{i.label}</option>)}
            {intervalValue !== null && !INTERVALS.some(i => i.minutes === intervalValue) && (
              <option value={String(intervalValue)}>Every {intervalValue} min</option>
            )}
          </select>
        </section>
      )}

      <section className="watch-manage-section">
        <h3 className="watch-label">Danger zone</h3>
        <button type="button" className="btn btn-ghost btn-sm" style={{ color: 'var(--verdict-incident-fg)' }}
                disabled={act.isPending}
                onClick={() => {
                  if (!window.confirm(`Delete "${w.name}"? Its monitoring history, alerts and notification channels are removed. Reports return to normal 24 h retention.`)) return;
                  act.mutate(async () => {
                    await deleteWatch(w.id);
                    queryClient.invalidateQueries({ queryKey: ['watches'] });
                    queryClient.invalidateQueries({ queryKey: ['watch-alerts'] });
                    navigate('/watch');
                  });
                }}>
          <Trash2 size={14} aria-hidden /> Delete project
        </button>
      </section>
    </details>
  );
}

export default WatchManage;
