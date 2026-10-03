import React from 'react';
import { Link } from 'react-router-dom';
import { ArrowRight, BellRing, ExternalLink } from 'lucide-react';
import type { WatchEvent } from '../../lib/types';
import { formatDate, safeHref } from '../../lib/format';
import { VerdictChip } from '../ui/VerdictChip';
import { CopyButton } from '../ui/CopyButton';

const PRIORITY_LABEL: Record<string, string> = {
  high: 'HIGH PRIORITY',
  medium: 'MEDIUM',
  low: 'LOW',
  info: 'INFO',
};

const CHANGE_LABEL: Record<string, string> = {
  added: 'new',
  withdrawn: 'withdrawn',
  added_withdrawn: 'withdrawn',
  reinstated: 'reinstated',
  removed: 'no longer reported',
  modified: 'corrected',
  threshold_crossed: 'crossed threshold',
  threshold_dropped: 'below threshold',
};

const SOURCE_LABEL: Record<string, string> = { osv: 'OSV', kev: 'CISA KEV', epss: 'EPSS' };

export function verdictColor(verdict: string): string {
  const key: Record<string, string> = {
    INCIDENT: 'incident', ACT_NOW: 'act-now', UPGRADE: 'upgrade', MONITOR: 'monitor',
    REVIEW: 'review', CANNOT_ASSESS: 'cannot', NO_KNOWN_FINDING: 'nkf',
  };
  return `var(--verdict-${key[verdict] || 'nkf'}-fg)`;
}

interface SecurityChangeCardProps {
  event: WatchEvent;
  currentReportId?: string;
}

export function SecurityChangeCard({ event: ev, currentReportId }: SecurityChangeCardProps) {
  const fixCmd = ev.response.steps.find(s => s.command)?.command;
  const viewing = currentReportId === ev.report_id;

  return (
    <article
      className={`watch-event watch-event-${ev.priority}`}
      style={{ borderLeftColor: verdictColor(ev.current.verdict) }}
      aria-label={`Security change for ${ev.package}@${ev.version}`}
    >
      <header className="watch-event-head">
        <span className="watch-event-title">
          <BellRing size={14} aria-hidden /> {ev.title}
        </span>
        <span className={`watch-priority watch-priority-${ev.priority}`}>{PRIORITY_LABEL[ev.priority] || ev.priority}</span>
        {ev.simulated && <span className="watch-sim-badge">{ev.label}</span>}
        {ev.check_status === 'partial' && (
          <span className="watch-priority watch-priority-medium" title="Some providers could not be checked">
            PARTIAL CHECK
          </span>
        )}
      </header>

      <code className="purl" style={{ fontWeight: 700, fontSize: 'var(--text-sm)' }}>
        {ev.package}@{ev.version}
      </code>
      <span style={{ fontSize: 'var(--text-xs)', color: 'var(--color-muted)', marginLeft: 'var(--space-2)' }}>
        {ev.project} · {ev.exposure.scope || 'unknown'} scope
      </span>

      <div className="watch-transition">
        <div>
          <div className="watch-label">Previous</div>
          <VerdictChip verdict={ev.previous.verdict} />
          <div className="watch-sub">{ev.previous.urgency}</div>
        </div>
        <ArrowRight size={18} aria-hidden style={{ color: 'var(--color-muted)', flexShrink: 0 }} />
        <div>
          <div className="watch-label">Current</div>
          <VerdictChip verdict={ev.current.verdict} />
          <div className="watch-sub">
            {ev.current.urgency}
            {ev.current.rules.length > 0 && ` · ${ev.current.rules.join(', ')}`}
          </div>
        </div>
      </div>

      <div className="watch-label">What changed</div>
      <ul className="watch-reasons">
        {ev.reason_lines.map((line, i) => <li key={i}>{line}</li>)}
      </ul>

      {ev.changed_evidence.length > 0 && (
        <div className="watch-evidence">
          {ev.changed_evidence.map(e => (
            <div key={`${e.subject}-${e.key}`} className="watch-evidence-row">
              <span className="font-mono" style={{ fontWeight: 600 }}>{e.id || e.key}</span>
              <span className="watch-tag">{CHANGE_LABEL[e.change] || e.change}</span>
              <span>{SOURCE_LABEL[e.source || ''] || e.source}{e.origin ? ` · ${e.origin}` : ''}</span>
              {e.published_at && <span>published {formatDate(e.published_at)}</span>}
              {e.observed_at && <span>observed {formatDate(e.observed_at)}</span>}
              {safeHref(e.url) && (
                <a href={safeHref(e.url)} target="_blank" rel="noopener noreferrer" aria-label={`Open source record ${e.id}`}>
                  <ExternalLink size={12} aria-hidden />
                </a>
              )}
            </div>
          ))}
        </div>
      )}

      {ev.exposure.paths.length > 0 && (
        <p className="watch-meta">
          <strong>Path:</strong> {ev.exposure.paths[0].join(' → ')}
          {ev.exposure.paths.length > 1 && ` (+${ev.exposure.paths.length - 1} more)`}
        </p>
      )}
      <p className="watch-meta" style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', flexWrap: 'wrap' }}>
        <strong>Response:</strong> {ev.response.class.replace('_', ' ')}
        {ev.response.fixed_version && ` → ${ev.response.fixed_version}`}
        {fixCmd && <CopyButton text={fixCmd} label="Copy fix command" />}
      </p>
      <p className="watch-meta">
        Detected {formatDate(ev.detected_at)} · Evidence as of {formatDate(ev.evidence_as_of)}
      </p>

      <div style={{ marginTop: 'var(--space-3)' }}>
        {viewing ? (
          <span className="watch-meta">You are viewing this updated analysis.</span>
        ) : (
          <Link to={`/report/${ev.report_id}`} className="btn btn-primary btn-sm">
            View updated analysis <ArrowRight size={14} aria-hidden />
          </Link>
        )}
      </div>
    </article>
  );
}

export default SecurityChangeCard;
