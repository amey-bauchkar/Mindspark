import type { RecentReport } from './types';
export type { RecentReport };

const RECENT_REPORTS_KEY = 'warrant_recent_reports';
const MAX_RECENT = 10;

export function formatDate(isoOrDate?: string | Date | null): string {
  if (!isoOrDate) return '—';
  try {
    const d = typeof isoOrDate === 'string' ? new Date(isoOrDate) : isoOrDate;
    if (isNaN(d.getTime())) return String(isoOrDate);
    return new Intl.DateTimeFormat('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      timeZoneName: 'short',
    }).format(d);
  } catch {
    return String(isoOrDate);
  }
}

export function formatDateShort(isoOrDate?: string | Date | null): string {
  if (!isoOrDate) return '—';
  try {
    const d = typeof isoOrDate === 'string' ? new Date(isoOrDate) : isoOrDate;
    if (isNaN(d.getTime())) return String(isoOrDate);
    return new Intl.DateTimeFormat('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
    }).format(d);
  } catch {
    return String(isoOrDate);
  }
}

export function getRecentReports(): RecentReport[] {
  try {
    const raw = localStorage.getItem(RECENT_REPORTS_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed;
  } catch {
    return [];
  }
}

export function saveRecentReport(report: RecentReport): void {
  try {
    const current = getRecentReports();
    const filtered = current.filter(r => r.id !== report.id);
    const updated = [report, ...filtered].slice(0, MAX_RECENT);
    localStorage.setItem(RECENT_REPORTS_KEY, JSON.stringify(updated));
  } catch {
    // Ignore localStorage errors (e.g. quota, private browsing)
  }
}

/**
 * Only absolute http(s) links from provider data may become clickable (blocks javascript:,
 * data: and other schemes even if a malformed advisory record slips through the backend).
 */
export function safeHref(url?: string | null): string | undefined {
  if (!url || typeof url !== 'string') return undefined;
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'https:' || parsed.protocol === 'http:' ? parsed.href : undefined;
  } catch {
    return undefined;
  }
}
