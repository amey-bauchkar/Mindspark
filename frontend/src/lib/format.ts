export function formatDate(dateStr: string | null | undefined): string {
  if (!dateStr) return '—';
  try {
    const d = new Date(dateStr);
    if (isNaN(d.getTime())) return String(dateStr);
    return d.toLocaleString(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  } catch {
    return String(dateStr);
  }
}

export function formatDateShort(dateStr: string | null | undefined): string {
  if (!dateStr) return '—';
  try {
    const d = new Date(dateStr);
    if (isNaN(d.getTime())) return String(dateStr);
    return d.toLocaleDateString(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    });
  } catch {
    return String(dateStr);
  }
}

const RECENT_REPORTS_KEY = 'warrant_recent_reports';

export interface RecentReportEntry {
  id: string;
  name: string;
  timestamp: string;
  summary: {
    incident: number;
    act_now: number;
    total_packages: number;
  };
}

export function getRecentReports(): RecentReportEntry[] {
  try {
    const raw = localStorage.getItem(RECENT_REPORTS_KEY);
    if (!raw) return [];
    return JSON.parse(raw);
  } catch {
    return [];
  }
}

export function saveRecentReport(entry: RecentReportEntry): void {
  try {
    const existing = getRecentReports().filter(r => r.id !== entry.id);
    const updated = [entry, ...existing].slice(0, 10);
    localStorage.setItem(RECENT_REPORTS_KEY, JSON.stringify(updated));
  } catch {
    // Ignore storage errors
  }
}
