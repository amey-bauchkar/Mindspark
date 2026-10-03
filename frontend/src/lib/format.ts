export interface RecentReport {
  id: string;
  name: string;
  timestamp: string;
  summary: {
    incident: number;
    act_now: number;
    total_packages: number;
  };
}

const RECENT_REPORTS_KEY = 'warrant_recent_reports';
const MAX_RECENT_REPORTS = 10;

export function formatDate(dateStr?: string | Date | null): string {
  if (!dateStr) return 'N/A';
  try {
    const d = typeof dateStr === 'string' ? new Date(dateStr) : dateStr;
    if (isNaN(d.getTime())) return String(dateStr);
    return d.toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      timeZoneName: 'short',
    });
  } catch {
    return String(dateStr);
  }
}

export function formatDateShort(dateStr?: string | Date | null): string {
  if (!dateStr) return 'N/A';
  try {
    const d = typeof dateStr === 'string' ? new Date(dateStr) : dateStr;
    if (isNaN(d.getTime())) return String(dateStr);
    return d.toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
    });
  } catch {
    return String(dateStr);
  }
}

export function getRecentReports(): RecentReport[] {
  try {
    const raw = localStorage.getItem(RECENT_REPORTS_KEY);
    if (!raw) return [];
    return JSON.parse(raw);
  } catch {
    return [];
  }
}

export function saveRecentReport(item: RecentReport): void {
  try {
    const existing = getRecentReports();
    const filtered = existing.filter(r => r.id !== item.id);
    const updated = [item, ...filtered].slice(0, MAX_RECENT_REPORTS);
    localStorage.setItem(RECENT_REPORTS_KEY, JSON.stringify(updated));
  } catch {
    // LocalStorage quota or access error in iframe
  }
}
