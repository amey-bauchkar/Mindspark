import type { Report, SampleItem, MethodologyData, Watch, WatchCheck, WatchEvent, WatchScenario } from './types';
import { getCloudReportById } from './supabaseClient';

const API_BASE = '/api';

export interface HealthResponse {
  status: string;
  offline: boolean;
  epss_threshold: number;
  freshness_hours: number;
  llm_enabled: boolean;
}

export interface SamplesResponse {
  samples: SampleItem[];
}

export interface AnalyzeResponse {
  report_id: string;
}

export async function getHealth(): Promise<HealthResponse> {
  const res = await fetch(`${API_BASE}/health`);
  if (!res.ok) {
    throw new Error(`Health check failed: ${res.statusText}`);
  }
  return res.json();
}

export async function getSamples(): Promise<SamplesResponse> {
  const res = await fetch(`${API_BASE}/samples`);
  if (!res.ok) {
    throw new Error(`Failed to fetch samples: ${res.statusText}`);
  }
  return res.json();
}

export async function analyzeFile(
  fileOrText: File | string,
  context: Record<string, unknown> = {},
): Promise<AnalyzeResponse> {
  const formData = new FormData();
  if (typeof fileOrText === 'string') {
    formData.append('text', fileOrText);
  } else {
    formData.append('file', fileOrText);
  }
  formData.append('context', JSON.stringify(context));

  const res = await fetch(`${API_BASE}/analyze`, {
    method: 'POST',
    body: formData,
  });

  if (!res.ok) {
    const errorText = await res.text();
    let message = res.statusText;
    try {
      const err = JSON.parse(errorText);
      message = err.detail || message;
    } catch {
      if (errorText) message = errorText;
    }
    throw new Error(message || 'Failed to analyze file');
  }

  return res.json();
}

export async function analyzeSample(
  sampleId: string,
  context: Record<string, unknown> = {},
): Promise<AnalyzeResponse> {
  const formData = new FormData();
  formData.append('context', JSON.stringify(context));

  const res = await fetch(`${API_BASE}/analyze/sample/${encodeURIComponent(sampleId)}`, {
    method: 'POST',
    body: formData,
  });

  if (!res.ok) {
    const errorText = await res.text();
    let message = res.statusText;
    try {
      const err = JSON.parse(errorText);
      message = err.detail || message;
    } catch {
      if (errorText) message = errorText;
    }
    throw new Error(message || 'Failed to analyze sample');
  }

  return res.json();
}

export class ReportRequestError extends Error {
  constructor(message: string, public status: number | null) {
    super(message);
    this.name = 'ReportRequestError';
  }
}

export async function getReport(reportId: string, asOf?: string): Promise<Report> {
  const url = asOf
    ? `${API_BASE}/reports/${encodeURIComponent(reportId)}?as_of=${encodeURIComponent(asOf)}`
    : `${API_BASE}/reports/${encodeURIComponent(reportId)}`;

  let status: number | null = null;
  try {
    const res = await fetch(url);
    if (res.ok) {
      return await res.json();
    }
    status = res.status;
    // Anything other than "not found" is a real answer (bad as-of, rate limit, server error):
    // surface it rather than silently showing a different copy of the report.
    if (status !== 404) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      throw new ReportRequestError(String(err.detail || `Request failed (${status})`), status);
    }
  } catch (e) {
    if (e instanceof ReportRequestError) throw e;
    // Network error / backend offline: fall through to the cloud copy
  }

  // A cloud copy cannot answer an as-of question, so never substitute it for one.
  if (!asOf) {
    try {
      const cloudReport = await getCloudReportById(reportId);
      if (cloudReport) return cloudReport;
    } catch {
      // Cloud lookup failed
    }
  }

  throw new ReportRequestError('Report not found locally or in cloud storage', status);
}

export function exportUrl(reportId: string, format: 'json' | 'md' | 'markdown' | 'html' = 'json'): string {
  return `${API_BASE}/reports/${encodeURIComponent(reportId)}/export?format=${format}`;
}

export async function verifyDemo(): Promise<Record<string, unknown>> {
  const res = await fetch(`${API_BASE}/verify-demo`, {
    method: 'POST',
  });
  if (!res.ok) {
    throw new Error(`Failed to run verify-demo: ${res.statusText}`);
  }
  return res.json();
}

export async function simulateFix(
  reportId: string,
  subject: string,
  toVersion: string,
): Promise<Record<string, unknown>> {
  const res = await fetch(`${API_BASE}/reports/${encodeURIComponent(reportId)}/simulate-fix`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      subject,
      to_version: toVersion,
    }),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: `Failed to simulate fix: ${res.statusText}` }));
    throw new Error(err.detail || 'Failed to simulate fix');
  }
  return res.json();
}

export async function getMethodology(): Promise<MethodologyData> {
  const res = await fetch(`${API_BASE}/methodology`);
  if (!res.ok) {
    throw new Error(`Failed to fetch methodology: ${res.statusText}`);
  }
  return res.json();
}

export async function importReport(file: File): Promise<{ report_id: string }> {
  const formData = new FormData();
  formData.append('file', file);

  const res = await fetch(`${API_BASE}/reports/import`, {
    method: 'POST',
    body: formData,
  });

  if (!res.ok) {
    const errorText = await res.text();
    let message = res.statusText;
    try {
      const err = JSON.parse(errorText);
      message = err.detail || message;
    } catch {
      if (errorText) message = errorText;
    }
    throw new Error(message || 'Failed to import report');
  }

  return res.json();
}

// ─── Warrant Watch ──────────────────────────────────────────────────────────

async function watchRequest<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}/watch${path}`, {
    ...init,
    headers: init?.body ? { 'Content-Type': 'application/json' } : undefined,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || 'Warrant Watch request failed');
  }
  return res.json();
}

export function getWatches(): Promise<{ watches: Watch[]; config: Record<string, unknown> }> {
  return watchRequest('');
}

export function getWatch(watchId: string): Promise<Watch> {
  return watchRequest(`/${encodeURIComponent(watchId)}`);
}

export function getWatchForReport(
  reportId: string,
): Promise<{ watch: Watch | null; eligibility: { eligible: boolean; reason: string | null } }> {
  return watchRequest(`/by-report/${encodeURIComponent(reportId)}`);
}

export function enableWatch(reportId: string): Promise<Watch> {
  return watchRequest('', { method: 'POST', body: JSON.stringify({ report_id: reportId }) });
}

export function watchAction(watchId: string, action: 'pause' | 'resume' | 'disable'): Promise<Watch> {
  return watchRequest(`/${encodeURIComponent(watchId)}/${action}`, { method: 'POST' });
}

export function checkWatchNow(watchId: string): Promise<{ check: WatchCheck; events: WatchEvent[]; watch: Watch }> {
  return watchRequest(`/${encodeURIComponent(watchId)}/check`, { method: 'POST' });
}

export function advanceReplay(
  watchId: string,
): Promise<{ label: string; clock: string; released: { id: string; change: string }[]; watch: Watch }> {
  return watchRequest(`/${encodeURIComponent(watchId)}/replay/advance`, { method: 'POST' });
}

export function acknowledgeWatchEvents(watchId: string, eventIds?: string[]): Promise<{ acknowledged: number }> {
  return watchRequest(`/${encodeURIComponent(watchId)}/events/ack`, {
    method: 'POST',
    body: JSON.stringify(eventIds ? { event_ids: eventIds } : {}),
  });
}

export function getWatchAlerts(): Promise<{ unacknowledged: number; events: WatchEvent[] }> {
  return watchRequest('/alerts');
}

export function getWatchScenarios(): Promise<{ label: string; scenarios: WatchScenario[] }> {
  return watchRequest('/scenarios');
}

export function startWatchDemo(scenarioId: string): Promise<Watch> {
  return watchRequest('/demo', { method: 'POST', body: JSON.stringify({ scenario_id: scenarioId }) });
}
