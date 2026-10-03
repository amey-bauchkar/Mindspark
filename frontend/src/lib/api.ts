import type { Report } from './types';

const API_BASE = '/api';

export async function getHealth(): Promise<{
  status: string;
  offline: boolean;
  epss_threshold: number;
  freshness_hours: number;
  llm_enabled: boolean;
}> {
  const res = await fetch(`${API_BASE}/health`);
  if (!res.ok) throw new Error(`Health check failed: ${res.status}`);
  return res.json();
}

export async function getSamples(): Promise<{
  samples: Array<{
    id: string;
    name: string;
    description: string;
    ecosystem: string;
    badge?: string;
  }>;
}> {
  const res = await fetch(`${API_BASE}/samples`);
  if (!res.ok) throw new Error(`Failed to load samples: ${res.status}`);
  return res.json();
}

export async function getMethodology(): Promise<Record<string, unknown>> {
  const res = await fetch(`${API_BASE}/methodology`);
  if (!res.ok) throw new Error(`Failed to load methodology: ${res.status}`);
  return res.json();
}

export async function analyzeFile(
  file: File | string,
  context: Record<string, unknown> = {}
): Promise<{ report_id: string }> {
  const formData = new FormData();
  if (typeof file === 'string') {
    formData.append('text', file);
  } else {
    formData.append('file', file);
  }
  formData.append('context', JSON.stringify(context));

  const res = await fetch(`${API_BASE}/analyze`, {
    method: 'POST',
    body: formData,
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Analysis request failed' }));
    throw new Error(err.detail || 'Analysis request failed');
  }
  return res.json();
}

export async function analyzeSample(
  sampleId: string,
  context: Record<string, unknown> = {}
): Promise<{ report_id: string }> {
  const formData = new FormData();
  formData.append('context', JSON.stringify(context));

  const res = await fetch(`${API_BASE}/analyze/sample/${sampleId}`, {
    method: 'POST',
    body: formData,
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Failed to start sample analysis' }));
    throw new Error(err.detail || 'Failed to start sample analysis');
  }
  return res.json();
}

export async function getReport(reportId: string, asOf?: string): Promise<Report> {
  const url = asOf
    ? `${API_BASE}/reports/${reportId}?as_of=${encodeURIComponent(asOf)}`
    : `${API_BASE}/reports/${reportId}`;
  const res = await fetch(url);
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Failed to fetch report' }));
    throw new Error(err.detail || 'Failed to fetch report');
  }
  return res.json();
}

export async function simulateFix(
  reportId: string,
  subject: string,
  toVersion: string
): Promise<unknown> {
  const res = await fetch(`${API_BASE}/reports/${reportId}/simulate-fix`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ subject, to_version: toVersion }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Simulate fix failed' }));
    throw new Error(err.detail || 'Simulate fix failed');
  }
  return res.json();
}

export async function verifyDemo(): Promise<unknown> {
  const res = await fetch(`${API_BASE}/verify-demo`, {
    method: 'POST',
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Verification demo failed' }));
    throw new Error(err.detail || 'Verification demo failed');
  }
  return res.json();
}

export function exportUrl(reportId: string, format: 'json' | 'md'): string {
  return `${API_BASE}/reports/${reportId}/export?format=${format}`;
}

export async function importReport(file: File): Promise<{ report_id: string }> {
  const formData = new FormData();
  formData.append('file', file);
  const res = await fetch(`${API_BASE}/reports/import`, {
    method: 'POST',
    body: formData,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Failed to import report' }));
    throw new Error(err.detail || 'Failed to import report');
  }
  return res.json();
}
