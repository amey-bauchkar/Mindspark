import type { Report } from './types';

const API_BASE = 'http://localhost:8000/api';

export async function getHealth(): Promise<{ status: string; offline: boolean; epss_threshold: number; freshness_hours: number; llm_enabled: boolean }> {
  const res = await fetch(`${API_BASE}/health`);
  if (!res.ok) throw new Error('Health check failed');
  return res.json();
}

export async function getReport(id: string, asOf?: string): Promise<Report> {
  const url = new URL(`${API_BASE}/reports/${id}`);
  if (asOf) {
    url.searchParams.set('as_of', asOf);
  }
  const res = await fetch(url.toString());
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(errorData.detail || 'Failed to fetch report');
  }
  return res.json();
}

export function exportUrl(reportId: string, format: 'json' | 'markdown' | 'md' | 'html'): string {
  return `${API_BASE}/reports/${reportId}/export?format=${format}`;
}

export async function analyzeFile(
  file: File,
  context?: Record<string, any>
): Promise<{ report_id: string }> {
  const formData = new FormData();
  formData.append('file', file);
  if (context) {
    formData.append('context', JSON.stringify(context));
  }

  const res = await fetch(`${API_BASE}/analyze`, {
    method: 'POST',
    body: formData,
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || 'Analysis initiation failed');
  }
  return res.json();
}

export async function analyzeSample(
  sampleId: string,
  context?: Record<string, any>
): Promise<{ report_id: string }> {
  const res = await fetch(`${API_BASE}/analyze/sample`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ sample_id: sampleId, context: context || {} }),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || 'Sample analysis failed');
  }
  return res.json();
}

export async function getSamples(): Promise<{ samples: Array<{ id: string; name: string; description: string; ecosystem: string; badge?: string }> }> {
  const res = await fetch(`${API_BASE}/samples`);
  if (!res.ok) throw new Error('Failed to fetch samples');
  return res.json();
}

export async function getMethodology(): Promise<Record<string, any>> {
  const res = await fetch(`${API_BASE}/methodology`);
  if (!res.ok) throw new Error('Failed to fetch methodology');
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
    const errorData = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(errorData.detail || 'Failed to import report');
  }

  return res.json();
}

export async function simulateFix(
  reportId: string,
  subject: string,
  fixedVersion: string
): Promise<Record<string, any>> {
  const res = await fetch(`${API_BASE}/reports/${reportId}/simulate-fix`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ subject, fixed_version: fixedVersion }),
  });
  if (!res.ok) throw new Error('Simulate fix failed');
  return res.json();
}

export async function verifyDemo(
  reportId: string,
  corrupt: boolean = false
): Promise<Record<string, any>> {
  const res = await fetch(`${API_BASE}/reports/${reportId}/verify?corrupt=${corrupt}`, {
    method: 'POST',
  });
  if (!res.ok) throw new Error('Verifier self-test failed');
  return res.json();
}
