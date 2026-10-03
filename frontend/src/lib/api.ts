import type { Report, SampleItem, MethodologyData } from './types';
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

export async function getReport(reportId: string, asOf?: string): Promise<Report> {
  const url = asOf
    ? `${API_BASE}/reports/${encodeURIComponent(reportId)}?as_of=${encodeURIComponent(asOf)}`
    : `${API_BASE}/reports/${encodeURIComponent(reportId)}`;

  try {
    const res = await fetch(url);
    if (res.ok) {
      return await res.json();
    }
  } catch {
    // Local backend error or offline; continue to cloud fallback
  }

  // Graceful fallback: check if report is available in Supabase cloud
  try {
    const cloudReport = await getCloudReportById(reportId);
    if (cloudReport) {
      return cloudReport;
    }
  } catch {
    // Cloud lookup failed
  }

  throw new Error('Failed to fetch report: not found locally or in cloud storage');
}

export function exportUrl(reportId: string, format: 'json' | 'md' = 'json'): string {
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
