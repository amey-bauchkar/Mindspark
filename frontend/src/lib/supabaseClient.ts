import { createClient } from '@supabase/supabase-js';
import type { Report, RecentReport } from './types';

const supabaseUrl = import.meta.env.VITE_SUPABASE_URL || '';
const supabaseAnonKey = import.meta.env.VITE_SUPABASE_ANON_KEY || '';

export const isSupabaseConfigured = Boolean(supabaseUrl && supabaseAnonKey);

export const supabase = isSupabaseConfigured
  ? createClient(supabaseUrl, supabaseAnonKey)
  : null;

/**
 * Save report to Supabase Cloud with automatic fallback to prevent crashes.
 */
export async function saveReportToCloud(report: Report): Promise<void> {
  if (!supabase) return;
  try {
    const summary = report.summary;
    const filename = (report.meta?.filename as string) || (report.meta?.sample_name as string) || 'manifest.json';
    const highestVerdict = !summary ? 'REVIEW'
      : summary.incident > 0 ? 'INCIDENT'
      : summary.act_now > 0 ? 'ACT_NOW'
      : summary.upgrade > 0 ? 'UPGRADE'
      : summary.monitor > 0 ? 'MONITOR'
      : summary.review > 0 ? 'REVIEW'
      : summary.cannot_assess > 0 ? 'CANNOT_ASSESS'
      : 'NO_KNOWN_FINDING';
    
    await supabase.from('reports').upsert({
      id: report.id,
      filename,
      highest_verdict: highestVerdict,
      total_packages: summary?.total_packages || report.graph?.nodes?.length || 0,
      incident_count: summary?.incident || 0,
      act_now_count: summary?.act_now || 0,
      data: report,
    });
  } catch (err) {
    console.warn('[Supabase] Cloud save skipped/failed (offline fallback active):', err);
  }
}

/**
 * Fetch latest reports for the Recent Analyses sidebar from Supabase.
 */
export async function getRecentCloudReports(limit = 10): Promise<RecentReport[]> {
  if (!supabase) return [];
  try {
    const { data, error } = await supabase
      .from('reports')
      .select('id, filename, highest_verdict, total_packages, incident_count, act_now_count, created_at')
      .order('created_at', { ascending: false })
      .limit(limit);

    if (error || !data) return [];

    return data.map(r => ({
      id: r.id,
      name: r.filename,
      timestamp: r.created_at,
      summary: {
        incident: r.incident_count || 0,
        act_now: r.act_now_count || 0,
        total_packages: r.total_packages || 0,
      },
    }));
  } catch (err) {
    console.warn('[Supabase] Failed to fetch cloud reports:', err);
    return [];
  }
}

/**
 * Fetch full report by ID from Supabase (for cross-device link sharing).
 */
export async function getCloudReportById(id: string): Promise<Report | null> {
  if (!supabase) return null;
  try {
    const { data, error } = await supabase
      .from('reports')
      .select('data')
      .eq('id', id)
      .single();

    if (error || !data) return null;
    return data.data as Report;
  } catch (err) {
    console.warn('[Supabase] Cloud report lookup failed:', err);
    return null;
  }
}
