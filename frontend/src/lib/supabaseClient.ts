import { createClient } from '@supabase/supabase-js';
import type { Report, RecentReport } from './types';

const supabaseUrl = import.meta.env.VITE_SUPABASE_URL || '';
const supabaseAnonKey = import.meta.env.VITE_SUPABASE_ANON_KEY || '';

export const isSupabaseConfigured = Boolean(supabaseUrl && supabaseAnonKey);

export const supabase = isSupabaseConfigured
  ? createClient(supabaseUrl, supabaseAnonKey)
  : null;

// ── Phase 5: SHA-256 Canonical Integrity Seal ─────────────────────────────────

/**
 * Compute a canonical SHA-256 fingerprint over the deterministic report fields.
 * Input: JSON-sorted stringification of summary + decisions list + filename.
 * Returns hex-encoded digest (64 chars), or null if SubtleCrypto is unavailable.
 */
export async function computeReportIntegritySeal(report: Report): Promise<string | null> {
  if (!globalThis.crypto?.subtle) return null;
  try {
    const canonical = JSON.stringify({
      summary: report.summary,
      decisions: (report.decisions ?? []).map((d) => ({
        subject: d.subject,
        verdict: d.verdict,
        urgency: d.urgency,
        qualifier: d.qualifier,
      })),
      filename: (report.meta?.filename as string) ?? '',
    });
    const msgBuf = new TextEncoder().encode(canonical);
    const hashBuf = await globalThis.crypto.subtle.digest('SHA-256', msgBuf);
    const hashArr = Array.from(new Uint8Array(hashBuf));
    return hashArr.map((b) => b.toString(16).padStart(2, '0')).join('');
  } catch {
    return null;
  }
}

/**
 * Verify a report's stored seal against a freshly computed seal.
 * Returns: 'valid' | 'tampered' | 'unverified'
 */
export async function verifyReportSeal(
  report: Report,
  storedSeal: string | null | undefined,
): Promise<'valid' | 'tampered' | 'unverified'> {
  if (!storedSeal) return 'unverified';
  const computed = await computeReportIntegritySeal(report);
  if (!computed) return 'unverified';
  return computed === storedSeal ? 'valid' : 'tampered';
}

// ── Phase 4: Corporate Privacy Mode — Scope Redaction ────────────────────────

/**
 * Return a list of scoped prefixes extracted from package names (e.g. '@acme-corp').
 * Used to seed the privacy mode redaction list from the user's own uploads.
 */
export function detectInternalScopes(report: Report, customPrefixes: string[] = []): string[] {
  const detected = new Set<string>(customPrefixes.filter(Boolean));
  const decisions = report.decisions ?? [];
  decisions.forEach((d) => {
    const name: string = ((d as unknown as Record<string, unknown>).name as string) ?? '';
    if (name.startsWith('@')) {
      const prefix = name.split('/')[0];
      if (prefix) detected.add(prefix);
    }
  });
  return Array.from(detected);
}

/**
 * Redact proprietary internal scopes from a report before it is synced to cloud.
 * Packages matching any of the `internalScopePrefixes` (e.g. ['@acme-corp', '@internal'])
 * have their names replaced with '@internal-masked/pkg-NNN'.
 *
 * The local copy in the browser session is NEVER modified — only the cloud payload.
 */
export function redactInternalScopes(report: Report, internalScopePrefixes: string[]): Report {
  if (!internalScopePrefixes.length) return report;

  // Deep clone so we don't mutate the live report object
  const clone: Report = JSON.parse(JSON.stringify(report));
  let counter = 0;
  const nameMap = new Map<string, string>();

  function maybeRedact(name: string): string {
    const isInternal = internalScopePrefixes.some(
      (prefix) => name === prefix || name.startsWith(prefix + '/'),
    );
    if (!isInternal) return name;
    if (!nameMap.has(name)) {
      nameMap.set(name, `@internal-masked/pkg-${String(++counter).padStart(3, '0')}`);
    }
    return nameMap.get(name)!;
  }

  // Redact decisions
  (clone.decisions ?? []).forEach((d) => {
    const dec = d as unknown as Record<string, unknown>;
    if (typeof dec.name === 'string') dec.name = maybeRedact(dec.name);
    if (typeof dec.subject === 'string') {
      // purl: pkg:npm/@scope/name@version → redact name part
      dec.subject = (dec.subject as string).replace(
        /pkg:npm\/([^@]+)@/,
        (_, pkgname) => `pkg:npm/${maybeRedact(decodeURIComponent(pkgname)).replace('@', '%40').replace('/', '%2F')}@`,
      );
    }
  });

  // Redact graph nodes
  (clone.graph?.nodes ?? []).forEach((node) => {
    const n = node as unknown as Record<string, unknown>;
    if (typeof n.name === 'string') n.name = maybeRedact(n.name);
    if (typeof n.purl === 'string') {
      n.purl = (n.purl as string).replace(
        /pkg:npm\/([^@]+)@/,
        (_, pkgname) => `pkg:npm/${maybeRedact(decodeURIComponent(pkgname)).replace('@', '%40').replace('/', '%2F')}@`,
      );
    }
  });

  // Redact licenses
  (clone.licenses ?? []).forEach((lic) => {
    const l = lic as unknown as Record<string, unknown>;
    if (typeof l.name === 'string') l.name = maybeRedact(l.name);
  });

  return clone;
}

// ── Cloud Sync ────────────────────────────────────────────────────────────────

/**
 * Save report to Supabase Cloud with:
 *  - Phase 4: optional corporate privacy scope redaction
 *  - Phase 5: SHA-256 integrity seal
 *  - Automatic offline fallback to prevent crashes
 */
export async function saveReportToCloud(
  report: Report,
  options: {
    corporatePrivacyMode?: boolean;
    internalScopePrefixes?: string[];
  } = {},
): Promise<void> {
  if (!supabase) return;
  try {
    // Phase 4: Apply corporate privacy redaction if enabled
    const payload: Report = options.corporatePrivacyMode && options.internalScopePrefixes?.length
      ? redactInternalScopes(report, options.internalScopePrefixes)
      : report;

    // Phase 5: Compute SHA-256 integrity seal from the ORIGINAL (unredacted) local data
    const integritySeal = await computeReportIntegritySeal(report);

    const summary = payload.summary;
    const filename =
      (payload.meta?.filename as string) ||
      (payload.meta?.sample_name as string) ||
      'manifest.json';
    const highestVerdict = !summary
      ? 'REVIEW'
      : summary.incident > 0
      ? 'INCIDENT'
      : summary.act_now > 0
      ? 'ACT_NOW'
      : summary.upgrade > 0
      ? 'UPGRADE'
      : summary.monitor > 0
      ? 'MONITOR'
      : summary.review > 0
      ? 'REVIEW'
      : summary.cannot_assess > 0
      ? 'CANNOT_ASSESS'
      : 'NO_KNOWN_FINDING';

    await supabase.from('reports').upsert({
      id: payload.id,
      filename,
      highest_verdict: highestVerdict,
      total_packages: summary?.total_packages || (payload.graph?.nodes?.length ?? 0),
      incident_count: summary?.incident || 0,
      act_now_count: summary?.act_now || 0,
      data: {
        ...payload,
        // Embed the integrity seal inside the stored data blob
        integrity_seal: integritySeal,
      },
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

    return (data as any[]).map((r: any) => ({
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
