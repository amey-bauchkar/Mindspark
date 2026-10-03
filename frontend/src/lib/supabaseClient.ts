import { createClient } from '@supabase/supabase-js';
import type { Report, RecentReport } from './types';

const supabaseUrl = import.meta.env.VITE_SUPABASE_URL || '';
const supabaseAnonKey = import.meta.env.VITE_SUPABASE_ANON_KEY || '';

export const isSupabaseConfigured = Boolean(supabaseUrl && supabaseAnonKey);

export const supabase = isSupabaseConfigured
  ? createClient(supabaseUrl, supabaseAnonKey)
  : null;

// ── Canonical JSON (stable key order, so storage round-trips don't change the hash) ──

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const obj = value as Record<string, unknown>;
  return `{${Object.keys(obj)
    .filter((k) => obj[k] !== undefined)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`)
    .join(',')}}`;
}

function sealInput(report: Report) {
  return {
    summary: report.summary,
    decisions: (report.decisions ?? []).map((d) => ({
      subject: d.subject,
      verdict: d.verdict,
      urgency: d.urgency,
      qualifier: d.qualifier,
    })),
    filename: (report.meta?.filename as string) ?? '',
  };
}

async function sha256Hex(text: string): Promise<string | null> {
  if (!globalThis.crypto?.subtle) return null;
  try {
    const hashBuf = await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
    return Array.from(new Uint8Array(hashBuf)).map((b) => b.toString(16).padStart(2, '0')).join('');
  } catch {
    return null;
  }
}

// ── Phase 5: SHA-256 Canonical Integrity Seal ─────────────────────────────────

/**
 * SHA-256 fingerprint over the deterministic report fields (summary, decision verdicts,
 * filename), serialised as canonical JSON. Returns null if SubtleCrypto is unavailable.
 */
export async function computeReportIntegritySeal(report: Report): Promise<string | null> {
  return sha256Hex(canonicalJson(sealInput(report)));
}

/**
 * Verify a stored seal against the report as loaded.
 * 'unverified' means there was nothing to verify against (e.g. a local report) — never "valid".
 * Seals written before canonical serialisation are still accepted.
 */
export async function verifyReportSeal(
  report: Report,
  storedSeal: string | null | undefined,
): Promise<'valid' | 'tampered' | 'unverified'> {
  if (!storedSeal) return 'unverified';
  const canonical = await computeReportIntegritySeal(report);
  if (!canonical) return 'unverified';
  if (canonical === storedSeal) return 'valid';
  const legacy = await sha256Hex(JSON.stringify(sealInput(report)));
  return legacy === storedSeal ? 'valid' : 'tampered';
}

// ── Phase 4: Corporate Privacy Mode — Scope Redaction ────────────────────────

const PRIVACY_PREFS_KEY = 'warrant:cloud-privacy';

export interface CloudPrivacyPrefs {
  corporatePrivacyMode: boolean;
  internalScopePrefixes: string[];
}

/** Remember the privacy choice so every later sync of the same reports applies it too. */
export function setCloudPrivacyPrefs(prefs: CloudPrivacyPrefs): void {
  try {
    localStorage.setItem(PRIVACY_PREFS_KEY, JSON.stringify(prefs));
  } catch {
    // Storage unavailable (private mode): the next sync falls back to "no redaction requested"
  }
}

export function getCloudPrivacyPrefs(): CloudPrivacyPrefs {
  try {
    const raw = JSON.parse(localStorage.getItem(PRIVACY_PREFS_KEY) || 'null');
    if (raw && typeof raw.corporatePrivacyMode === 'boolean' && Array.isArray(raw.internalScopePrefixes)) {
      return {
        corporatePrivacyMode: raw.corporatePrivacyMode,
        internalScopePrefixes: raw.internalScopePrefixes.filter((p: unknown) => typeof p === 'string' && p.trim()),
      };
    }
  } catch {
    // ignore
  }
  return { corporatePrivacyMode: false, internalScopePrefixes: [] };
}

/**
 * Return a list of scoped prefixes extracted from package names (e.g. '@acme-corp').
 * Used to seed the privacy mode redaction list from the user's own uploads.
 */
export function detectInternalScopes(report: Report, customPrefixes: string[] = []): string[] {
  const detected = new Set<string>(customPrefixes.filter(Boolean));
  (report.decisions ?? []).forEach((d) => {
    if (d.name.startsWith('@')) {
      const prefix = d.name.split('/')[0];
      if (prefix) detected.add(prefix);
    }
  });
  return Array.from(detected);
}

function namesInReport(report: Report): Set<string> {
  const names = new Set<string>();
  const fromPurl = (purl: unknown) => {
    if (typeof purl !== 'string') return;
    const m = /^pkg:npm\/(.+)@[^@]*$/.exec(purl);
    if (m) {
      try {
        names.add(decodeURIComponent(m[1]));
      } catch {
        // malformed purl: ignore
      }
    }
  };
  report.graph?.nodes?.forEach((n) => {
    names.add(n.name);
    fromPurl(n.id);
  });
  report.decisions?.forEach((d) => {
    names.add(d.name);
    fromPurl(d.subject);
  });
  report.licenses?.forEach((l) => {
    names.add(l.name);
    fromPurl(l.subject);
  });
  report.evidence?.forEach((e) => fromPurl(e.subject));
  return names;
}

function replaceAll(text: string, pairs: [string, string][]): string {
  let out = text;
  for (const [from, to] of pairs) {
    if (out.includes(from)) out = out.split(from).join(to);
  }
  return out;
}

function deepReplaceStrings<T>(value: T, pairs: [string, string][]): T {
  if (typeof value === 'string') return replaceAll(value, pairs) as unknown as T;
  if (Array.isArray(value)) return value.map((v) => deepReplaceStrings(v, pairs)) as unknown as T;
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[replaceAll(k, pairs)] = deepReplaceStrings(v, pairs);
    }
    return out as T;
  }
  return value;
}

/**
 * Redact proprietary internal scopes from a report before it is synced to cloud.
 * Every package matching `internalScopePrefixes` (e.g. ['@acme-corp']) is replaced with
 * '@internal-masked/pkg-NNN' EVERYWHERE it appears — decisions, paths, graph nodes and edges,
 * licenses, evidence subjects and claims — in both plain and purl-encoded form.
 *
 * The local copy in the browser session is NEVER modified — only the cloud payload.
 */
export function redactInternalScopes(report: Report, internalScopePrefixes: string[]): Report {
  const prefixes = internalScopePrefixes.map((p) => p.trim()).filter(Boolean);
  if (!prefixes.length) return report;

  const internal = Array.from(namesInReport(report))
    .filter((name) => prefixes.some((prefix) => name === prefix || name.startsWith(prefix + '/')))
    .sort();
  if (!internal.length) return report;

  const pairs: [string, string][] = [];
  internal.forEach((name, i) => {
    const masked = `@internal-masked/pkg-${String(i + 1).padStart(3, '0')}`;
    pairs.push([name, masked]);
    pairs.push([name.replace('@', '%40').replace('/', '%2F'), masked.replace('@', '%40').replace('/', '%2F')]);
    pairs.push([encodeURIComponent(name), encodeURIComponent(masked)]);
  });
  // Longest first, so '@acme/ab' is replaced before '@acme/a' could match inside it
  pairs.sort((a, b) => b[0].length - a[0].length);
  return deepReplaceStrings(report, pairs);
}

// ── Cloud Sync ────────────────────────────────────────────────────────────────

/**
 * Save report to Supabase Cloud with:
 *  - Phase 4: corporate privacy scope redaction (explicit options, else the remembered choice)
 *  - Phase 5: SHA-256 integrity seal over the payload that is actually stored
 *  - Automatic offline fallback to prevent crashes
 * As-of views and copies that were themselves loaded from the cloud are never uploaded.
 */
export async function saveReportToCloud(
  report: Report,
  options: {
    corporatePrivacyMode?: boolean;
    internalScopePrefixes?: string[];
  } = {},
): Promise<void> {
  if (!supabase) return;
  const meta = (report.meta ?? {}) as Record<string, unknown>;
  if (meta.as_of_view || meta.cloud_copy) return;
  try {
    const prefs = options.corporatePrivacyMode === undefined ? getCloudPrivacyPrefs() : {
      corporatePrivacyMode: options.corporatePrivacyMode,
      internalScopePrefixes: options.internalScopePrefixes ?? [],
    };
    const payload: Report = prefs.corporatePrivacyMode && prefs.internalScopePrefixes.length
      ? redactInternalScopes(report, prefs.internalScopePrefixes)
      : report;

    // Phase 5: the seal covers exactly what is stored, so the cloud copy can be verified later
    const integritySeal = await computeReportIntegritySeal(payload);

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

    const row = {
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
    };
    // Upsert by report id is idempotent, so one retry after a transient failure is safe.
    let { error } = await supabase.from('reports').upsert(row);
    if (error) {
      await new Promise((r) => setTimeout(r, 1500));
      ({ error } = await supabase.from('reports').upsert(row));
    }
    if (error) console.warn('[Supabase] Cloud save failed; the report remains available locally:', error.message);
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

    return data.map((r) => ({
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

    if (error || !data || !data.data) return null;
    const report = data.data as Report;
    // Mark as a cloud copy: shown read-only, never re-uploaded over itself
    return { ...report, meta: { ...(report.meta ?? {}), cloud_copy: true } };
  } catch (err) {
    console.warn('[Supabase] Cloud report lookup failed:', err);
    return null;
  }
}
