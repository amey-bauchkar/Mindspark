import type { Report } from './types';
import type { DependencyChangeEvent } from '../components/asof/AsOfSlider';

/** Decode `pkg:npm/%40scope%2Fname@1.2.3` / `pkg:pypi/name@1.0` into name + version. */
export function parsePurl(purl: string): { name: string; version: string } {
  const inner = purl.replace(/^pkg:[a-z]+\//, '');
  const at = inner.lastIndexOf('@');
  const rawName = at > 0 ? inner.slice(0, at) : inner;
  let name = rawName;
  try {
    name = decodeURIComponent(rawName);
  } catch {
    // keep the raw form
  }
  return { name, version: at > 0 ? inner.slice(at + 1) : '' };
}

function toIso(value: unknown): string | null {
  if (typeof value !== 'string' || !value) return null;
  const d = new Date(value.replace(' ', 'T'));
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

/**
 * Timeline markers for the as-of view, taken ONLY from dated evidence in this report:
 * when each OSV advisory / malware report was published and, if so, withdrawn.
 * Nothing is inferred or invented — a report without dated evidence has no markers.
 */
export function evidenceTimeline(report: Report): DependencyChangeEvent[] {
  const events: DependencyChangeEvent[] = [];
  const seen = new Set<string>();
  for (const e of report.evidence ?? []) {
    if (e.source !== 'osv' || (e.tier !== 'T1' && e.tier !== 'T2')) continue;
    const data = (e.data ?? {}) as Record<string, unknown>;
    const vulnId = typeof data.vuln_id === 'string' ? data.vuln_id : e.id;
    const { name, version } = parsePurl(e.subject);
    const published = toIso(e.published_at);
    if (published && !seen.has(`${e.subject}|${vulnId}|p`)) {
      seen.add(`${e.subject}|${vulnId}|p`);
      events.push({
        package_id: e.subject,
        package_name: name,
        version,
        type: data.is_malware ? 'MALWARE_REPORT' : 'ADVISORY',
        effective_at: published,
        reason: `${vulnId} published${e.origin ? ` (${e.origin})` : ''}`,
      });
    }
    const withdrawn = toIso(data.withdrawn_at);
    if (withdrawn && !seen.has(`${e.subject}|${vulnId}|w`)) {
      seen.add(`${e.subject}|${vulnId}|w`);
      events.push({
        package_id: e.subject,
        package_name: name,
        version,
        type: 'WITHDRAWN',
        effective_at: withdrawn,
        reason: `${vulnId} withdrawn by its source`,
      });
    }
  }
  return events.sort((a, b) => a.effective_at.localeCompare(b.effective_at));
}
