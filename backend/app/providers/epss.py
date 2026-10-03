"""
EPSS and CISA KEV providers.
EPSS: https://api.first.org/data/v1/epss?cve=CVE-1,CVE-2
CISA KEV: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
"""
from __future__ import annotations

import asyncio
import hashlib
from datetime import datetime, timezone

import httpx

from .cache import cache_get, cache_set, TTL_EPSS, TTL_KEV
from .health import report_provider_issue
from ..models.evidence import EvidenceRecord, EvidenceTier, EvidenceKind
from ..config import get_settings

EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
TIMEOUT = 30.0
MAX_RETRIES = 3
CHUNK_SIZE = 100  # EPSS batch size


async def _retry_get(client: httpx.AsyncClient, url: str, **kwargs) -> httpx.Response | None:
    """Retry transient failures (network, 429, 5xx) with backoff; give up at once on other 4xx."""
    from .osv import _retry_delay

    for attempt in range(MAX_RETRIES):
        resp = None
        try:
            resp = await client.get(url, timeout=TIMEOUT, **kwargs)
            if resp.status_code < 400:
                return resp
            if resp.status_code != 429 and resp.status_code < 500:
                return None
        except httpx.HTTPError:
            pass
        if attempt < MAX_RETRIES - 1:
            await asyncio.sleep(_retry_delay(resp, attempt))
    return None


async def fetch_kev() -> set[str] | None:
    """
    Return the set of CVE IDs in CISA KEV (cached daily), or None if the catalogue could not be
    checked. None is NOT "nothing listed": callers record the check as not run.
    """
    cache_key = "cisa_kev"
    cached = cache_get(cache_key)
    if isinstance(cached, list):
        return {c for c in cached if isinstance(c, str)}

    settings = get_settings()
    if settings.offline_fixtures:
        report_provider_issue("kev", "CISA KEV not checked (offline fixtures mode, no recorded catalog)", scope="not_checked")
        return None

    async with httpx.AsyncClient() as client:
        resp = await _retry_get(client, KEV_URL)
        try:
            data = resp.json() if resp is not None else None
        except ValueError:
            data = None
        entries = data.get("vulnerabilities") if isinstance(data, dict) else None
        if not isinstance(entries, list):
            report_provider_issue("kev", "CISA KEV catalog could not be fetched", scope="batch")
            return None
        cves = {v["cveID"] for v in entries if isinstance(v, dict) and isinstance(v.get("cveID"), str)}
        cache_set(cache_key, sorted(cves), TTL_KEV)
        return cves


async def fetch_epss(cve_ids: list[str]) -> dict[str, float]:
    """Return dict of CVE → EPSS probability score. Cached 24h."""
    if not cve_ids:
        return {}

    result: dict[str, float] = {}
    settings = get_settings()

    cve_ids = sorted(set(cve_ids))  # Deterministic chunks -> stable cache keys, no duplicate lookups
    chunks = [cve_ids[i:i+CHUNK_SIZE] for i in range(0, len(cve_ids), CHUNK_SIZE)]

    async with httpx.AsyncClient() as client:
        for chunk in chunks:
            cache_key = "epss_" + hashlib.md5(",".join(sorted(chunk)).encode()).hexdigest()
            cached = cache_get(cache_key)
            if cached is not None:
                result.update(cached)
                continue
            if settings.offline_fixtures:
                report_provider_issue(
                    "epss", f"EPSS not checked for {len(chunk)} CVEs (offline fixtures mode)",
                    scope="not_checked", count=len(chunk),
                )
                continue

            resp = await _retry_get(client, EPSS_URL, params={"cve": ",".join(chunk)})
            if resp is None:
                report_provider_issue("epss", f"EPSS scores could not be fetched for {len(chunk)} CVEs", count=len(chunk))
                continue

            try:
                data = resp.json()
            except ValueError:
                data = None
            if not isinstance(data, dict) or not isinstance(data.get("data"), list):
                report_provider_issue("epss", f"EPSS returned a malformed response for {len(chunk)} CVEs", count=len(chunk))
                continue
            chunk_result = {}
            for item in data["data"]:
                if not isinstance(item, dict):
                    continue
                cve = item.get("cve")
                epss = item.get("epss")
                if cve in chunk and epss is not None:
                    try:
                        score = float(epss)
                    except (ValueError, TypeError):
                        continue
                    if 0.0 <= score <= 1.0:
                        chunk_result[cve] = score
            result.update(chunk_result)
            cache_set(cache_key, chunk_result, TTL_EPSS)

    return result


def build_epss_kev_records(
    evidence_list: list[EvidenceRecord],
    epss_scores: dict[str, float],
    kev_set: set[str] | None,
    threshold: float,
) -> list[EvidenceRecord]:
    """
    Given existing OSV evidence records, add EPSS + KEV records for any CVE aliases.
    Returns new EvidenceRecord objects (not mutated originals).

    Every derived record carries `data.derived_from` (the advisory id) so the decision engine
    can ignore it while that advisory is withdrawn or not yet published. `kev_set=None` means
    the KEV catalogue could not be checked: that is recorded per CVE, never treated as "not listed".
    """
    now = datetime.now(timezone.utc)
    new_records: list[EvidenceRecord] = []
    idx = 0

    for rec in evidence_list:
        if rec.tier not in (EvidenceTier.T1, EvidenceTier.T2):
            continue
        cve_aliases: list[str] = rec.data.get("cve_aliases", [])
        vuln_id: str = rec.data.get("vuln_id", "")
        derived = {"derived_from": vuln_id} if vuln_id else {}

        if not cve_aliases:
            # No CVE → EPSS/KEV not applicable
            new_records.append(EvidenceRecord(
                id=f"EPSS-NA-{idx:04d}",
                tier=EvidenceTier.ABSENT,
                source="epss",
                origin="first.org",
                kind=EvidenceKind.EPSS,
                subject=rec.subject,
                claim=f"EPSS n/a, KEV n/a (no CVE alias for {vuln_id})",
                retrieved_at=now,
                data={"vuln_id": vuln_id, **derived},
            ))
            idx += 1
            continue

        for cve in cve_aliases:
            epss_score = epss_scores.get(cve)
            in_kev = kev_set is not None and cve in kev_set

            if kev_set is None:
                new_records.append(EvidenceRecord(
                    id=f"KEV-MISS-{idx + 1:04d}",
                    tier=EvidenceTier.ABSENT,
                    source="kev",
                    origin="CISA KEV",
                    kind=EvidenceKind.KEV,
                    subject=rec.subject,
                    claim=f"CISA KEV unavailable — known-exploited status of {cve} not checked",
                    retrieved_at=now,
                    data={"cve": cve, **derived},
                ))

            idx += 1
            if in_kev:
                new_records.append(EvidenceRecord(
                    id=f"KEV-{idx:04d}",
                    tier=EvidenceTier.T1,
                    source="kev",
                    origin="CISA KEV",
                    kind=EvidenceKind.KEV,
                    subject=rec.subject,
                    claim=f"{cve} is in the CISA Known Exploited Vulnerabilities catalogue",
                    url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                    retrieved_at=now,
                    data={"cve": cve, "epss": epss_score, **derived},
                ))
            elif epss_score is not None:
                new_records.append(EvidenceRecord(
                    id=f"EPSS-{idx:04d}",
                    tier=EvidenceTier.T2,
                    source="epss",
                    origin="first.org",
                    kind=EvidenceKind.EPSS,
                    subject=rec.subject,
                    claim=f"EPSS score for {cve}: {epss_score:.3f} ({'≥' if epss_score >= threshold else '<'} threshold {threshold})",
                    url=f"https://api.first.org/data/v1/epss?cve={cve}",
                    retrieved_at=now,
                    data={"cve": cve, "epss": epss_score, "threshold": threshold,
                          "above_threshold": epss_score >= threshold, **derived},
                ))
            else:
                new_records.append(EvidenceRecord(
                    id=f"EPSS-MISS-{idx:04d}",
                    tier=EvidenceTier.ABSENT,
                    source="epss",
                    origin="first.org",
                    kind=EvidenceKind.EPSS,
                    subject=rec.subject,
                    claim=f"EPSS score not found for {cve}",
                    retrieved_at=now,
                    data={"cve": cve, **derived},
                ))

    return new_records
