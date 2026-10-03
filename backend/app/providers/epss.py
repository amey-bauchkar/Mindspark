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
from ..models.evidence import EvidenceRecord, EvidenceTier, EvidenceKind
from ..config import get_settings

EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
TIMEOUT = 30.0
MAX_RETRIES = 3
CHUNK_SIZE = 100  # EPSS batch size


async def _retry_get(client: httpx.AsyncClient, url: str, **kwargs) -> httpx.Response | None:
    for attempt in range(MAX_RETRIES):
        try:
            resp = await client.get(url, timeout=TIMEOUT, **kwargs)
            resp.raise_for_status()
            return resp
        except Exception:
            if attempt == MAX_RETRIES - 1:
                return None
            await asyncio.sleep(2 ** attempt)
    return None


async def fetch_kev() -> set[str]:
    """Return the set of CVE IDs in CISA KEV. Cached daily."""
    cache_key = "cisa_kev"
    cached = cache_get(cache_key)
    if cached is not None:
        return set(cached)

    settings = get_settings()
    if settings.offline_fixtures:
        return set()

    async with httpx.AsyncClient() as client:
        resp = await _retry_get(client, KEV_URL)
        if resp is None:
            return set()
        data = resp.json()
        cves = {v["cveID"] for v in data.get("vulnerabilities", []) if "cveID" in v}
        cache_set(cache_key, list(cves), TTL_KEV)
        return cves


async def fetch_epss(cve_ids: list[str]) -> dict[str, float]:
    """Return dict of CVE → EPSS probability score. Cached 24h."""
    if not cve_ids:
        return {}

    result: dict[str, float] = {}
    settings = get_settings()

    chunks = [cve_ids[i:i+CHUNK_SIZE] for i in range(0, len(cve_ids), CHUNK_SIZE)]

    async with httpx.AsyncClient() as client:
        for chunk in chunks:
            cache_key = "epss_" + hashlib.md5(",".join(sorted(chunk)).encode()).hexdigest()
            cached = cache_get(cache_key)
            if cached is not None:
                result.update(cached)
                continue
            if settings.offline_fixtures:
                continue

            resp = await _retry_get(client, EPSS_URL, params={"cve": ",".join(chunk)})
            if resp is None:
                continue

            data = resp.json()
            chunk_result = {}
            for item in data.get("data", []):
                cve = item.get("cve")
                epss = item.get("epss")
                if cve and epss is not None:
                    try:
                        chunk_result[cve] = float(epss)
                    except (ValueError, TypeError):
                        pass
            result.update(chunk_result)
            cache_set(cache_key, chunk_result, TTL_EPSS)

    return result


def build_epss_kev_records(
    evidence_list: list[EvidenceRecord],
    epss_scores: dict[str, float],
    kev_set: set[str],
    threshold: float,
) -> list[EvidenceRecord]:
    """
    Given existing OSV evidence records, add EPSS + KEV records for any CVE aliases.
    Returns new EvidenceRecord objects (not mutated originals).
    """
    now = datetime.now(timezone.utc)
    new_records: list[EvidenceRecord] = []
    idx = 0

    for rec in evidence_list:
        if rec.tier not in (EvidenceTier.T1, EvidenceTier.T2):
            continue
        cve_aliases: list[str] = rec.data.get("cve_aliases", [])
        vuln_id: str = rec.data.get("vuln_id", "")

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
                data={"vuln_id": vuln_id},
            ))
            idx += 1
            continue

        for cve in cve_aliases:
            epss_score = epss_scores.get(cve)
            in_kev = cve in kev_set

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
                    data={"cve": cve, "epss": epss_score},
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
                    data={"cve": cve, "epss": epss_score, "threshold": threshold, "above_threshold": epss_score >= threshold},
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
                    data={"cve": cve},
                ))

    return new_records
