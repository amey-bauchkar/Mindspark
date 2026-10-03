"""
OSV provider — queries OSV batch API for vulnerabilities and malware reports.
Handles MAL-*, GHSA, CVE aliases, withdrawn records, and version matching.
"""
from __future__ import annotations

import asyncio
import hashlib
import re
import unicodedata
from datetime import datetime, timezone
from typing import Any

import httpx

from .cache import cache_get, cache_set, TTL_VULNS
from ..models.evidence import EvidenceRecord, EvidenceTier, EvidenceKind
from ..config import get_settings

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{id}"
CHUNK_SIZE = 500   # Keep well under the 1000 limit
MAX_CONCURRENCY = 5
TIMEOUT = 30.0
MAX_RETRIES = 3

_CONTROL_CHARS_RE = re.compile(r'[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f-\x9f\u200b-\u200f\u2028-\u2029\ufeff]')
_MAX_QUOTE_LEN = 500


def _sanitize(text: str) -> str:
    """Strip control/bidi/zero-width characters and cap length."""
    cleaned = _CONTROL_CHARS_RE.sub("", text)
    return cleaned[:_MAX_QUOTE_LEN] if len(cleaned) > _MAX_QUOTE_LEN else cleaned


def _purl_to_query(purl: str) -> dict:
    """Convert pkg:npm/name@version to an OSV package query."""
    # purl format: pkg:npm/%40scope%2Fpkg@version
    inner = purl[len("pkg:npm/"):]
    if "@" in inner:
        encoded_name, version = inner.rsplit("@", 1)
    else:
        encoded_name, version = inner, ""
    name = encoded_name.replace("%40", "@").replace("%2F", "/")
    return {"version": version, "package": {"name": name, "ecosystem": "npm"}}


def _make_evidence_id(base: str, idx: int) -> str:
    return f"OSV-{hashlib.md5(f'{base}{idx}'.encode()).hexdigest()[:8].upper()}"


async def _fetch_with_retry(client: httpx.AsyncClient, method: str, url: str, **kwargs) -> httpx.Response | None:
    settings = get_settings()
    for attempt in range(MAX_RETRIES):
        try:
            resp = await client.request(method, url, timeout=TIMEOUT, **kwargs)
            resp.raise_for_status()
            return resp
        except Exception as e:
            if attempt == MAX_RETRIES - 1:
                return None
            await asyncio.sleep(2 ** attempt)
    return None


async def fetch_osv_batch(purls: list[str], offline_data: dict | None = None) -> list[EvidenceRecord]:
    """Fetch OSV vulnerabilities for a list of purls. Returns EvidenceRecord list."""
    settings = get_settings()
    records: list[EvidenceRecord] = []

    if not purls:
        return records

    # Split into chunks
    chunks = [purls[i:i+CHUNK_SIZE] for i in range(0, len(purls), CHUNK_SIZE)]

    # Collect vulnerability IDs per purl
    vuln_ids_for_purl: dict[str, list[str]] = {}

    async with httpx.AsyncClient() as client:
        for chunk in chunks:
            # Check cache first
            cache_key = "osv_batch_" + hashlib.md5("|".join(sorted(chunk)).encode()).hexdigest()
            cached = cache_get(cache_key)
            if cached is not None:
                batch_result = cached
            elif settings.offline_fixtures and offline_data:
                batch_result = offline_data.get("osv_batch", {})
            else:
                queries = [_purl_to_query(p) for p in chunk]
                resp = await _fetch_with_retry(client, "POST", OSV_BATCH_URL, json={"queries": queries})
                if resp is None:
                    # Record ABSENT for all in chunk
                    for purl in chunk:
                        records.append(EvidenceRecord(
                            id=_make_evidence_id(purl, 0),
                            tier=EvidenceTier.ABSENT,
                            source="osv",
                            origin="OSV API",
                            kind=EvidenceKind.OTHER,
                            subject=purl,
                            claim="OSV API unavailable — vulnerability check not run",
                            retrieved_at=datetime.now(timezone.utc),
                        ))
                    continue
                batch_result = resp.json()
                cache_set(cache_key, batch_result, TTL_VULNS)

            results_list = batch_result.get("results", [])
            for i, purl in enumerate(chunk):
                if i >= len(results_list):
                    break
                vulns = results_list[i].get("vulns", [])
                if vulns:
                    vuln_ids_for_purl[purl] = [v["id"] for v in vulns]

    # Fetch detailed vuln records
    all_vuln_ids = {vid for ids in vuln_ids_for_purl.values() for vid in ids}
    vuln_details: dict[str, dict] = {}

    sem = asyncio.Semaphore(MAX_CONCURRENCY)

    async def fetch_detail(client: httpx.AsyncClient, vid: str) -> None:
        cache_key = f"osv_vuln_{vid}"
        cached = cache_get(cache_key)
        if cached is not None:
            vuln_details[vid] = cached
            return
        async with sem:
            resp = await _fetch_with_retry(client, "GET", OSV_VULN_URL.format(id=vid))
            if resp:
                detail = resp.json()
                vuln_details[vid] = detail
                cache_set(cache_key, detail, TTL_VULNS)

    async with httpx.AsyncClient() as client:
        await asyncio.gather(*[fetch_detail(client, vid) for vid in all_vuln_ids])

    # Build EvidenceRecords
    now = datetime.now(timezone.utc)
    idx = 0
    for purl, vids in vuln_ids_for_purl.items():
        for vid in vids:
            detail = vuln_details.get(vid)
            if not detail:
                continue
            idx += 1
            withdrawn = bool(detail.get("withdrawn"))
            is_malware = vid.startswith("MAL-")

            # Determine tier
            if is_malware and not withdrawn:
                tier = EvidenceTier.T1
                kind = EvidenceKind.MALWARE_REPORT
            elif not withdrawn:
                tier = EvidenceTier.T2
                kind = EvidenceKind.ADVISORY
            else:
                tier = EvidenceTier.T2
                kind = EvidenceKind.ADVISORY

            # Extract CVSS severity
            severity_list = detail.get("severity", [])
            cvss_vector = None
            cvss_severity_text = None
            for sev in severity_list:
                if sev.get("type", "").startswith("CVSS"):
                    cvss_vector = sev.get("score")
                    cvss_severity_text = sev.get("type", "")
                    break

            # Get summary/description for quote
            summary = detail.get("summary", "") or detail.get("details", "") or ""
            quote = _sanitize(summary) if summary else None

            # Published/modified
            pub_str = detail.get("published")
            try:
                pub_at = datetime.fromisoformat(pub_str.replace("Z", "+00:00")) if pub_str else None
            except Exception:
                pub_at = None

            # Aliases
            aliases = detail.get("aliases", [])
            cve_aliases = [a for a in aliases if a.startswith("CVE-")]

            # Database origins
            origin = detail.get("database_specific", {}).get("source", "") or vid.split("-")[0]

            # URL
            refs = detail.get("references", [])
            url = next((r.get("url") for r in refs if r.get("type") == "ADVISORY"), None) or \
                  next((r.get("url") for r in refs), None)

            # Fixed version
            fixed_version = None
            for affected in detail.get("affected", []):
                for rng in affected.get("ranges", []):
                    for evt in rng.get("events", []):
                        if "fixed" in evt:
                            fixed_version = evt["fixed"]
                            break

            records.append(EvidenceRecord(
                id=f"E{idx:04d}",
                tier=tier,
                source="osv",
                origin=origin,
                kind=kind,
                subject=purl,
                claim=f"{'Malware report' if is_malware else 'Vulnerability'}: {vid}" + (f" (withdrawn)" if withdrawn else ""),
                url=url,
                published_at=pub_at,
                retrieved_at=now,
                quote=quote,
                withdrawn=withdrawn,
                data={
                    "vuln_id": vid,
                    "aliases": aliases,
                    "cve_aliases": cve_aliases,
                    "cvss_vector": cvss_vector,
                    "cvss_severity": cvss_severity_text,
                    "fixed_version": fixed_version,
                    "is_malware": is_malware,
                    "summary": summary[:200] if summary else "",
                },
            ))

    return records
