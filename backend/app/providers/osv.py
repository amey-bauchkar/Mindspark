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
from .health import report_provider_issue
from .versions import select_fixed_version
from ..models.evidence import EvidenceRecord, EvidenceTier, EvidenceKind
from ..config import get_settings

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{id}"
CHUNK_SIZE = 500   # Keep well under the 1000 limit
MAX_CONCURRENCY = 5
TIMEOUT = 30.0
MAX_RETRIES = 3

# Control, zero-width and bidi-override characters (incl. U+202A–U+202E, U+2066–U+2069)
_CONTROL_CHARS_RE = re.compile(r'[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2028-\u2029\u2066-\u2069\ufeff]')
_VULN_ID_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$')
_MAX_URL_LEN = 2048
MAX_RETRY_AFTER = 30.0  # seconds; never sleep longer on a provider's Retry-After
_MAX_QUOTE_LEN = 500


def _sanitize(text: str) -> str:
    """Strip control/bidi/zero-width characters and cap length."""
    cleaned = _CONTROL_CHARS_RE.sub("", text)
    return cleaned[:_MAX_QUOTE_LEN] if len(cleaned) > _MAX_QUOTE_LEN else cleaned


def _purl_to_query(purl: str) -> dict:
    """Convert purl (pkg:npm/... or pkg:pypi/...) to an OSV package query."""
    if purl.startswith("pkg:pypi/"):
        inner = purl[len("pkg:pypi/"):]
        ecosystem = "PyPI"
    elif purl.startswith("pkg:npm/"):
        inner = purl[len("pkg:npm/"):]
        ecosystem = "npm"
    else:
        inner = purl.split("/", 1)[-1] if "/" in purl else purl
        ecosystem = "npm"

    if "@" in inner:
        encoded_name, version = inner.rsplit("@", 1)
    else:
        encoded_name, version = inner, ""
    name = encoded_name.replace("%40", "@").replace("%2F", "/")
    return {"version": version, "package": {"name": name, "ecosystem": ecosystem}}


def _make_evidence_id(base: str, idx: int) -> str:
    return f"OSV-{hashlib.md5(f'{base}{idx}'.encode()).hexdigest()[:8].upper()}"


def _safe_url(url) -> str | None:
    """Only absolute http(s) links from provider data are kept (no javascript:/data: URLs)."""
    if not isinstance(url, str) or len(url) > _MAX_URL_LEN:
        return None
    url = url.strip()
    if not url.lower().startswith(("https://", "http://")) or _CONTROL_CHARS_RE.search(url):
        return None
    return url


def _retry_delay(resp: httpx.Response | None, attempt: int) -> float:
    if resp is not None:
        try:
            return min(float(resp.headers.get("retry-after", "")), MAX_RETRY_AFTER)
        except ValueError:
            pass
    return float(2 ** attempt)


async def _fetch_with_retry(client: httpx.AsyncClient, method: str, url: str, **kwargs) -> httpx.Response | None:
    """Retry transient failures (network, 429, 5xx) with backoff; give up at once on other 4xx."""
    for attempt in range(MAX_RETRIES):
        resp = None
        try:
            resp = await client.request(method, url, timeout=TIMEOUT, **kwargs)
            if resp.status_code < 400:
                return resp
            if resp.status_code != 429 and resp.status_code < 500:
                return None
        except httpx.HTTPError:
            pass
        if attempt < MAX_RETRIES - 1:
            await asyncio.sleep(_retry_delay(resp, attempt))
    return None


def _absent(purl: str, key: str, claim: str) -> EvidenceRecord:
    return EvidenceRecord(
        id=_make_evidence_id(key, 0),
        tier=EvidenceTier.ABSENT,
        source="osv",
        origin="OSV API",
        kind=EvidenceKind.OTHER,
        subject=purl,
        claim=claim,
        retrieved_at=datetime.now(timezone.utc),
    )


async def fetch_osv_batch(purls: list[str], offline_data: dict | None = None) -> list[EvidenceRecord]:
    """
    Fetch OSV vulnerabilities and malware reports for exact purls.

    Every purl ends up either matched against OSV's answer or with an ABSENT record saying why
    it was not checked: a provider failure is never returned as "no vulnerabilities".
    """
    settings = get_settings()
    records: list[EvidenceRecord] = []
    purls = list(dict.fromkeys(purls))  # Never query the same package version twice
    if not purls:
        return records

    chunks = [purls[i:i+CHUNK_SIZE] for i in range(0, len(purls), CHUNK_SIZE)]
    vuln_ids_for_purl: dict[str, list[str]] = {}

    async with httpx.AsyncClient() as client:
        for chunk in chunks:
            cache_key = "osv_batch_" + hashlib.md5("|".join(sorted(chunk)).encode()).hexdigest()
            batch_result = cache_get(cache_key)
            if batch_result is None and settings.offline_fixtures and offline_data:
                batch_result = offline_data.get("osv_batch")
            if batch_result is None:
                if settings.offline_fixtures:
                    # Recorded mode must not silently go live, nor pretend a lookup ran.
                    report_provider_issue("osv", f"OSV not checked for {len(chunk)} packages (offline fixtures "
                                                 "mode, no recorded response)", scope="batch", count=len(chunk))
                    records.extend(_absent(p, p, "OSV not checked — offline fixtures mode has no recorded response")
                                   for p in chunk)
                    continue
                queries = [_purl_to_query(p) for p in chunk]
                resp = await _fetch_with_retry(client, "POST", OSV_BATCH_URL, json={"queries": queries})
                try:
                    batch_result = resp.json() if resp is not None else None
                except ValueError:
                    batch_result = None
                results = batch_result.get("results") if isinstance(batch_result, dict) else None
                if not isinstance(results, list) or len(results) != len(chunk):
                    report_provider_issue(
                        "osv", f"OSV batch query failed for {len(chunk)} packages", scope="batch", count=len(chunk),
                    )
                    records.extend(_absent(p, p, "OSV API unavailable — vulnerability check not run") for p in chunk)
                    continue
                cache_set(cache_key, batch_result, TTL_VULNS)

            results_list = batch_result.get("results") if isinstance(batch_result, dict) else None
            results_list = results_list if isinstance(results_list, list) else []
            for i, purl in enumerate(chunk):
                entry = results_list[i] if i < len(results_list) and isinstance(results_list[i], dict) else None
                if entry is None:
                    report_provider_issue("osv", f"OSV returned no result for {purl}", scope="record", count=1)
                    records.append(_absent(purl, purl, "OSV returned no result for this package — not checked"))
                    continue
                vids = [v.get("id") for v in entry.get("vulns") or [] if isinstance(v, dict)]
                good = [v for v in vids if isinstance(v, str) and _VULN_ID_RE.match(v)]
                if len(good) != len(vids):
                    report_provider_issue("osv", f"OSV returned {len(vids) - len(good)} malformed record id(s)",
                                          scope="record", count=len(vids) - len(good))
                    records.append(_absent(purl, f"{purl}|malformed-id",
                                           "OSV returned a malformed record id — that record was not assessed"))
                good = list(dict.fromkeys(good))
                if good:
                    vuln_ids_for_purl[purl] = good
                if entry.get("next_page_token"):
                    report_provider_issue("osv", f"OSV paginated the result for {purl}", scope="record", count=1)
                    records.append(_absent(purl, f"{purl}|page",
                                           "OSV returned more records than fit in one page — the rest were not fetched"))

        # Fetch each distinct record once, with bounded concurrency
        vuln_details: dict[str, dict] = {}
        sem = asyncio.Semaphore(MAX_CONCURRENCY)

        async def fetch_detail(vid: str) -> None:
            cached = cache_get(f"osv_vuln_{vid}")
            if isinstance(cached, dict):
                vuln_details[vid] = cached
                return
            if settings.offline_fixtures:
                report_provider_issue("osv", f"OSV record {vid} not recorded (offline fixtures mode)",
                                      scope="record", count=1)
                return
            async with sem:
                resp = await _fetch_with_retry(client, "GET", OSV_VULN_URL.format(id=vid))
            try:
                detail = resp.json() if resp is not None else None
            except ValueError:
                detail = None
            if isinstance(detail, dict):
                vuln_details[vid] = detail
                cache_set(f"osv_vuln_{vid}", detail, TTL_VULNS)
            else:
                report_provider_issue("osv", f"OSV record {vid} could not be fetched", scope="record", count=1)

        all_vuln_ids = sorted({vid for ids in vuln_ids_for_purl.values() for vid in ids})
        await asyncio.gather(*[fetch_detail(vid) for vid in all_vuln_ids])

    records.extend(build_osv_evidence(vuln_ids_for_purl, vuln_details, datetime.now(timezone.utc)))
    return records


def _parse_osv_time(value) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _str_list(value) -> list[str]:
    return [v for v in value if isinstance(v, str)] if isinstance(value, list) else []


def _record_to_evidence(purl: str, vid: str, detail: dict, eid: str, now: datetime) -> EvidenceRecord:
    query = _purl_to_query(purl)
    withdrawn = bool(detail.get("withdrawn"))
    is_malware = vid.startswith("MAL-")
    if is_malware and not withdrawn:
        tier, kind = EvidenceTier.T1, EvidenceKind.MALWARE_REPORT
    else:
        tier, kind = EvidenceTier.T2, EvidenceKind.ADVISORY

    cvss_vector = None
    cvss_severity_text = None
    for sev in detail.get("severity") or []:
        if isinstance(sev, dict) and str(sev.get("type", "")).startswith("CVSS") and isinstance(sev.get("score"), str):
            cvss_vector = _sanitize(sev["score"])[:200]
            cvss_severity_text = str(sev.get("type"))[:20]
            break

    raw_summary = detail.get("summary") or detail.get("details") or ""
    summary = _sanitize(raw_summary) if isinstance(raw_summary, str) else ""
    aliases = [a[:64] for a in _str_list(detail.get("aliases"))][:50]
    cve_aliases = [a for a in aliases if a.startswith("CVE-")]

    origin = (detail.get("database_specific") or {}).get("source") if isinstance(detail.get("database_specific"), dict) else None
    origin = _sanitize(origin)[:80] if isinstance(origin, str) and origin else vid.split("-")[0]

    refs = [r for r in detail.get("references") or [] if isinstance(r, dict)]
    url = next((_safe_url(r.get("url")) for r in refs if r.get("type") == "ADVISORY" and _safe_url(r.get("url"))), None) \
        or next((_safe_url(r.get("url")) for r in refs if _safe_url(r.get("url"))), None)

    # The fix that applies to THIS version (OSV records often carry several version lines)
    fixed_version = select_fixed_version(
        detail, query["package"]["name"], query["version"], query["package"]["ecosystem"],
    )

    return EvidenceRecord(
        id=eid,
        tier=tier,
        source="osv",
        origin=origin,
        kind=kind,
        subject=purl,
        claim=f"{'Malware report' if is_malware else 'Vulnerability'}: {vid}" + (" (withdrawn)" if withdrawn else ""),
        url=url,
        published_at=_parse_osv_time(detail.get("published")),
        retrieved_at=now,
        quote=summary or None,
        withdrawn=withdrawn,
        data={
            "vuln_id": vid,
            "aliases": aliases,
            "cve_aliases": cve_aliases,
            "cvss_vector": cvss_vector,
            "cvss_severity": cvss_severity_text,
            "fixed_version": fixed_version,
            "is_malware": is_malware,
            "summary": summary[:200],
            "modified": detail.get("modified") if isinstance(detail.get("modified"), str) else None,
            "withdrawn_at": detail.get("withdrawn") if isinstance(detail.get("withdrawn"), str) else None,
        },
    )


def build_osv_evidence(
    vuln_ids_for_purl: dict[str, list[str]],
    vuln_details: dict[str, dict],
    now: datetime,
) -> list[EvidenceRecord]:
    """
    Convert OSV records into EvidenceRecords for the purls they were matched to.
    Shared by the live OSV provider and Warrant Watch's recorded replay feed.

    A matched record that is missing (fetch failed) or malformed becomes an ABSENT record for
    that package: the package was NOT shown to be free of that advisory.
    """
    records: list[EvidenceRecord] = []
    idx = 0
    for purl, vids in vuln_ids_for_purl.items():
        for vid in vids:
            detail = vuln_details.get(vid)
            if not isinstance(detail, dict) or not detail:
                records.append(_absent(purl, f"{purl}|{vid}", f"OSV record {vid} could not be fetched — "
                                                              "this advisory was not assessed"))
                continue
            idx += 1
            try:
                records.append(_record_to_evidence(purl, vid, detail, f"E{idx:04d}", now))
            except Exception:
                report_provider_issue("osv", f"OSV record {vid} is malformed", scope="record", count=1)
                records.append(_absent(purl, f"{purl}|{vid}", f"OSV record {vid} is malformed — "
                                                              "this advisory was not assessed"))
    return records
