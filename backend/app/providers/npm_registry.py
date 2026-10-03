"""
npm registry provider — fetches package publish times for staleness and freshness checks.
Fetched ONLY for: direct deps, nodes with lookalike candidates, nodes with T1/T2 finding.
Others get an ABSENT record.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import httpx

from .cache import cache_get, cache_set, TTL_REGISTRY
from .health import report_provider_issue
from ..models.evidence import EvidenceRecord, EvidenceTier, EvidenceKind
from ..security import sanitize_package_name, verify_safe_outbound_ip

REGISTRY_URL = "https://registry.npmjs.org/{name}"
MAX_CONCURRENCY = 5
TIMEOUT = 20.0
MAX_RETRIES = 2


async def fetch_npm_times(name: str) -> dict | None:
    """Return the npm registry `time` object for a package, or None on failure."""
    # ── Sanitize package name to prevent URL injection / path traversal ──
    try:
        safe_name = sanitize_package_name(name)
    except ValueError:
        return None

    cache_key = f"npm_registry_{safe_name}"
    cached = cache_get(cache_key)
    if cached is not None:
        return cached

    # ── Verify outbound target hostname resolves to a public IP (anti-SSRF) ──
    if not verify_safe_outbound_ip("registry.npmjs.org"):
        return None

    encoded = safe_name.replace("/", "%2F")
    url = REGISTRY_URL.format(name=encoded)
    try:
        async with httpx.AsyncClient() as client:
            for attempt in range(MAX_RETRIES):
                try:
                    resp = await client.get(url, timeout=TIMEOUT, headers={"Accept": "application/json"})
                    if resp.status_code == 200:
                        data = resp.json()
                        times = data.get("time", {})
                        cache_set(cache_key, times, TTL_REGISTRY)
                        return times
                    if resp.status_code == 429 or resp.status_code >= 500:
                        report_provider_issue("npm-registry", f"npm registry returned HTTP {resp.status_code} for {name}", count=1)
                    break
                except Exception:
                    if attempt < MAX_RETRIES - 1:
                        await asyncio.sleep(1)
                    else:
                        report_provider_issue("npm-registry", f"npm registry unreachable for {name}", count=1)
    except Exception:
        report_provider_issue("npm-registry", f"npm registry unreachable for {name}", count=1)
    return None


async def bulk_fetch_npm_times(
    packages: list[tuple[str, str]],   # (name, version)
) -> dict[str, dict | None]:
    """Fetch times for multiple packages concurrently. Returns dict of name → times."""
    sem = asyncio.Semaphore(MAX_CONCURRENCY)
    results: dict[str, dict | None] = {}

    async def _fetch(name: str, version: str) -> None:
        async with sem:
            times = await fetch_npm_times(name)
            results[name] = times

    unique_names = list({name for name, _ in packages})
    await asyncio.gather(*[_fetch(n, "") for n in unique_names])
    return results
