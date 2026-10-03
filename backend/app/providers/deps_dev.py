"""deps.dev provider — fetches license info for packages missing license data."""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import httpx

from .cache import cache_get, cache_set, TTL_DEPS_DEV
from ..models.evidence import EvidenceRecord, EvidenceTier, EvidenceKind

DEPS_DEV_URL = "https://api.deps.dev/v3/systems/npm/packages/{name}/versions/{version}"
MAX_CONCURRENCY = 5
TIMEOUT = 20.0
MAX_RETRIES = 2


async def fetch_license_from_deps_dev(name: str, version: str) -> str | None:
    """Return SPDX license expression or None."""
    # Encode scoped packages
    encoded_name = name.replace("/", "%2F")
    encoded_version = version.replace("+", "%2B")
    cache_key = f"depsdev_{encoded_name}_{encoded_version}"

    cached = cache_get(cache_key)
    if cached is not None:
        return cached.get("license")

    url = DEPS_DEV_URL.format(name=encoded_name, version=encoded_version)
    try:
        async with httpx.AsyncClient() as client:
            for attempt in range(MAX_RETRIES):
                try:
                    resp = await client.get(url, timeout=TIMEOUT)
                    if resp.status_code == 200:
                        data = resp.json()
                        licenses = data.get("licenses", []) or []
                        if isinstance(licenses, list) and licenses:
                            expr = " AND ".join(licenses)
                        else:
                            expr = data.get("version", {}).get("licenses", [None])[0] if data.get("version") else None
                        cache_set(cache_key, {"license": expr}, TTL_DEPS_DEV)
                        return expr
                    break
                except Exception:
                    if attempt == MAX_RETRIES - 1:
                        break
                    await asyncio.sleep(1)
    except Exception:
        pass
    return None


async def bulk_fetch_licenses(packages: list[tuple[str, str]]) -> dict[tuple[str, str], str | None]:
    """
    Fetch licenses for multiple (name, version) pairs concurrently.
    Returns dict of (name, version) → license.
    """
    sem = asyncio.Semaphore(MAX_CONCURRENCY)
    results: dict[tuple[str, str], str | None] = {}

    async def _fetch(name: str, version: str) -> None:
        async with sem:
            result = await fetch_license_from_deps_dev(name, version)
            results[(name, version)] = result

    await asyncio.gather(*[_fetch(n, v) for n, v in packages])
    return results
