"""
npm registry provider — fetches package publish times for staleness and freshness checks.
Fetched ONLY for: direct deps, nodes with lookalike candidates, nodes with T1/T2 finding.
Others get an ABSENT record.
"""
from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone

import httpx

from .cache import cache_get, cache_set, TTL_REGISTRY
from .health import report_provider_issue
from ..models.evidence import EvidenceRecord, EvidenceTier, EvidenceKind
from ..security import sanitize_package_name, verify_safe_outbound_ip

REGISTRY_URL = "https://registry.npmjs.org/{name}"
REGISTRY_HOST = "registry.npmjs.org"
MAX_CONCURRENCY = 5
TIMEOUT = 20.0
MAX_RETRIES = 2
MAX_TIME_ENTRIES = 20_000      # Versions per package kept from the registry `time` map
HOST_CHECK_TTL = 300.0         # Seconds a successful/failed resolution check is reused

_host_check: dict[str, tuple[float, bool]] = {}
_host_locks: dict[int, asyncio.Lock] = {}


async def _registry_host_is_public() -> bool:
    """
    Anti-SSRF / DNS-rebinding guard: registry.npmjs.org must resolve to a public address.
    The (blocking) resolution runs off the event loop, once at a time, and is reused for
    HOST_CHECK_TTL seconds instead of being repeated for every package.
    """
    def fresh() -> bool | None:
        cached = _host_check.get(REGISTRY_HOST)
        return cached[1] if cached and time.monotonic() - cached[0] < HOST_CHECK_TTL else None

    if (ok := fresh()) is not None:
        return ok
    lock = _host_locks.setdefault(id(asyncio.get_running_loop()), asyncio.Lock())
    async with lock:  # Single flight: concurrent lookups wait for one resolution
        if (ok := fresh()) is not None:
            return ok
        ok = await asyncio.to_thread(verify_safe_outbound_ip, REGISTRY_HOST)
        _host_check[REGISTRY_HOST] = (time.monotonic(), ok)
        return ok


def _clean_times(raw) -> dict[str, str] | None:
    """Keep only string→string entries of the registry `time` map (schema validation)."""
    if not isinstance(raw, dict):
        return None
    return {k: v for k, v in list(raw.items())[:MAX_TIME_ENTRIES] if isinstance(k, str) and isinstance(v, str)}


async def fetch_npm_times(name: str) -> dict | None:
    """Return the npm registry `time` object for a package, or None if it could not be fetched."""
    # ── Sanitize package name to prevent URL injection / path traversal ──
    try:
        safe_name = sanitize_package_name(name)
    except ValueError:
        return None

    cache_key = f"npm_registry_{safe_name}"
    cached = cache_get(cache_key)
    if isinstance(cached, dict):
        return cached

    if not await _registry_host_is_public():
        report_provider_issue("npm-registry", f"{REGISTRY_HOST} did not resolve to a public address — "
                                              f"metadata for {name} not fetched", count=1)
        return None

    url = REGISTRY_URL.format(name=safe_name.replace("/", "%2F"))
    async with httpx.AsyncClient() as client:
        for attempt in range(MAX_RETRIES):
            try:
                resp = await client.get(url, timeout=TIMEOUT, headers={"Accept": "application/json"})
            except httpx.HTTPError:
                if attempt < MAX_RETRIES - 1:
                    await asyncio.sleep(1)
                    continue
                report_provider_issue("npm-registry", f"npm registry unreachable for {name}", count=1)
                return None
            if resp.status_code == 200:
                try:
                    times = _clean_times(resp.json().get("time"))
                except (ValueError, AttributeError):
                    times = None
                if times is None:
                    report_provider_issue("npm-registry", f"npm registry returned malformed metadata for {name}", count=1)
                    return None
                cache_set(cache_key, times, TTL_REGISTRY)
                return times
            if resp.status_code == 429 or resp.status_code >= 500:
                if attempt < MAX_RETRIES - 1:
                    await asyncio.sleep(1)
                    continue
                report_provider_issue("npm-registry", f"npm registry returned HTTP {resp.status_code} for {name}", count=1)
            return None  # 404 etc.: not in the public registry — recorded by the caller as not fetched
    return None


async def bulk_fetch_npm_times(
    packages: list[tuple[str, str]],   # (name, version)
) -> dict[str, dict | None]:
    """Fetch times for multiple packages concurrently. Returns dict of name → times (None = not fetched)."""
    sem = asyncio.Semaphore(MAX_CONCURRENCY)
    results: dict[str, dict | None] = {}

    async def _fetch(name: str) -> None:
        async with sem:
            results[name] = await fetch_npm_times(name)

    unique_names = list(dict.fromkeys(name for name, _ in packages))
    await asyncio.gather(*[_fetch(n) for n in unique_names])
    return {n: results.get(n) for n in unique_names}
