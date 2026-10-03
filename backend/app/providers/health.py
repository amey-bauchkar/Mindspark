"""
Provider health side-channel.

Providers call `report_provider_issue(...)` on their failure paths. Every call is logged
(structured, without payloads); the provider itself also records the failure in the
analysis as ABSENT evidence. Warrant Watch additionally wraps its re-analysis in a collector
so that a provider that could not be checked makes the monitoring check partial/failed —
never silently "nothing changed".
"""
from __future__ import annotations

import logging
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, asdict
from typing import Iterator

logger = logging.getLogger("warrant.providers")

# Display names used in monitoring status messages.
PROVIDER_NAMES = {
    "osv": "OSV",
    "kev": "CISA KEV",
    "epss": "EPSS",
    "npm-registry": "npm registry",
}


@dataclass
class ProviderIssue:
    provider: str          # "osv" | "kev" | "epss" | "npm-registry"
    detail: str            # Plain-language reason
    scope: str = "partial"  # "batch" (whole query failed) | "record" | "partial" | "not_checked"
    count: int = 0         # Number of subjects affected, when known

    def to_dict(self) -> dict:
        return asdict(self)


_collector: ContextVar[list[ProviderIssue] | None] = ContextVar("warrant_provider_issues", default=None)


def report_provider_issue(provider: str, detail: str, scope: str = "partial", count: int = 0) -> None:
    """Log a provider failure and record it for the active monitoring check, if any."""
    # Structured, content-free: provider, scope and count; never request/response bodies.
    logger.warning("provider check incomplete: %s", detail,
                   extra={"provider": provider, "scope": scope, "count": count})
    issues = _collector.get()
    if issues is not None:
        issues.append(ProviderIssue(provider=provider, detail=detail, scope=scope, count=count))


@contextmanager
def collect_provider_issues() -> Iterator[list[ProviderIssue]]:
    """Collect provider issues raised by any code (including asyncio tasks) run inside this block."""
    issues: list[ProviderIssue] = []
    token = _collector.set(issues)
    try:
        yield issues
    finally:
        _collector.reset(token)
