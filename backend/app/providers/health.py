"""
Provider health side-channel.

Providers call `report_provider_issue(...)` on their failure paths. Outside a
`collect_provider_issues()` block this is a no-op, so regular analyses behave
exactly as before. Warrant Watch wraps its re-analysis in a collector so that a
provider that could not be checked is recorded as a partial/failed monitoring
check — never silently treated as "nothing changed".
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, asdict
from typing import Iterator

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
    """Record a provider failure for the active monitoring check (no-op otherwise)."""
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
