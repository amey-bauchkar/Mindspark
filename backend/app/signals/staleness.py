"""Staleness and freshness signals (T3, REVIEW only)."""
from __future__ import annotations

from datetime import datetime, timezone, timedelta

from ..models.evidence import EvidenceRecord, EvidenceTier, EvidenceKind
from ..config import get_settings

STALE_YEARS = 2
VERY_NEW_DAYS = 30


def check_staleness(name: str, version: str, npm_times: dict | None) -> list[EvidenceRecord]:
    """Return T3 evidence records for stale or very new packages."""
    if not npm_times:
        return []

    now = datetime.now(timezone.utc)
    purl = f"pkg:npm/{name.replace('@', '%40').replace('/', '%2F')}@{version}"
    records: list[EvidenceRecord] = []

    # Version-specific publish time
    version_time_str = npm_times.get(version)
    # Package created time
    created_str = npm_times.get("created")

    # Freshness: very new
    settings = get_settings()
    freshness_hours = settings.freshness_hours
    if version_time_str:
        try:
            version_time = datetime.fromisoformat(version_time_str.replace("Z", "+00:00"))
            age_hours = (now - version_time).total_seconds() / 3600
            if age_hours < freshness_hours:
                records.append(EvidenceRecord(
                    id=f"FRESH-{name[:20].replace('/', '-').replace('@', '')}",
                    tier=EvidenceTier.T3,
                    source="npm-registry",
                    origin="npm registry",
                    kind=EvidenceKind.VERY_NEW,
                    subject=purl,
                    claim=f"Version {version} published {age_hours:.0f}h ago — very new package version (< {freshness_hours}h freshness horizon).",
                    retrieved_at=now,
                    published_at=version_time,
                    data={"version_time": version_time_str, "age_hours": age_hours},
                ))
        except Exception:
            pass

    # Staleness: last publish
    # Find the most recent version publish time
    skip_keys = {"created", "modified"}
    version_times = {k: v for k, v in npm_times.items() if k not in skip_keys}
    if version_times:
        latest_str = max(version_times.values())
        try:
            latest_time = datetime.fromisoformat(latest_str.replace("Z", "+00:00"))
            age_days = (now - latest_time).days
            if age_days > STALE_YEARS * 365:
                records.append(EvidenceRecord(
                    id=f"STALE-{name[:20].replace('/', '-').replace('@', '')}",
                    tier=EvidenceTier.T3,
                    source="npm-registry",
                    origin="npm registry",
                    kind=EvidenceKind.STALE,
                    subject=purl,
                    claim=f"Possibly unmaintained — last release was {latest_time.year} ({age_days // 365} years ago).",
                    retrieved_at=now,
                    published_at=latest_time,
                    data={"last_publish": latest_str, "age_days": age_days},
                ))
        except Exception:
            pass

    return records


def check_install_script(name: str, version: str, has_install_script: bool) -> list[EvidenceRecord]:
    """Flag packages with install scripts as CONTEXT evidence."""
    if not has_install_script:
        return []
    purl = f"pkg:npm/{name.replace('@', '%40').replace('/', '%2F')}@{version}"
    return [EvidenceRecord(
        id=f"INST-{name[:20].replace('/', '-').replace('@', '')}",
        tier=EvidenceTier.CONTEXT,
        source="lockfile",
        origin="lockfile",
        kind=EvidenceKind.INSTALL_SCRIPT,
        subject=purl,
        claim=f"Package declares an install script (hasInstallScript: true). Runs during npm install.",
        retrieved_at=datetime.now(timezone.utc),
        data={"has_install_script": True},
    )]
