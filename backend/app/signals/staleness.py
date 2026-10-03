"""
Staleness, freshness, and deprecation signals (T3, REVIEW only).
Handles scoped packages, robust ISO time parsing, and registry deprecation payloads.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from ..models.evidence import EvidenceRecord, EvidenceTier, EvidenceKind
from ..config import get_settings

STALE_YEARS = 2
VERY_NEW_DAYS = 30


def _parse_iso_datetime(dt_val: Any) -> datetime | None:
    """Safely parse various datetime formats or ISO strings."""
    if not dt_val:
        return None
    if isinstance(dt_val, datetime):
        return dt_val if dt_val.tzinfo else dt_val.replace(tzinfo=timezone.utc)
    if isinstance(dt_val, str):
        try:
            # Replace Z with +00:00 for fromisoformat compatibility
            clean_str = dt_val.strip().replace("Z", "+00:00")
            dt = datetime.fromisoformat(clean_str)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            pass
    return None


def _make_purl(name: str, version: str) -> str:
    """Generate RFC-compliant Package URL (purl)."""
    encoded_name = name.replace("@", "%40").replace("/", "%2F")
    return f"pkg:npm/{encoded_name}@{version}"


def check_staleness(
    name: str,
    version: str,
    npm_times: dict[str, Any] | None = None,
    deprecated: str | bool | None = None,
) -> list[EvidenceRecord]:
    """
    Evaluate registry time metadata and deprecation flags for a package.
    Returns T3 evidence records for stale, very new, or deprecated packages.
    """
    records: list[EvidenceRecord] = []
    now = datetime.now(timezone.utc)
    purl = _make_purl(name, version)
    sanitized_id = re.sub(r'[^a-zA-Z0-9_-]', '', name)[:24]

    # 1. Deprecation check
    if deprecated:
        dep_msg = str(deprecated) if isinstance(deprecated, str) else "Package has been marked deprecated by maintainer."
        records.append(
            EvidenceRecord(
                id=f"DEP-{sanitized_id}",
                tier=EvidenceTier.T3,
                source="npm-registry",
                origin="npm registry",
                kind=EvidenceKind.STALE,
                subject=purl,
                claim=f"Package is deprecated: {dep_msg}",
                retrieved_at=now,
                data={"deprecated": True, "message": dep_msg},
            )
        )

    if not npm_times or not isinstance(npm_times, dict):
        return records

    # 2. Freshness check: very new release
    version_time_str = npm_times.get(version)
    settings = get_settings()
    freshness_hours = getattr(settings, "freshness_hours", 72)

    if version_time_str:
        version_time = _parse_iso_datetime(version_time_str)
        if version_time:
            age_hours = (now - version_time).total_seconds() / 3600
            if 0 <= age_hours < freshness_hours:
                records.append(
                    EvidenceRecord(
                        id=f"FRESH-{sanitized_id}",
                        tier=EvidenceTier.T3,
                        source="npm-registry",
                        origin="npm registry",
                        kind=EvidenceKind.VERY_NEW,
                        subject=purl,
                        claim=f"Version {version} published {age_hours:.0f}h ago — very new package version (< {freshness_hours}h freshness horizon).",
                        retrieved_at=now,
                        published_at=version_time,
                        data={"version_time": version_time_str, "age_hours": age_hours},
                    )
                )

    # 3. Staleness check: last release date
    skip_keys = {"created", "modified"}
    version_time_entries = []
    for k, v in npm_times.items():
        if k not in skip_keys and v:
            dt = _parse_iso_datetime(v)
            if dt:
                version_time_entries.append((dt, v))

    if version_time_entries:
        latest_time, latest_str = max(version_time_entries, key=lambda item: item[0])
        age_days = (now - latest_time).days
        if age_days > STALE_YEARS * 365:
            records.append(
                EvidenceRecord(
                    id=f"STALE-{sanitized_id}",
                    tier=EvidenceTier.T3,
                    source="npm-registry",
                    origin="npm registry",
                    kind=EvidenceKind.STALE,
                    subject=purl,
                    claim=f"Possibly unmaintained — last release was {latest_time.year} ({age_days // 365} years ago).",
                    retrieved_at=now,
                    published_at=latest_time,
                    data={"last_publish": latest_str, "age_days": age_days},
                )
            )

    return records


def check_install_script(name: str, version: str, has_install_script: bool) -> list[EvidenceRecord]:
    """Flag packages with install scripts as CONTEXT evidence."""
    if not has_install_script:
        return []

    purl = _make_purl(name, version)
    sanitized_id = re.sub(r'[^a-zA-Z0-9_-]', '', name)[:24]

    return [
        EvidenceRecord(
            id=f"INST-{sanitized_id}",
            tier=EvidenceTier.CONTEXT,
            source="lockfile",
            origin="lockfile",
            kind=EvidenceKind.INSTALL_SCRIPT,
            subject=purl,
            claim="Package declares an install script (hasInstallScript: true). Runs during npm install.",
            retrieved_at=datetime.now(timezone.utc),
            data={"has_install_script": True},
        )
    ]
