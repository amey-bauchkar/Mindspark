"""
Version ordering for selecting an advisory's fixed version.

Only used to decide WHICH of an advisory's published `fixed` versions applies to the exact
installed version (OSV records often carry several ranges, e.g. a 0.x and a 1.x line).
Matching an advisory to a version is still done by OSV itself; nothing here decides whether
a version is affected.
"""
from __future__ import annotations

import re

# Single-quantifier groups only (no nested repetition), so matching is linear-time.
_SEMVER_RE = re.compile(
    r"^v?(\d{1,9})(?:\.(\d{1,9}))?(?:\.(\d{1,9}))?(?:\.(\d{1,9}))?"
    r"(?:[-.]?([A-Za-z0-9][A-Za-z0-9.-]{0,40}))?(?:\+[A-Za-z0-9.-]{1,40})?$"
)


def version_key(version: str | None) -> tuple | None:
    """
    Sortable key for semver-like versions ("1.2.3", "1.2.3-beta.1", "2.19", PEP 440 "2.0.0rc1").
    Pre-releases sort before their release. Returns None if the string is not version-like.
    """
    if not version or len(version) > 64:
        return None
    if version == "0":  # OSV "introduced: 0" — before every version
        return ((0, 0, 0, 0), 0, ())
    m = _SEMVER_RE.match(version.strip())
    if not m:
        return None
    release = tuple(int(x) if x is not None else 0 for x in m.group(1, 2, 3, 4))
    pre = m.group(5)
    if not pre:
        return (release, 1, ())
    idents = tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in re.split(r"[.-]", pre) if p)
    return (release, 0, idents)


def _same_name(a: str, b: str, ecosystem: str) -> bool:
    if ecosystem == "PyPI":
        norm = lambda n: re.sub(r"[-_.]+", "-", n).lower()
        return norm(a) == norm(b)
    return a == b


def select_fixed_version(detail: dict, name: str, version: str, ecosystem: str) -> str | None:
    """
    The fixed version that applies to `version`:
    1. the `fixed` event closing the SEMVER/ECOSYSTEM range that contains the version;
    2. otherwise the lowest published fix above the version;
    3. if the versions cannot be ordered, the first published fix (previous behaviour).
    Returns None when no fix above the installed version exists — never a downgrade.
    """
    current = version_key(version)
    fixes: list[str] = []
    for affected in detail.get("affected") or []:
        if not isinstance(affected, dict):
            continue
        pkg_name = (affected.get("package") or {}).get("name")
        if pkg_name and name and not _same_name(pkg_name, name, ecosystem):
            continue
        for rng in affected.get("ranges") or []:
            if not isinstance(rng, dict) or rng.get("type") not in ("SEMVER", "ECOSYSTEM"):
                continue
            introduced = None
            for evt in rng.get("events") or []:
                if not isinstance(evt, dict):
                    continue
                if "introduced" in evt:
                    introduced = str(evt["introduced"])
                elif "fixed" in evt:
                    fixed = str(evt["fixed"])
                    fixes.append(fixed)
                    lo, hi = version_key(introduced), version_key(fixed)
                    if current is not None and lo is not None and hi is not None and lo <= current < hi:
                        return fixed
                    introduced = None
                elif "last_affected" in evt or "limit" in evt:
                    introduced = None
    if not fixes:
        return None
    if current is None:
        return fixes[0]
    above = [f for f in fixes if (k := version_key(f)) is not None and k > current]
    if above:
        return min(above, key=version_key)
    if all(version_key(f) is not None for f in fixes):
        return None  # Every published fix is at or below the installed version
    return fixes[0]
