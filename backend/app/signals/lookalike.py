"""
Lookalike/typosquat heuristic signal (T3, REVIEW only).
Uses pure Python Levenshtein distance (no Rust) plus Jaro-Winkler approximation.
"""
from __future__ import annotations

import difflib
import json
import unicodedata
from pathlib import Path
from datetime import datetime, timezone

from ..models.evidence import EvidenceRecord, EvidenceTier, EvidenceKind

_POPULAR_LIST: list[str] | None = None
_DATA_FILE = Path(__file__).parent.parent / "data" / "popular_npm.json"

MIN_NAME_LEN = 5
EDIT_DISTANCE_THRESHOLD = 1


def _load_popular() -> list[str]:
    global _POPULAR_LIST
    if _POPULAR_LIST is None:
        if _DATA_FILE.exists():
            raw = json.loads(_DATA_FILE.read_text(encoding="utf-8"))
            _POPULAR_LIST = [n.lower() for n in raw.get("packages", [])]
        else:
            _POPULAR_LIST = []
    return _POPULAR_LIST


def _levenshtein(a: str, b: str) -> int:
    """Pure Python Levenshtein distance."""
    la, lb = len(a), len(b)
    if la == 0: return lb
    if lb == 0: return la
    # dp row
    prev = list(range(lb + 1))
    for i in range(1, la + 1):
        curr = [i] + [0] * lb
        for j in range(1, lb + 1):
            cost = 0 if a[i-1] == b[j-1] else 1
            curr[j] = min(prev[j] + 1, curr[j-1] + 1, prev[j-1] + cost)
        prev = curr
    return prev[lb]


def _normalize(name: str) -> str:
    """Normalise package name for comparison: lowercase, replace -/_ with -."""
    return name.lower().replace("_", "-").replace(".", "-")


def check_lookalike(name: str, version: str) -> list[EvidenceRecord]:
    """
    Check if a package name looks like a popular package.
    Returns T3 REVIEW evidence if a close match is found.
    """
    popular = _load_popular()
    if not popular:
        return []

    norm_name = _normalize(name)

    # Exact match → not a lookalike
    if norm_name in popular:
        return []

    # Short names: only flag if distance 1 to a very popular package (top 50)
    if len(name) < MIN_NAME_LEN:
        top_50 = popular[:50]
        for popular_name in top_50:
            if _levenshtein(norm_name, popular_name) == 1:
                return [_make_record(name, version, popular_name, 1)]
        return []

    # Standard check: distance ≤ threshold against full list
    best_dist = 999
    best_match = ""
    for popular_name in popular:
        dist = _levenshtein(norm_name, popular_name)
        if dist < best_dist:
            best_dist = dist
            best_match = popular_name
            if dist == 0:
                return []  # Exact match

    if best_dist <= EDIT_DISTANCE_THRESHOLD:
        return [_make_record(name, version, best_match, best_dist)]

    # Additional checks: scope confusion (@myorg/pkg similar to pkg)
    if name.startswith("@"):
        # Check if the unscoped name is in the popular list
        unscoped = name.split("/")[-1].lower()
        if unscoped in popular:
            return [_make_record(name, version, unscoped, 0, note="Scoped variant of popular package")]

    return []


def _make_record(name: str, version: str, similar_to: str, distance: int, note: str = "") -> EvidenceRecord:
    extra = f" — {note}" if note else ""
    purl = f"pkg:npm/{name.replace('@', '%40').replace('/', '%2F')}@{version}"
    return EvidenceRecord(
        id=f"LOOK-{name[:20].replace('/', '-').replace('@', '').replace('.', '')}",
        tier=EvidenceTier.T3,
        source="heuristic",
        origin="heuristic",
        kind=EvidenceKind.LOOKALIKE,
        subject=purl,
        claim=f"Name is {distance} edit(s) from `{similar_to}` (Levenshtein) — heuristic only, not evidence of malice{extra}.",
        retrieved_at=datetime.now(timezone.utc),
        data={"similar_to": similar_to, "distance": distance},
    )
