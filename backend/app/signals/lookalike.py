"""
Lookalike/typosquat heuristic signal (T3, REVIEW only).
Uses pure Python Levenshtein distance, scope-squatting detection, and official scope whitelisting.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from datetime import datetime, timezone

from ..models.evidence import EvidenceRecord, EvidenceTier, EvidenceKind

_POPULAR_LIST: list[str] | None = None
_DATA_FILE = Path(__file__).parent.parent / "data" / "popular_npm.json"

MIN_NAME_LEN = 5
EDIT_DISTANCE_THRESHOLD = 1

# Well-known, official ecosystem namespaces that should not trigger scope-squat warnings
KNOWN_OFFICIAL_SCOPES = {
    "@types",
    "@babel",
    "@angular",
    "@nestjs",
    "@azure",
    "@aws-sdk",
    "@google-cloud",
    "@octokit",
    "@vitejs",
    "@vue",
    "@testing-library",
    "@prisma",
    "@rollup",
    "@swc",
    "@tailwindcss",
    "@emotion",
    "@reduxjs",
    "@fontsource",
    "@mui",
    "@material-ui",
    "@react-spring",
    "@eslint",
    "@jest",
    "@storybook",
    "@trpc",
    "@fastify",
    "@shadcn",
    "@radix-ui",
    "@next",
    "@nuxt",
    "@sveltejs",
    "@open-telemetry",
    "@grpc",
}


def _load_popular() -> list[str]:
    global _POPULAR_LIST
    if _POPULAR_LIST is None:
        if _DATA_FILE.exists():
            try:
                raw = json.loads(_DATA_FILE.read_text(encoding="utf-8"))
                _POPULAR_LIST = [str(n).lower() for n in raw.get("packages", [])]
            except Exception:
                _POPULAR_LIST = []
        else:
            _POPULAR_LIST = []
    return _POPULAR_LIST


def _levenshtein(a: str, b: str) -> int:
    """Pure Python Levenshtein distance."""
    la, lb = len(a), len(b)
    if la == 0:
        return lb
    if lb == 0:
        return la
    prev = list(range(lb + 1))
    for i in range(1, la + 1):
        curr = [i] + [0] * lb
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            curr[j] = min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost)
        prev = curr
    return prev[lb]


def _normalize(name: str) -> str:
    """Normalise package name for comparison: lowercase, replace -/_ with -."""
    return name.lower().replace("_", "-").replace(".", "-")


def _split_scope(name: str) -> tuple[str | None, str]:
    """
    Split a package name into (scope, base_name).
    Examples:
      "@plain/crypto-js" -> ("@plain", "crypto-js")
      "@types/node"      -> ("@types", "node")
      "express"          -> (None, "express")
    """
    if name.startswith("@") and "/" in name:
        parts = name.split("/", 1)
        return parts[0].lower(), parts[1].lower()
    return None, name.lower()


def check_lookalike(name: str, version: str) -> list[EvidenceRecord]:
    """
    Check if a package name looks like a popular package or attempts scope-squatting.
    Returns T3 REVIEW evidence if a close match or malicious scope imitation is found.
    """
    popular = _load_popular()
    if not popular:
        return []

    norm_full = _normalize(name)
    scope, base_name = _split_scope(name)
    norm_base = _normalize(base_name)

    # 1. Exact match on full name -> not a lookalike
    if norm_full in popular:
        return []

    # 2. Scoped package analysis
    if scope is not None:
        # Check if the base name alone matches a popular package (e.g. @plain/crypto-js imitating crypto-js)
        if norm_base in popular:
            # If the scope is an official recognized namespace (e.g. @types/react, @babel/core), allow it
            if scope in KNOWN_OFFICIAL_SCOPES:
                return []
            return [
                _make_record(
                    name,
                    version,
                    similar_to=norm_base,
                    distance=0,
                    note=f"Scoped imitation/squat of popular package '{norm_base}' under unauthorized scope '{scope}'",
                )
            ]

        # If base name is a typo of a popular package (e.g. @attacker/expres)
        for popular_name in popular:
            # Only compare base to unscoped popular packages
            if not popular_name.startswith("@"):
                dist = _levenshtein(norm_base, _normalize(popular_name))
                if dist == 1 and len(norm_base) >= MIN_NAME_LEN:
                    return [
                        _make_record(
                            name,
                            version,
                            similar_to=popular_name,
                            distance=dist,
                            note=f"Scoped package base '{norm_base}' is {dist} edit from popular package '{popular_name}'",
                        )
                    ]

        # If scope is official, do not perform aggressive cross-name fuzzy matching
        if scope in KNOWN_OFFICIAL_SCOPES:
            return []

    # 3. Unscoped package checks
    # Short names: only flag if distance 1 to top 50 very popular packages
    if len(norm_full) < MIN_NAME_LEN:
        top_50 = popular[:50]
        for popular_name in top_50:
            if not popular_name.startswith("@") and _levenshtein(norm_full, _normalize(popular_name)) == 1:
                return [_make_record(name, version, popular_name, 1)]
        return []

    # Standard check: distance <= EDIT_DISTANCE_THRESHOLD against popular list
    best_dist = 999
    best_match = ""
    for popular_name in popular:
        if popular_name.startswith("@") and not name.startswith("@"):
            continue
        dist = _levenshtein(norm_full, _normalize(popular_name))
        if dist < best_dist:
            best_dist = dist
            best_match = popular_name
            if dist == 0:
                return []  # Exact match

    if best_dist <= EDIT_DISTANCE_THRESHOLD:
        return [_make_record(name, version, best_match, best_dist)]

    return []


def _make_record(name: str, version: str, similar_to: str, distance: int, note: str = "") -> EvidenceRecord:
    extra = f" — {note}" if note else ""
    encoded_purl_name = name.replace("@", "%40").replace("/", "%2F")
    purl = f"pkg:npm/{encoded_purl_name}@{version}"
    sanitized_id = re.sub(r'[^a-zA-Z0-9_-]', '', name)[:24]

    if distance == 0:
        claim = f"Scoped name '{name}' directly matches popular package `{similar_to}` — possible scope-squatting or dependency confusion{extra}."
    else:
        claim = f"Name '{name}' is {distance} edit(s) from `{similar_to}` (Levenshtein) — heuristic only, not evidence of malice{extra}."

    return EvidenceRecord(
        id=f"LOOK-{sanitized_id}",
        tier=EvidenceTier.T3,
        source="heuristic",
        origin="heuristic",
        kind=EvidenceKind.LOOKALIKE,
        subject=purl,
        claim=claim,
        retrieved_at=datetime.now(timezone.utc),
        data={"similar_to": similar_to, "distance": distance, "note": note},
    )
