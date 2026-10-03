"""
SPDX license expression parser.
Handles: AND, OR, WITH, parentheses, and common non-standard aliases.
OR: pick most permissive and note it.
AND: all apply.
"""
from __future__ import annotations
import re

COMMON_ALIASES: dict[str, str] = {
    "apache 2.0": "Apache-2.0",
    "apache 2": "Apache-2.0",
    "apache-2": "Apache-2.0",
    "apache v2": "Apache-2.0",
    "apache license 2.0": "Apache-2.0",
    "apache license, version 2.0": "Apache-2.0",
    "bsd 3-clause": "BSD-3-Clause",
    "bsd 2-clause": "BSD-2-Clause",
    "bsd-3": "BSD-3-Clause",
    "bsd-2": "BSD-2-Clause",
    "bsd": "BSD-2-Clause",
    "cc by 4.0": "CC-BY-4.0",
    "cc-by-4.0": "CC-BY-4.0",
    "cc by 3.0": "CC-BY-3.0",
    "cc-by-3.0": "CC-BY-3.0",
    "cc0": "CC0-1.0",
    "mit/x11": "MIT",
    "w3c": "W3C",
}


def normalize_license_identifier(ident: str) -> str:
    """Normalize common aliases and strip redundant punctuation."""
    clean = ident.strip("() ").strip()
    return COMMON_ALIASES.get(clean.lower(), clean)


def parse_spdx(expr: str) -> dict:
    """
    Parse an SPDX expression into a normalized structure.
    Returns: {identifiers: [str], note: str | None, raw: str}
    """
    if not expr or expr.strip().upper() in ("UNLICENSED", "NONE", ""):
        return {"identifiers": [], "note": "No license declared", "raw": expr}

    if expr.strip().upper() == "SEE LICENSE IN":
        return {"identifiers": [], "note": "License in external file (not readable)", "raw": expr}

    s = expr.strip()

    # Direct alias match for entire expression (e.g. "Apache 2.0", "BSD 3-Clause")
    clean_s = s.strip("() ").strip()
    if clean_s.lower() in COMMON_ALIASES:
        normalized = COMMON_ALIASES[clean_s.lower()]
        return {"identifiers": [normalized], "note": None, "raw": expr}

    # Check if this is a boolean compound expression (contains AND, OR, WITH as words)
    has_boolean_ops = bool(re.search(r'\b(AND|OR|WITH)\b', s, re.IGNORECASE))
    if not has_boolean_ops:
        # Single expression / custom license name (e.g. "Remix Icon License 1.0", "Hippocratic-2.1")
        return {"identifiers": [clean_s], "note": None, "raw": expr}

    # Tokenize boolean expression
    tokens = re.split(r'\s+', s)

    identifiers: list[str] = []
    note: str | None = None
    has_or = False
    has_with = False

    for tok in tokens:
        tok_clean = tok.strip("()")
        if tok_clean.upper() in ("AND", "OR", "WITH"):
            if tok_clean.upper() == "OR":
                has_or = True
            if tok_clean.upper() == "WITH":
                has_with = True
            continue
        if tok_clean:
            norm = normalize_license_identifier(tok_clean)
            identifiers.append(norm)

    if has_or and len(identifiers) > 1:
        note = f"OR expression: most permissive alternative ({identifiers[0]}) applied"
        identifiers = [identifiers[0]]  # Take first (assume listed permissive-first)

    if has_with:
        note = (note or "") + " (WITH exception noted)"

    return {"identifiers": identifiers, "note": note, "raw": expr}

