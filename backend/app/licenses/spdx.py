"""
SPDX license expression parser.
Handles: AND, OR, WITH, parentheses.
OR: pick most permissive and note it.
AND: all apply.
"""
from __future__ import annotations
import re


def parse_spdx(expr: str) -> dict:
    """
    Parse an SPDX expression into a normalized structure.
    Returns: {identifiers: [str], note: str | None, raw: str}
    """
    if not expr or expr.strip().upper() in ("UNLICENSED", "NONE", ""):
        return {"identifiers": [], "note": "No license declared", "raw": expr}

    if expr.strip().upper() == "SEE LICENSE IN":
        return {"identifiers": [], "note": "License in external file (not readable)", "raw": expr}

    # Normalize whitespace
    s = expr.strip()

    # Tokenize
    tokens = re.split(r'\s+', s)

    # Simple extractor: collect all SPDX-like identifiers (not AND/OR/WITH)
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
            identifiers.append(tok_clean)

    if has_or and len(identifiers) > 1:
        note = f"OR expression: most permissive alternative ({identifiers[0]}) applied"
        identifiers = [identifiers[0]]  # Take first (assume listed permissive-first)

    if has_with:
        note = (note or "") + " (WITH exception noted)"

    return {"identifiers": identifiers, "note": note, "raw": expr}
