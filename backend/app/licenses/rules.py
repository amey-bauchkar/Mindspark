"""
License rule engine — classifies licenses given project context.
Rule table is defined as DATA (referenced by /methodology).
"""
from __future__ import annotations

import json
from pathlib import Path

from ..models.report import AnalysisContext, DistributionMode, ProjectLicense, LicenseResult
from .spdx import parse_spdx

# Load company policies dataset
DATA_DIR = Path(__file__).parent.parent / "data"
POLICIES_FILE = DATA_DIR / "company_policies.json"
COMPANY_POLICIES: dict[str, dict] = {}
if POLICIES_FILE.exists():
    try:
        COMPANY_POLICIES = json.loads(POLICIES_FILE.read_text(encoding="utf-8")).get("policies", {})
    except Exception:
        COMPANY_POLICIES = {}


# ─── Rule table (data) ─────────────────────────────────────────────────────────
# Each rule: {id, description, license_patterns, status_fn}
# status_fn(dist_mode, proj_license) -> ("OK"|"CONFLICT"|"REVIEW"|"UNKNOWN"|"CANNOT_ASSESS", note)

PERMISSIVE = frozenset([
    "MIT", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Apache-2.0",
    "0BSD", "Unlicense", "CC0-1.0", "BlueOak-1.0.0",
])

WEAK_COPYLEFT = frozenset([
    "LGPL-2.0-only", "LGPL-2.0-or-later", "LGPL-2.1-only", "LGPL-2.1-or-later",
    "LGPL-3.0-only", "LGPL-3.0-or-later", "MPL-2.0", "EPL-1.0", "EPL-2.0",
    "CDDL-1.0",
])

STRONG_COPYLEFT = frozenset([
    "GPL-2.0-only", "GPL-2.0-or-later", "GPL-3.0-only", "GPL-3.0-or-later",
])

AGPL = frozenset(["AGPL-3.0-only", "AGPL-3.0-or-later", "AGPL-3.0"])

SOURCE_AVAILABLE = frozenset([
    "SSPL-1.0", "BUSL-1.1", "Elastic-2.0", "Commons-Clause",
    "PolyForm-Noncommercial-1.0.0", "PolyForm-Small-Business-1.0.0",
])

_DISTRIBUTED = {DistributionMode.DISTRIBUTED, DistributionMode.OPEN_SOURCE}
_SAAS_OR_DIST = {DistributionMode.SAAS, DistributionMode.DISTRIBUTED, DistributionMode.OPEN_SOURCE}


# Exported rule table for /methodology
LICENSE_RULES_TABLE = [
    {
        "id": "LR1", "category": "Permissive",
        "examples": "MIT, BSD-2/3-Clause, ISC, Apache-2.0, 0BSD, Unlicense, CC0-1.0",
        "status": "OK", "condition": "Any use",
        "note": "Permissive — no copyleft obligations in most cases",
    },
    {
        "id": "LR2", "category": "Weak copyleft",
        "examples": "LGPL-*, MPL-2.0, EPL-*",
        "status": "REVIEW if distributed, OK otherwise",
        "condition": "Distribution",
        "note": "May require disclosing modifications to the library",
    },
    {
        "id": "LR3", "category": "Strong copyleft (GPL)",
        "examples": "GPL-2.0-only, GPL-2.0-or-later, GPL-3.0-*",
        "status": "CONFLICT if Proprietary + distributed; REVIEW otherwise",
        "condition": "Proprietary project distributing the software",
        "note": "Copyleft may require releasing source of the whole application",
    },
    {
        "id": "LR4", "category": "AGPL",
        "examples": "AGPL-3.0",
        "status": "CONFLICT if Proprietary + (SaaS or distributed); REVIEW otherwise",
        "condition": "Proprietary project distributing or serving the software",
        "note": "Network use may trigger copyleft obligations",
    },
    {
        "id": "LR5", "category": "GPL-2.0-only + Apache-2.0 project",
        "examples": "GPL-2.0-only",
        "status": "CONFLICT",
        "condition": "Apache-2.0 project license (incompatible copyleft terms)",
        "note": "GPL-2.0 and Apache-2.0 are license-incompatible",
    },
    {
        "id": "LR6", "category": "Source-available",
        "examples": "SSPL, BUSL, Commons-Clause, Elastic",
        "status": "REVIEW",
        "condition": "Any use",
        "note": "Not OSI-approved; commercial use restrictions may apply",
    },
    {
        "id": "LR7", "category": "Unlicensed / missing",
        "examples": "UNLICENSED, SEE LICENSE IN, (blank)",
        "status": "REVIEW (no license declared) or CANNOT_ASSESS (unreadable)",
        "condition": "Any",
        "note": "No license = all rights reserved by default",
    },
    {
        "id": "LR8", "category": "Corporate Policy Banned License",
        "examples": "AGPL at Google, GPL at Apache (Category X), SSPL, Commons Clause, Non-Commercial",
        "status": "CONFLICT if banned by company policy",
        "condition": "Corporate policy active (Google, Apache Foundation, Meta, Microsoft)",
        "note": "Prohibited by corporate open-source compliance policy",
    },
    {
        "id": "LR-BANNED-PKG", "category": "Organization Banned Dependency",
        "examples": "Explicitly blacklisted package names or specs",
        "status": "CONFLICT",
        "condition": "Listed in organization banned dependencies list",
        "note": "Forbidden by internal security or architecture blacklist",
    },
]


def classify_license(
    license_expr: str | None,
    context: AnalysisContext,
    package_name: str | None = None,
    package_version: str | None = None,
) -> tuple[str, str, str]:
    """
    Returns (status, rule_id, note).
    status: "OK" | "CONFLICT" | "REVIEW" | "UNKNOWN" | "CANNOT_ASSESS"
    """
    # 1. Check custom banned dependencies blacklist
    if package_name and context.banned_dependencies:
        clean_name = package_name.lower().strip()
        clean_version = (package_version or "").lower().strip()
        pkg_full = f"{clean_name}@{clean_version}" if clean_version else clean_name
        for banned_pat in context.banned_dependencies:
            clean_pat = banned_pat.lower().strip()
            if not clean_pat:
                continue
            # Exact match on package name or package@version
            if clean_pat == clean_name or clean_pat == pkg_full:
                display_pkg = f"{package_name}@{package_version}" if package_version else package_name
                return "CONFLICT", "LR-BANNED-PKG", f"Package '{display_pkg}' is explicitly BANNED by organization dependency policy."
            if "@" in clean_pat:
                pat_name, pat_ver = clean_pat.split("@", 1)
                if pat_name == clean_name and (not clean_version or pat_ver == clean_version):
                    display_pkg = f"{package_name}@{package_version}" if package_version else package_name
                    return "CONFLICT", "LR-BANNED-PKG", f"Package '{display_pkg}' is explicitly BANNED by organization dependency policy."

    if not license_expr or license_expr.strip() == "":
        return "REVIEW", "LR7", "No license declared — all rights reserved by default. Flag for review."

    parsed = parse_spdx(license_expr)
    identifiers = parsed["identifiers"]
    parse_note = parsed.get("note", "")

    if not identifiers:
        note_str = license_expr.strip()
        if note_str.upper() in ("UNLICENSED", "NONE"):
            return "REVIEW", "LR7", "Unlicensed — no license granted."
        return "CANNOT_ASSESS", "LR7", f"Cannot parse license expression: {license_expr!r}"

    # 2. Check Corporate Policy preset (e.g. Google, Apache Foundation, Meta, Microsoft)
    policy = None
    if context.company_policy:
        company_key = context.company_policy.lower().strip()
        policy = COMPANY_POLICIES.get(company_key)
        # Fallback partial match (e.g. "google llc" -> "google")
        if not policy:
            for k, p in COMPANY_POLICIES.items():
                if k in company_key or company_key in k:
                    policy = p
                    break

    dist = context.distribution_mode
    proj_lic = context.project_license

    results: list[tuple[str, str, str]] = []
    for ident in identifiers:
        results.append(_classify_one(ident, dist, proj_lic, policy))

    # Return worst result
    priority = ["CONFLICT", "CANNOT_ASSESS", "REVIEW", "UNKNOWN", "OK"]
    best = max(results, key=lambda r: priority.index(r[0]) if r[0] in priority else 99)
    # Prepend parse note if any
    note = (parse_note + " | " if parse_note else "") + best[2]
    return best[0], best[1], note


def _classify_one(
    ident: str,
    dist: DistributionMode,
    proj_lic: ProjectLicense,
    policy: dict | None = None,
) -> tuple[str, str, str]:
    # Check company policy first
    if policy:
        banned_list = policy.get("banned_licenses", [])
        if ident in banned_list or any(ident.upper() == b.upper() for b in banned_list):
            return "CONFLICT", "LR8", f"BANNED by {policy.get('short_name', 'Company')} Policy: {ident} is prohibited ({policy.get('banned_rationale', 'Prohibited license')})"
        restricted_list = policy.get("restricted_licenses", [])
        if ident in restricted_list or any(ident.upper() == r.upper() for r in restricted_list):
            return "REVIEW", "LR8", f"Restricted by {policy.get('short_name', 'Company')} Policy: {ident} ({policy.get('restricted_condition', 'Requires review')})"

    if ident in PERMISSIVE:
        return "OK", "LR1", f"Permissive ({ident}) — no copyleft obligations."

    if ident in WEAK_COPYLEFT:
        if dist in _DISTRIBUTED:
            return "REVIEW", "LR2", f"Weak copyleft ({ident}) — may require disclosing modifications if distributing."
        return "OK", "LR2", f"Weak copyleft ({ident}) — OK for internal/SaaS use."

    if ident in STRONG_COPYLEFT:
        # GPL-2.0-only + Apache-2.0 → incompatible
        if ident == "GPL-2.0-only" and proj_lic == ProjectLicense.APACHE2:
            return "CONFLICT", "LR5", f"GPL-2.0-only is incompatible with Apache-2.0 project license."
        if proj_lic == ProjectLicense.PROPRIETARY and dist in _DISTRIBUTED:
            return "CONFLICT", "LR3", f"Strong copyleft ({ident}) may require releasing your source code."
        return "REVIEW", "LR3", f"Strong copyleft ({ident}) — review needed for your distribution mode."

    if ident in AGPL:
        if proj_lic == ProjectLicense.PROPRIETARY and dist in _SAAS_OR_DIST:
            return "CONFLICT", "LR4", f"AGPL ({ident}) — network/distribution use may trigger copyleft for proprietary projects."
        return "REVIEW", "LR4", f"AGPL ({ident}) — review needed."

    if ident in SOURCE_AVAILABLE:
        return "REVIEW", "LR6", f"Source-available license ({ident}) — not OSI-approved; check commercial use terms."

    # Unknown/unrecognised SPDX identifier
    return "UNKNOWN", "LR7", f"Unrecognised license identifier: {ident!r}"
