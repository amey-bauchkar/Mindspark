"""Miscellaneous routes — health, samples, methodology."""
from __future__ import annotations

from fastapi import APIRouter

from ..engine.rules import RULES, ENGINE_PARAMETERS
from ..licenses.rules import LICENSE_RULES_TABLE, COMPANY_POLICIES
from ..config import get_settings

router = APIRouter(prefix="/api")


@router.get("/health")
async def health():
    settings = get_settings()
    return {
        "status": "ok",
        "offline": settings.offline_fixtures,
        "epss_threshold": settings.epss_threshold,
        "freshness_hours": settings.freshness_hours,
        "llm_enabled": bool(settings.llm_api_key),
        "auth_required": bool(settings.warrant_api_key or settings.warrant_read_key),
    }


@router.get("/samples")
async def list_samples():
    return {
        "samples": [
            {
                "id": "slack-action",
                "name": "Sample A: Slack GitHub Action (Real Project)",
                "description": "100% authentic, unmodified lockfile from slackapi/slack-github-action@a8dafde (Lockfile v3, 94 packages).",
                "ecosystem": "npm",
                "badge": "100% REAL",
            },
            {
                "id": "legacy-express",
                "name": "Legacy Express App",
                "description": "Old Express.js app with many known vulnerabilities, deep transitive paths, and a git-URL dependency.",
                "ecosystem": "npm",
            },
            {
                "id": "axios-replay",
                "name": "Incident Replay: Compromised axios (Mar 2026)",
                "description": "Reconstructed lockfile demonstrating the axios/plain-crypto-js malware incident. Evidence is recorded from real OSV/OpenSSF records.",
                "ecosystem": "npm",
                "badge": "REPLAY",
            },
            {
                "id": "python-requirements",
                "name": "Python requirements.txt (limited)",
                "description": "Small pinned requirements.txt — vulnerabilities and licenses work, paths are unknown.",
                "ecosystem": "PyPI",
                "badge": "LIMITED",
            },
        ]
    }


@router.get("/methodology")
async def methodology():
    settings = get_settings()
    return {
        "rules": RULES,
        "license_rules": LICENSE_RULES_TABLE,
        "company_policies": COMPANY_POLICIES,
        "parameters": ENGINE_PARAMETERS,
        "current_parameters": {
            "epss_threshold": settings.epss_threshold,
            "freshness_hours": settings.freshness_hours,
        },
        "evidence_tiers": [
            {"tier": "T1", "name": "Reported", "description": "Named authority reports malicious (OSV MAL-* / OpenSSF) or CISA KEV confirms exploited in the wild."},
            {"tier": "T2", "name": "Advisory", "description": "Vulnerability advisory matching the exact resolved purl@version (OSV/GHSA)."},
            {"tier": "T3", "name": "Heuristic", "description": "Our rules applied to metadata (lookalike names, staleness, very new). Never decisive alone."},
            {"tier": "CONTEXT", "name": "Context", "description": "Scope, depth, install-script flag, user-declared context answers."},
            {"tier": "ABSENT", "name": "Absent", "description": "A check that could not run, with reason. Never treated as 'clean'."},
        ],
        "verdict_definitions": [
            {"verdict": "INCIDENT", "meaning": "Named authority confirms this exact resolved version is malicious. Containment required."},
            {"verdict": "ACT_NOW", "meaning": "Exploited in the wild (KEV) or very high exploitation probability (EPSS ≥ θ) on a production path."},
            {"verdict": "UPGRADE", "meaning": "Vulnerability advisory with a known fix on a production path. Schedule upgrade."},
            {"verdict": "MONITOR", "meaning": "Vulnerability advisory, but only on dev/optional paths. Track and upgrade when convenient."},
            {"verdict": "REVIEW", "meaning": "Heuristic or license signal only. Needs human review — not evidence of malice."},
            {"verdict": "CANNOT_ASSESS", "meaning": "A required check could not run. Not the same as safe."},
            {"verdict": "NO_KNOWN_FINDING", "meaning": "All required checks ran and found nothing. Shown with scope and timestamp — not 'safe'."},
        ],
        "limitations": [
            "Package-level analysis only — function-level reachability is not assessed.",
            "Heuristic signals (lookalike, staleness) have false positives and are never decisive alone.",
            "License flags are for review, not legal advice.",
            "Public data can lag behind actual disclosure.",
            "EPSS threshold and freshness horizon are defaults, not empirically validated.",
            "Only npm package-lock.json (v2/v3) and pinned requirements.txt are supported.",
        ],
        "data_sources": [
            {"name": "OSV", "url": "https://osv.dev", "type": "vulnerabilities, malware reports"},
            {"name": "CISA KEV", "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "type": "exploited vulnerabilities"},
            {"name": "EPSS", "url": "https://www.first.org/epss", "type": "exploitation probability scores"},
            {"name": "deps.dev", "url": "https://deps.dev", "type": "license metadata"},
            {"name": "npm registry", "url": "https://registry.npmjs.org", "type": "publish times, metadata"},
        ],
    }
