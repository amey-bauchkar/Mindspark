"""
Tests for report export generators: markdown, HTML, and CSV.
"""
from __future__ import annotations
import json
import pytest
from app.api.routes_reports import _report_to_markdown, _report_to_csv, _report_to_html

SAMPLE_REPORT_DATA = {
    "id": "test-export-1234",
    "created_at": "2026-10-04T00:00:00Z",
    "meta": {"filename": "package-lock.json", "ecosystem": "npm"},
    "summary": {
        "incident": 1,
        "act_now": 0,
        "upgrade": 1,
        "monitor": 0,
        "review": 1,
        "cannot_assess": 0,
        "no_known_finding": 5,
        "total_packages": 8,
        "direct_packages": 2,
        "as_of": "2026-10-04T00:00:00Z",
        "ecosystem": "npm",
        "data_badge": "LIVE",
    },
    "decisions": [
        {
            "name": "malicious-pkg",
            "version": "1.0.0",
            "subject": "pkg:npm/malicious-pkg@1.0.0",
            "verdict": "INCIDENT",
            "urgency": "IMMEDIATE",
            "qualifier": "ESTABLISHED",
            "exposure": {
                "scope": "prod",
                "paths": [["express", "malicious-pkg"]],
            },
            "depth": 2,
            "is_direct": False,
            "what": "Active malware report confirmed by OSV.",
            "derivation": ["R1 <- MAL-2026-999"],
            "evidence_ids": ["MAL-2026-999"],
            "response_steps": [
                {"text": "Revoke leaked tokens and remove package immediately.", "command": "npm uninstall malicious-pkg"}
            ],
        },
        {
            "name": "vulnerable-pkg",
            "version": "2.0.0",
            "subject": "pkg:npm/vulnerable-pkg@2.0.0",
            "verdict": "UPGRADE",
            "urgency": "SCHEDULED",
            "qualifier": "ESTABLISHED",
            "exposure": {
                "scope": "prod",
                "paths": [["vulnerable-pkg"]],
            },
            "depth": 1,
            "is_direct": True,
            "fixed_version": "2.0.1",
            "what": "Known vulnerability advisory with available fix.",
            "derivation": ["R3 <- GHSA-1234"],
            "evidence_ids": ["GHSA-1234"],
            "response_steps": [
                {"text": "Upgrade to version 2.0.1", "command": "npm install vulnerable-pkg@2.0.1"}
            ],
        }
    ],
    "evidence": [
        {
            "id": "MAL-2026-999",
            "tier": "T1",
            "source": "OSV",
            "claim": "Package contains reverse shell payload",
            "url": "https://osv.dev/vulnerability/MAL-2026-999",
            "quote": "Discovered data exfiltration script in postinstall hook.",
        },
        {
            "id": "GHSA-1234",
            "tier": "T2",
            "source": "GHSA",
            "claim": "Prototype pollution via Object.assign",
            "url": "https://github.com/advisories/GHSA-1234",
        }
    ],
    "licenses": [
        {
            "name": "vulnerable-pkg",
            "version": "2.0.0",
            "license_expr": "MIT",
            "license_status": "PERMITTED",
            "note": "Standard permissive license",
        }
    ]
}


def test_report_to_markdown():
    md = _report_to_markdown(SAMPLE_REPORT_DATA)
    assert "# Warrant Security Analysis Report" in md
    assert "malicious-pkg@1.0.0" in md
    assert "INCIDENT" in md
    assert "MAL-2026-999" in md
    assert "npm uninstall malicious-pkg" in md
    assert "MIT" in md
    assert "Executive Findings Summary" in md


def test_report_to_csv():
    csv_str = _report_to_csv(SAMPLE_REPORT_DATA)
    assert "Package,Version,Verdict" in csv_str
    assert "malicious-pkg,1.0.0,INCIDENT" in csv_str
    assert "vulnerable-pkg,2.0.0,UPGRADE" in csv_str
    assert "npm install vulnerable-pkg@2.0.1" in csv_str


def test_report_to_html():
    html_str = _report_to_html(SAMPLE_REPORT_DATA)
    assert "<!DOCTYPE html>" in html_str
    assert "Warrant Security Audit Report" in html_str
    assert "malicious-pkg@1.0.0" in html_str
    assert "INCIDENT" in html_str
    assert "vulnerable-pkg@2.0.0" in html_str
