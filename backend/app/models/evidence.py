"""Evidence record models — the atomic unit of every verdict."""
from __future__ import annotations
from enum import Enum
from typing import Any, Literal
from pydantic import BaseModel, Field
from datetime import datetime


class EvidenceTier(str, Enum):
    T1 = "T1"          # Named authority report (malware / KEV)
    T2 = "T2"          # Vulnerability advisory matching exact version
    T3 = "T3"          # Heuristic (lookalike, stale, very new)
    CONTEXT = "CONTEXT" # Scope, depth, install-script flag, user answers
    ABSENT = "ABSENT"   # A check that could not run


class EvidenceKind(str, Enum):
    MALWARE_REPORT = "malware_report"
    ADVISORY = "advisory"
    KEV = "kev"
    EPSS = "epss"
    LOOKALIKE = "lookalike"
    STALE = "stale"
    VERY_NEW = "very_new"
    LICENSE = "license"
    INSTALL_SCRIPT = "install_script"
    SCOPE = "scope"
    UNRESOLVED_SOURCE = "unresolved_source"
    UNRESOLVED_EDGES = "unresolved_edges"
    INJECTION_SUSPECT = "injection_suspect"
    OTHER = "other"


class EvidenceRecord(BaseModel):
    id: str
    tier: EvidenceTier
    source: str  # e.g. "osv", "epss", "kev", "npm-registry", "heuristic"
    origin: str  # e.g. "GHSA", "OpenSSF", "Amazon Inspector", "heuristic"
    kind: EvidenceKind
    subject: str  # purl: "pkg:npm/name@version"
    claim: str    # Short plain-language statement
    url: str | None = None
    published_at: datetime | None = None
    retrieved_at: datetime
    quote: str | None = None  # Max 500 chars from advisory text (sanitised)
    withdrawn: bool = False
    data: dict[str, Any] = Field(default_factory=dict)
