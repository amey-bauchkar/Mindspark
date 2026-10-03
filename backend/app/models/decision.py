"""Decision and related output models."""
from __future__ import annotations
from enum import Enum
from typing import Any
from pydantic import BaseModel, Field
from datetime import datetime


class Verdict(str, Enum):
    INCIDENT = "INCIDENT"
    ACT_NOW = "ACT_NOW"
    UPGRADE = "UPGRADE"
    MONITOR = "MONITOR"
    REVIEW = "REVIEW"
    CANNOT_ASSESS = "CANNOT_ASSESS"
    NO_KNOWN_FINDING = "NO_KNOWN_FINDING"


class Urgency(str, Enum):
    IMMEDIATE = "IMMEDIATE"
    OUT_OF_CYCLE = "OUT_OF_CYCLE"
    SCHEDULED = "SCHEDULED"
    DEFER = "DEFER"
    NONE = "NONE"


class Qualifier(str, Enum):
    ESTABLISHED = "ESTABLISHED"
    PROBABLE = "PROBABLE"
    POSSIBLE = "POSSIBLE"
    UNKNOWN = "UNKNOWN"


class ResponseClass(str, Enum):
    CONTAINMENT = "containment"
    MINIMAL_UPGRADE = "minimal_upgrade"
    UPGRADE = "upgrade"
    DEFER = "defer"
    REVIEW = "review"
    CANNOT_ASSESS = "cannot_assess"
    NONE = "none"


class ExposureInfo(BaseModel):
    paths: list[list[str]]  # root → node name chains
    scope: str              # "prod" | "dev" | "optional"
    scope_provenance: str   # How scope was determined
    install_phase: str      # "observed" | "unknown"
    scripts_enabled: str    # "declared" | "assumed"


class RemediationStep(BaseModel):
    text: str
    command: str | None = None


class Decision(BaseModel):
    subject: str            # purl@version
    name: str
    version: str
    verdict: Verdict
    urgency: Urgency
    qualifier: Qualifier
    exposure: ExposureInfo
    evidence_ids: list[str]
    open_defeaters: list[str] = Field(default_factory=list)
    unrun_checks: list[str] = Field(default_factory=list)
    response: ResponseClass
    response_steps: list[RemediationStep] = Field(default_factory=list)
    as_of: datetime
    derivation: list[str] = Field(default_factory=list)  # ["R1 ← E3", ...]
    introduced_by: list[str] = Field(default_factory=list)
    fixed_version: str | None = None
    depth: int = 0
    is_direct: bool = False
    cvss_vector: str | None = None
    cvss_severity: str | None = None
    what: str = ""  # one-line cause
    carry_reason: str | None = None  # for R1' ancestor nodes
