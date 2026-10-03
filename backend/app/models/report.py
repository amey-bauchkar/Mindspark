"""Report, context and graph models."""
from __future__ import annotations
from enum import Enum
from typing import Any
from pydantic import BaseModel, Field
from datetime import datetime

from .evidence import EvidenceRecord
from .decision import Decision


class DistributionMode(str, Enum):
    SAAS = "SaaS"
    DISTRIBUTED = "Distributed"
    INTERNAL = "Internal"
    OPEN_SOURCE = "OpenSource"
    UNKNOWN = "Unknown"


class ProjectLicense(str, Enum):
    PROPRIETARY = "Proprietary"
    MIT = "MIT"
    APACHE2 = "Apache-2.0"
    GPL3 = "GPL-3.0-or-later"
    UNKNOWN = "Unknown"


class AnalysisContext(BaseModel):
    distribution_mode: DistributionMode = DistributionMode.UNKNOWN
    project_license: ProjectLicense = ProjectLicense.UNKNOWN
    install_scripts_run: bool | None = None  # None = skipped/unknown
    skipped_fields: list[str] = Field(default_factory=list)


class GraphNode(BaseModel):
    id: str              # purl@version
    name: str
    version: str
    is_direct: bool
    scope: str           # "prod"|"dev"|"optional"
    depth: int
    has_install_script: bool
    resolved_url: str | None = None
    is_git_or_file: bool = False
    verdict: str | None = None  # for coloring


class GraphEdge(BaseModel):
    source: str   # purl
    target: str   # purl
    requirement: str | None = None
    scope: str = "prod"


class LicenseResult(BaseModel):
    subject: str
    name: str
    version: str
    license_expr: str | None
    license_status: str  # "OK"|"CONFLICT"|"REVIEW"|"UNKNOWN"|"CANNOT_ASSESS"
    rule_fired: str | None = None
    introducing_paths: list[list[str]] = Field(default_factory=list)
    note: str | None = None


class CoverageCheck(BaseModel):
    check: str
    status: str   # "Ran"|"Partial"|"Not run"|"Not supported"
    reason: str | None = None
    count: int | None = None


class ReportSummary(BaseModel):
    incident: int = 0
    act_now: int = 0
    upgrade: int = 0
    monitor: int = 0
    review: int = 0
    cannot_assess: int = 0
    no_known_finding: int = 0
    total_packages: int = 0
    direct_packages: int = 0
    as_of: datetime
    ecosystem: str
    data_badge: str  # "LIVE"|"RECORDED"|"REPLAY"|"PARTIAL"


class Report(BaseModel):
    id: str
    created_at: datetime
    meta: dict[str, Any]
    summary: ReportSummary
    decisions: list[Decision]
    evidence: list[EvidenceRecord]
    graph: dict[str, Any]   # {nodes: [...], edges: [...]}
    licenses: list[LicenseResult]
    coverage: list[CoverageCheck]
    context: AnalysisContext
    schema_version: str = "1.0"
