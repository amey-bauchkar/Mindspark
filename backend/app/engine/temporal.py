"""
As-of view of a stored report.

Decisions are re-derived by the existing engine (`derive_decisions`) from the report's own
stored dependency graph and evidence, keeping only evidence that was active at `as_of`
(published by then, not yet withdrawn, and — for EPSS/KEV lookups — derived from an advisory
that was active). No provider is queried, so nothing learned later can leak into the view
except data that carries no publication date, which the response states explicitly.
"""
from __future__ import annotations

import copy
import json
from datetime import datetime
from types import SimpleNamespace

from ..graph.build import build_from_report_graph
from ..models.evidence import EvidenceRecord
from ..models.report import AnalysisContext
from .decide import _parse_time, active_evidence, derive_decisions

AS_OF_NOTE = (
    "Decisions re-derived by the same rules from this report's stored evidence, keeping only records "
    "published — and not yet withdrawn — by this time. Evidence without a publication date (EPSS scores, "
    "CISA KEV listings, registry heuristics, coverage) reflects what was retrieved at analysis time."
)


class AsOfUnavailable(ValueError):
    """The report does not carry enough stored state to be re-evaluated."""


def _jsonable(obj) -> dict:
    return json.loads(json.dumps(obj.model_dump(), default=str))


def rederive_as_of(report: dict, as_of: datetime) -> dict:
    from ..jobs import _build_summary, decisions_for_requirements, enrich_remediation

    data = copy.deepcopy(report)
    meta = data.setdefault("meta", {})
    summary = data.get("summary") or {}
    analysed_as_of = _parse_time(summary.get("as_of"))

    if analysed_as_of is not None and as_of >= analysed_as_of:
        meta["as_of_view"] = {
            "requested": as_of.isoformat(),
            "applied": analysed_as_of.isoformat(),
            "rederived": False,
            "note": "The requested time is not earlier than this analysis. Showing the analysis as recorded: "
                    "evidence published after it was never retrieved, so it cannot be shown here.",
        }
        return data

    try:
        evidence = [EvidenceRecord.model_validate(e) for e in data.get("evidence") or []]
        context = AnalysisContext.model_validate(data.get("context") or {})
    except Exception as exc:
        raise AsOfUnavailable("This report's stored evidence could not be read, so it cannot be re-evaluated.") from exc

    ecosystem = str(summary.get("ecosystem") or meta.get("ecosystem") or "npm")
    if ecosystem.startswith("PyPI"):
        packages = [
            SimpleNamespace(purl=l["subject"], name=l.get("name", ""), version=l.get("version", ""))
            for l in data.get("licenses") or [] if isinstance(l, dict) and l.get("subject")
        ]
        if not packages:
            raise AsOfUnavailable("This report lists no packages, so it cannot be re-evaluated.")
        decisions = decisions_for_requirements(packages, evidence, context, as_of)
        total, direct = len(packages), 0
    else:
        graph = data.get("graph") or {}
        if not graph.get("nodes"):
            raise AsOfUnavailable("This report has no stored dependency graph, so it cannot be re-evaluated "
                                  "as of an earlier time.")
        build = build_from_report_graph(graph, str(meta.get("root_name") or meta.get("filename") or "project"))
        decisions = derive_decisions(build, evidence, context, as_of=as_of)
        enrich_remediation(decisions)
        verdicts = {d.subject: d.verdict.value for d in decisions}
        for node in graph["nodes"]:
            node["verdict"] = verdicts.get(node.get("id"))
        total, direct = len(build.packages), sum(1 for p in build.packages.values() if p.is_direct)

    active_ids = {e.id for e in active_evidence(evidence, as_of)}
    excluded = [e.id for e in evidence if e.id not in active_ids]
    new_summary = _build_summary(decisions, total, direct, as_of, ecosystem, str(summary.get("data_badge") or "LIVE"))
    data["summary"] = _jsonable(new_summary)
    data["decisions"] = [_jsonable(d) for d in decisions]
    meta["as_of_view"] = {
        "requested": as_of.isoformat(),
        "applied": as_of.isoformat(),
        "rederived": True,
        "analysed_as_of": analysed_as_of.isoformat() if analysed_as_of else None,
        "excluded_evidence_count": len(excluded),
        "excluded_evidence_ids": excluded[:500],
        "note": AS_OF_NOTE,
    }
    return data
