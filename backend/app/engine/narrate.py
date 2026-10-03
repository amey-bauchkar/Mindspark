"""
Deterministic template narrator + claim verifier.
LLM is never used here. The verifier is fully deterministic.
"""
from __future__ import annotations

from ..models.decision import Decision, Verdict, Urgency


def narrate_decision(decision: Decision, evidence_map: dict) -> str:
    """
    Generate a plain-English narrative from decision fields.
    No AI, no LLM — purely template-based.
    """
    d = decision
    v = d.verdict.value.replace("_", " ").title()
    lines = [
        f"**{d.name}@{d.version}** — {v} ({d.urgency.value})",
        "",
        f"**What:** {d.what}",
    ]

    if d.exposure.paths:
        first_path = " → ".join(d.exposure.paths[0])
        lines.append(f"**Path:** {first_path}")

    lines.append(f"**Scope:** {d.exposure.scope} (provenance: {d.exposure.scope_provenance})")

    if d.fixed_version:
        lines.append(f"**Fixed in:** {d.fixed_version}")

    if d.unrun_checks:
        lines.append("")
        lines.append("**Not checked:**")
        for uc in d.unrun_checks[:5]:
            lines.append(f"  - {uc}")

    lines.append("")
    lines.append("*Generated from rules, no AI.*")
    return "\n".join(lines)


# ─── Verifier ─────────────────────────────────────────────────────────────────

class VerificationResult:
    def __init__(self, passed: bool, gate: str, detail: str):
        self.passed = passed
        self.gate = gate
        self.detail = detail


def verify_claim(claim: dict, decision: Decision, evidence_map: dict) -> VerificationResult:
    """
    Deterministic verifier: reject a claim unless:
    1. Every evidence_id exists in the decision.
    2. Every entity/number appears in the decision's evidence slice.
    3. Verdict words match the decision.
    """
    # Gate 1: evidence IDs
    claimed_eids = claim.get("evidence_ids", [])
    decision_eids = set(decision.evidence_ids)
    for eid in claimed_eids:
        if eid not in decision_eids:
            return VerificationResult(
                passed=False,
                gate="evidence_id_exists",
                detail=f"Claimed evidence ID {eid!r} not found in decision {decision.subject}",
            )

    # Gate 2: verdict match
    claimed_verdict = claim.get("verdict")
    if claimed_verdict and claimed_verdict != decision.verdict.value:
        return VerificationResult(
            passed=False,
            gate="verdict_match",
            detail=f"Claimed verdict {claimed_verdict!r} ≠ actual {decision.verdict.value!r}",
        )

    # Gate 3: entities match (check each claimed entity appears in decision fields)
    entities = claim.get("entities", [])
    decision_text = f"{decision.subject} {decision.what} {decision.name} {decision.version}"
    for entity in entities:
        if str(entity) not in decision_text:
            return VerificationResult(
                passed=False,
                gate="entity_in_evidence",
                detail=f"Claimed entity {entity!r} not found in decision data",
            )

    return VerificationResult(passed=True, gate="all", detail="All gates passed")


SYNTHETIC_CORRUPTED_CLAIM = {
    "evidence_ids": ["E_FABRICATED_999"],
    "verdict": "INCIDENT",
    "entities": ["imaginary-package@9.9.9"],
    "_note": "Synthetic test claim — intentionally corrupted to verify the rejection gate",
}
