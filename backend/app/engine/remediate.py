"""
Remediation helpers — command generation and Simulate Fix.
"""
from __future__ import annotations

from ..models.decision import Decision, RemediationStep, ResponseClass


def build_fix_commands(decision: Decision, introduced_by_versions: dict[str, str] | None = None) -> list[RemediationStep]:
    """
    Generate copyable fix commands for a decision.
    - Direct deps: npm install <name>@<fixed>
    - Transitive deps: package.json overrides snippet
    """
    steps: list[RemediationStep] = list(decision.response_steps)

    if not decision.fixed_version:
        steps.append(RemediationStep(text="No fixed version in the advisory — monitor for upstream patch."))
        return steps

    fixed = decision.fixed_version
    if fixed == "0.0.1-security":
        steps.append(RemediationStep(text="Advisory references a placeholder version — check upstream for actual fix."))
        return steps

    name = decision.name
    if decision.is_direct:
        steps.append(RemediationStep(
            text=f"Upgrade {name} to {fixed} (direct dependency)",
            command=f"npm install {name}@{fixed}",
        ))
    else:
        steps.append(RemediationStep(
            text=f"Add an override in package.json (transitive dependency)",
            command=f'"overrides": {{\n  "{name}": "{fixed}"\n}}',
        ))

    if decision.verdict.value in ("INCIDENT",):
        steps.append(RemediationStep(
            text="After removing: audit the exposure window using the advisory timestamp.",
        ))

    return steps


def format_containment_checklist(decision: Decision) -> list[RemediationStep]:
    """For INCIDENT verdicts, return the full containment checklist."""
    name = decision.name
    version = decision.version
    return [
        RemediationStep(text=f"1. Remove {name}@{version} immediately or pin to a version before the affected range."),
        RemediationStep(text="2. Identify all machines that ran npm install during the exposure window."),
        RemediationStep(text="3. Assume credentials, secrets, and environment variables on those machines are compromised."),
        RemediationStep(text="4. Rotate ALL secrets from a CLEAN machine (not one that ran the affected install)."),
        RemediationStep(text="5. Audit git history and CI logs for the exposure window."),
        RemediationStep(text="6. Human approval required before re-introducing any version of this package."),
        RemediationStep(
            text=f"7. Pin to safe version" if decision.fixed_version else "7. No confirmed safe version in advisory — remove and find an alternative.",
            command=f"npm install {name}@{decision.fixed_version}" if decision.fixed_version and decision.is_direct else None,
        ),
    ]
