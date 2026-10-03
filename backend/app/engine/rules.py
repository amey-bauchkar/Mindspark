"""
Decision engine rule table — stored as DATA.
This exact structure is rendered on the /methodology page.
Rules are applied top-down per node; first matching rule wins.
"""
from __future__ import annotations

RULES: list[dict] = [
    {
        "id": "R1",
        "name": "Active malware report",
        "condition": "Active T1 malware report (OSV MAL-* / OpenSSF) matches the node's exact resolved purl@version, any scope, any depth",
        "verdict": "INCIDENT",
        "urgency": "IMMEDIATE",
        "qualifier": "PROBABLE",
        "qualifier_note": "PROBABLE when T1 report has a single origin; ESTABLISHED when multiple independent origins",
        "response_class": "containment",
        "response_steps": [
            "Remove the package or pin to the last version before the first affected, if determinable from the advisory data.",
            "Assume secrets and credentials may be exposed on machines that ran npm install during the affected window.",
            "Rotate credentials from a clean machine.",
            "Audit the exposure window using the advisory published_at timestamp.",
            "Human approval required before re-introducing any version of this package.",
        ],
    },
    {
        "id": "R1'",
        "name": "Ancestor of incident node",
        "condition": "Node is an ancestor of an R1 node in the resolved dependency graph",
        "verdict": None,
        "urgency": None,
        "qualifier": None,
        "response_class": None,
        "response_steps": [],
        "note": "The decision lives on the descendant. Ancestor is annotated 'carries incident via path' only.",
    },
    {
        "id": "R2",
        "name": "Known exploited or high EPSS",
        "condition": "T1 CISA KEV entry, OR T2 advisory with EPSS ≥ θ (default 0.10), on a node with a runtime-scope (prod) path",
        "verdict": "ACT_NOW",
        "urgency": "IMMEDIATE or OUT_OF_CYCLE",
        "qualifier": "ESTABLISHED (KEV) or PROBABLE (EPSS)",
        "response_class": "minimal_upgrade",
        "response_steps": [
            "Upgrade to the fixed version stated in the advisory.",
            "If a direct dependency, run: npm install <package>@<fixed-version>",
            "If a transitive dependency, add an 'overrides' entry in package.json and re-lock.",
        ],
    },
    {
        "id": "R3",
        "name": "Advisory with fix, runtime path",
        "condition": "T2 advisory with a known fixed version, node reachable via a runtime-scope (prod) path",
        "verdict": "UPGRADE",
        "urgency": "SCHEDULED",
        "qualifier": "ESTABLISHED",
        "response_class": "upgrade",
        "response_steps": [
            "Schedule upgrade to the fixed version.",
            "Review changelog for breaking changes.",
        ],
    },
    {
        "id": "R4",
        "name": "Advisory, dev/optional only",
        "condition": "T2 advisory, but all root→node paths are dev or optional scope",
        "verdict": "MONITOR",
        "urgency": "DEFER",
        "qualifier": "ESTABLISHED",
        "response_class": "defer",
        "response_steps": [
            "Track upstream fix; upgrade when convenient.",
            "If this package is ever moved to a production dependency, re-assess.",
        ],
    },
    {
        "id": "R5",
        "name": "Heuristic or license signal only",
        "condition": "T3-only evidence (lookalike, stale, very new), OR a license flag, OR unresolved source conflict — no T1/T2",
        "verdict": "REVIEW",
        "urgency": "SCHEDULED",
        "qualifier": "POSSIBLE",
        "response_class": "review",
        "response_steps": [
            "Manually review the package: inspect source repository, maintainer history, download trends.",
            "For license flags: consult your legal team before distribution.",
            "Heuristic signals are not evidence of malice.",
        ],
    },
    {
        "id": "R6",
        "name": "Cannot assess",
        "condition": "None of R1–R5 apply AND (a required check could not run, OR version younger than freshness horizon, OR identity unresolved e.g. git/file/tarball, OR edges unknown)",
        "verdict": "CANNOT_ASSESS",
        "urgency": "NONE",
        "qualifier": "UNKNOWN",
        "response_class": "cannot_assess",
        "response_steps": [
            "Investigate manually: the tool could not gather enough evidence to assess this package.",
            "Resolve the reason listed in 'Not checked'.",
        ],
    },
    {
        "id": "R7",
        "name": "No known finding",
        "condition": "All required checks completed, nothing found",
        "verdict": "NO_KNOWN_FINDING",
        "urgency": "NONE",
        "qualifier": "UNKNOWN",
        "response_class": "none",
        "response_steps": [],
        "note": "Always print scope and as-of time. NEVER shown as green or 'safe'.",
    },
]

# Parameters shown on /methodology
ENGINE_PARAMETERS = {
    "epss_threshold": {
        "default": 0.10,
        "description": "EPSS probability score threshold for R2 (ACT NOW). Not empirically validated — treat as a starting point.",
        "configurable": True,
    },
    "freshness_hours": {
        "default": 72,
        "description": "Packages first published within this window get CANNOT ASSESS (very new). Not empirically validated.",
        "configurable": True,
    },
    "max_paths_per_node": {
        "default": 10,
        "description": "Maximum root→node paths enumerated per package (DFS cap).",
        "configurable": False,
    },
}
