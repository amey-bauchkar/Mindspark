"""
CVSS vector → plain English impact profile.
No numeric score of our own. No RCE claims unless the advisory says so.
Supports CVSS v3.x base metrics.
"""
from __future__ import annotations
import re

CVSS_LABEL = "Read from the CVSS vector. This is not confirmed exploitability on your system."

# CVSS v3 metric keys and human-readable mappings
_AV = {"N": "network-reachable", "A": "adjacent network", "L": "local access", "P": "physical access"}
_AC = {"L": "low complexity", "H": "high complexity"}
_PR = {"N": "no privileges needed", "L": "low privileges", "H": "high privileges"}
_UI = {"N": "no user interaction", "R": "requires user interaction"}
_S  = {"U": "unchanged scope", "C": "changed scope"}
_CIA = {"N": "none", "L": "low", "H": "high"}

_CVSS3_RE = re.compile(
    r'CVSS:3\.[01]/AV:([NALP])/AC:([LH])/PR:([NLH])/UI:([NR])/S:([UC])/C:([NLH])/I:([NLH])/A:([NLH])',
    re.IGNORECASE,
)


def parse_cvss_vector(vector: str | None) -> dict | None:
    """Parse a CVSS v3.x vector string into a plain-English profile dict."""
    if not vector:
        return None
    m = _CVSS3_RE.search(vector)
    if not m:
        return {"raw": vector, "note": "Unrecognised CVSS format; vector shown as-is."}
    av, ac, pr, ui, s, c, i, a = m.groups()
    return {
        "attack_vector": _AV.get(av.upper(), av),
        "attack_complexity": _AC.get(ac.upper(), ac),
        "privileges_required": _PR.get(pr.upper(), pr),
        "user_interaction": _UI.get(ui.upper(), ui),
        "scope": _S.get(s.upper(), s),
        "confidentiality_impact": _CIA.get(c.upper(), c),
        "integrity_impact": _CIA.get(i.upper(), i),
        "availability_impact": _CIA.get(a.upper(), a),
        "raw": vector,
        "label": CVSS_LABEL,
    }
