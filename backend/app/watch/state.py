"""
Security state of a monitored project, and old-vs-new comparison.

The state is read straight from a Warrant report: verdict, urgency, qualifier, response
and fixed version come from the existing decision engine; evidence facts come from the
existing providers. Nothing here scores or classifies risk — it only decides which
differences between two engine outputs warrant a security-change event.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

NKF = "NO_KNOWN_FINDING"
CANNOT_ASSESS = "CANNOT_ASSESS"

# Verdicts that ask the user to do something (existing rule table R1–R4).
ACTIONABLE = {"INCIDENT", "ACT_NOW", "UPGRADE", "MONITOR"}

# Ordering of the existing verdicts, most severe last. CANNOT_ASSESS is deliberately
# absent: "could not check" is neither better nor worse than a known state.
SEVERITY = {NKF: 0, "REVIEW": 1, "MONITOR": 2, "UPGRADE": 3, "ACT_NOW": 4, "INCIDENT": 5}
URGENCY_RANK = {"NONE": 0, "DEFER": 1, "SCHEDULED": 2, "OUT_OF_CYCLE": 3, "IMMEDIATE": 4}

# Evidence sources that constitute *security* evidence for monitoring purposes.
SECURITY_SOURCES = ("osv", "kev", "epss")

DECISION_FIELDS = ("verdict", "urgency", "qualifier", "response", "fixed_version")


def iso(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def rule_ids(derivation: list[str] | None) -> list[str]:
    """'R3 ← E0001' → 'R3'. Evidence ids in derivations are positional, so only rule ids are compared."""
    out = []
    for item in derivation or []:
        rule = item.split("←")[0].split("—")[0].strip()
        if rule and rule not in out:
            out.append(rule)
    return out


def _evidence_key(ev: dict) -> str | None:
    if ev.get("source") not in SECURITY_SOURCES or ev.get("tier") not in ("T1", "T2"):
        return None
    data = ev.get("data") or {}
    if ev["source"] == "osv":
        return f"osv:{data.get('vuln_id') or ev.get('id')}"
    cve = data.get("cve")
    return f"{ev['source']}:{cve}" if cve else None


def _evidence_facts(ev: dict) -> dict:
    """Decision-relevant facts only — text or score jitter must not look like a change."""
    data = ev.get("data") or {}
    facts: dict[str, Any] = {
        "source": ev.get("source"),
        "tier": ev.get("tier"),
        "kind": ev.get("kind"),
        "withdrawn": bool(ev.get("withdrawn")),
    }
    if ev.get("source") == "osv":
        facts.update({
            "vuln_id": data.get("vuln_id"),
            "is_malware": bool(data.get("is_malware")),
            "fixed_version": data.get("fixed_version"),
            "cvss_vector": data.get("cvss_vector"),
            "cve_aliases": sorted(data.get("cve_aliases") or []),
        })
    elif ev.get("source") == "kev":
        facts["cve"] = data.get("cve")
    elif ev.get("source") == "epss":
        facts.update({"cve": data.get("cve"), "above_threshold": bool(data.get("above_threshold"))})
    return facts


def _evidence_meta(ev: dict) -> dict:
    data = ev.get("data") or {}
    return {
        "evidence_id": ev.get("id"),
        "origin": ev.get("origin"),
        "claim": ev.get("claim"),
        "url": ev.get("url"),
        "published_at": iso(ev.get("published_at")),
        "observed_at": iso(ev.get("retrieved_at")),
        "modified_at": data.get("modified"),
        "epss": data.get("epss"),
        "threshold": data.get("threshold"),
    }


def empty_package(subject: str, name: str = "", version: str = "") -> dict:
    return {
        "subject": subject, "name": name, "version": version,
        "verdict": NKF, "urgency": "NONE", "qualifier": "UNKNOWN", "response": "none",
        "fixed_version": None, "derivation": [], "what": "", "carry_reason": None,
        "evidence": {},
    }


def state_from_report(report: dict) -> dict[str, dict]:
    """
    Per-package security state from a report dict. Packages with neither a decision nor
    security evidence are implicitly NO_KNOWN_FINDING and are not stored.
    """
    names = {n["id"]: (n.get("name", ""), n.get("version", "")) for n in (report.get("graph") or {}).get("nodes", [])}
    state: dict[str, dict] = {}

    def entry(subject: str) -> dict:
        if subject not in state:
            name, version = names.get(subject, ("", ""))
            state[subject] = empty_package(subject, name, version)
        return state[subject]

    for dec in report.get("decisions", []):
        pkg = entry(dec["subject"])
        pkg.update({
            "name": dec.get("name", pkg["name"]),
            "version": dec.get("version", pkg["version"]),
            "verdict": dec["verdict"],
            "urgency": dec["urgency"],
            "qualifier": dec["qualifier"],
            "response": dec["response"],
            "fixed_version": dec.get("fixed_version"),
            "derivation": list(dec.get("derivation") or []),
            "what": dec.get("what", ""),
            "carry_reason": dec.get("carry_reason"),
        })

    for ev in report.get("evidence", []):
        key = _evidence_key(ev)
        if key is None:
            continue
        entry(ev["subject"])["evidence"][key] = {"facts": _evidence_facts(ev), "meta": _evidence_meta(ev)}
    return state


def package_signature(pkg: dict) -> dict:
    return {
        **{f: pkg.get(f) for f in DECISION_FIELDS},
        "rules": rule_ids(pkg.get("derivation")),
        "evidence": {k: v["facts"] for k, v in sorted(pkg.get("evidence", {}).items())},
    }


def state_signature(state: dict[str, dict]) -> dict:
    """Comparable view of a state: ignores observation times, claim text and positional ids."""
    return {s: package_signature(p) for s, p in sorted(state.items()) if package_signature(p) != package_signature(empty_package(s))}


# ─── Comparison ────────────────────────────────────────────────────────────────

@dataclass
class PackageChange:
    subject: str
    previous: dict
    current: dict
    change_type: str                    # ESCALATION | DE_ESCALATION | EVIDENCE_CHANGE
    evidence_diff: list[dict] = field(default_factory=list)


@dataclass
class Comparison:
    changes: list[PackageChange]        # Meaningful changes → security-change events
    next_state: dict[str, dict]         # Baseline to persist after this check
    evidence_changed: list[str]         # Subjects whose security evidence differed at all
    held: list[str]                     # Subjects whose previous decision was kept (not re-assessed)


def evidence_diff(old: dict, new: dict) -> list[dict]:
    out = []
    old_ev, new_ev = old.get("evidence", {}), new.get("evidence", {})
    for key in sorted(set(old_ev) | set(new_ev)):
        a, b = old_ev.get(key), new_ev.get(key)
        if a and b and a["facts"] == b["facts"]:
            continue
        fa, fb = (a or {}).get("facts", {}), (b or {}).get("facts", {})
        if a and not b:
            change = "removed"
        elif b and not a:
            change = "added_withdrawn" if fb["withdrawn"] else "added"
        elif fb["withdrawn"] and not fa["withdrawn"]:
            change = "withdrawn"
        elif fa["withdrawn"] and not fb["withdrawn"]:
            change = "reinstated"
        elif fb.get("source") == "epss" and fa.get("above_threshold") != fb.get("above_threshold"):
            change = "threshold_crossed" if fb.get("above_threshold") else "threshold_dropped"
        else:
            change = "modified"
        out.append({
            "key": key,
            "change": change,
            "fields_changed": sorted(k for k in set(fa) | set(fb) if fa.get(k) != fb.get(k)) if a and b else [],
            "previous": fa or None,
            "current": fb or None,
            "meta": (b or a)["meta"],
            "previous_meta": a["meta"] if a else None,
        })
    return out


def _decision_changed(old: dict, new: dict) -> bool:
    return any(old.get(f) != new.get(f) for f in DECISION_FIELDS) or rule_ids(old.get("derivation")) != rule_ids(new.get("derivation"))


def _adds_evidence(diff: list[dict]) -> bool:
    return any(d["change"] in ("added", "reinstated", "threshold_crossed") for d in diff)


def _adds_authority(diff: list[dict]) -> bool:
    """New T1 evidence: a malware report or a CISA KEV listing."""
    return any(d["change"] in ("added", "reinstated") and (d["current"] or {}).get("tier") == "T1" for d in diff)


def _merge_evidence(old: dict, new: dict) -> dict:
    """Partial check: keep previously known evidence the failed provider could not re-confirm."""
    return {**new, "evidence": {**old.get("evidence", {}), **new.get("evidence", {})}}


def compare_states(old_state: dict[str, dict], new_state: dict[str, dict], *, complete: bool) -> Comparison:
    """
    Compare the previous baseline with a fresh engine run.

    complete=False means a provider could not be checked: only escalations backed by
    evidence that *was* retrieved are trusted. De-escalations and removals are not, so a
    provider outage can never turn into a cleaner result.
    """
    changes: list[PackageChange] = []
    next_state: dict[str, dict] = {s: p for s, p in old_state.items()}
    evidence_changed: list[str] = []
    held: list[str] = []

    for subject in sorted(set(old_state) | set(new_state)):
        new_default = new_state.get(subject) or {}
        old = old_state.get(subject) or empty_package(subject, new_default.get("name", ""), new_default.get("version", ""))
        new = new_state.get(subject) or empty_package(subject, old["name"], old["version"])
        diff = evidence_diff(old, new)
        if diff:
            evidence_changed.append(subject)
        if package_signature(old) == package_signature(new):
            continue

        ov, nv = old["verdict"], new["verdict"]

        if not complete and nv == CANNOT_ASSESS and ov != CANNOT_ASSESS:
            # Lost visibility while a provider is down: neither an alert nor a clean result.
            held.append(subject)
            continue

        if not complete:
            escalated = (
                nv in ACTIONABLE
                and (ov == CANNOT_ASSESS or SEVERITY[nv] > SEVERITY[ov])
            )
            strengthened = (
                nv == ov and nv in ACTIONABLE and _adds_evidence(diff)
                and (URGENCY_RANK.get(new["urgency"], 0) >= URGENCY_RANK.get(old["urgency"], 0))
            )
            if escalated or strengthened:
                changes.append(PackageChange(subject, old, new, "ESCALATION" if escalated else "EVIDENCE_CHANGE", diff))
                next_state[subject] = _merge_evidence(old, new)
            else:
                held.append(subject)
            continue

        # Complete check: the new engine output becomes the baseline.
        next_state[subject] = new
        if nv == NKF and not new.get("evidence"):
            next_state.pop(subject, None)

        if ov == CANNOT_ASSESS:
            if nv in ACTIONABLE:
                changes.append(PackageChange(subject, old, new, "ESCALATION", diff))
            elif nv == CANNOT_ASSESS and _adds_evidence(diff):
                changes.append(PackageChange(subject, old, new, "EVIDENCE_CHANGE", diff))
            continue

        if nv == CANNOT_ASSESS:
            # All providers ran, yet the engine can no longer assess this version (e.g. its advisory was
            # withdrawn, or a new advisory has no fix). A finding that stops standing must be surfaced.
            if ov in ACTIONABLE:
                changes.append(PackageChange(subject, old, new, "DE_ESCALATION", diff))
            elif diff:
                changes.append(PackageChange(subject, old, new, "EVIDENCE_CHANGE", diff))
            continue

        if ov != nv:
            if SEVERITY[nv] > SEVERITY[ov]:
                if nv in ACTIONABLE or diff:
                    changes.append(PackageChange(subject, old, new, "ESCALATION", diff))
            elif ov in ACTIONABLE or diff:
                changes.append(PackageChange(subject, old, new, "DE_ESCALATION", diff))
            continue

        if nv in ACTIONABLE and (_decision_changed(old, new) or _adds_authority(diff)):
            changes.append(PackageChange(subject, old, new, "EVIDENCE_CHANGE", diff))

    return Comparison(changes=changes, next_state=next_state, evidence_changed=evidence_changed, held=held)


def priority_for(change: PackageChange) -> str:
    """Notification priority, derived from the existing urgency of the new decision."""
    if change.current.get("verdict") == CANNOT_ASSESS:
        return "low"  # Not a resolution: CANNOT ASSESS is never "safe"
    if change.change_type == "DE_ESCALATION":
        return "info"
    urgency = change.current.get("urgency", "NONE")
    if urgency in ("IMMEDIATE", "OUT_OF_CYCLE"):
        return "high"
    if urgency == "SCHEDULED":
        return "medium"
    return "low"
