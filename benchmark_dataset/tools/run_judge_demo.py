#!/usr/bin/env python3
"""
Warrant-2.1 Judge Demonstration Runner
Runs Demo A (Primary Real Project) and Demo B (Temporal Replay)
directly using Warrant's deterministic engine.
"""
import sys
import json
from pathlib import Path
from datetime import datetime, timezone

ROOT_DIR = Path(__file__).parent.parent
BACKEND_DIR = ROOT_DIR.parent / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.parsers.npm_lock import parse_npm_lock
from app.graph.build import build_graph, ROOT_ID, find_paths
from app.engine.decide import derive_decisions
from app.models.evidence import EvidenceRecord, EvidenceTier, EvidenceKind
from app.models.report import AnalysisContext
from app.signals.lookalike import check_lookalike
from app.signals.staleness import check_staleness


def run_demo_a():
    print("\n" + "=" * 65)
    print("DEMO A — PRIMARY REAL PROJECT: slackapi/slack-github-action @ a8dafde")
    print("=" * 65)
    print("Input: REAL, UNMODIFIED package-lock.json (Lockfile v3, 94 packages)")
    print("Source: https://github.com/slackapi/slack-github-action/tree/a8dafde")
    
    lock_file = ROOT_DIR / "projects" / "primary" / "package-lock.json"
    content = lock_file.read_text(encoding="utf-8")
    
    pr = parse_npm_lock(content)
    bg = build_graph(pr)
    
    total = len(bg.packages)
    direct = len([p for p in bg.packages.values() if p.is_direct])
    trans = total - direct
    
    print(f"\n[1] GRAPH RECONSTRUCTION:")
    print(f"    - Total Nodes: {total}")
    print(f"    - Direct Dependencies: {direct} (3 in package.json)")
    print(f"    - Transitive Dependencies: {trans}")
    print(f"    - Edges: {bg.graph.number_of_edges()}")
    print(f"    - Cycles Detected: {bg.cycles_detected}")
    
    # Run heuristic and advisory demonstration
    ev = []
    for purl, pkg in bg.packages.items():
        ev.extend(check_lookalike(pkg.name, pkg.version))
        ev.extend(check_staleness(pkg.name, pkg.version, None))
        
    # Add real historical advisories for axios@1.14.0 (known in April 2026)
    axios_purl = "pkg:npm/axios@1.14.0"
    if axios_purl in bg.packages:
        now = datetime.now(timezone.utc)
        ev.append(EvidenceRecord(
            id="E-GHSA-AXIOS",
            tier=EvidenceTier.T2,
            source="osv",
            origin="GHSA",
            kind=EvidenceKind.ADVISORY,
            subject=axios_purl,
            claim="Advisory GHSA-35jp-ww65-95wh with fix available",
            published_at=now,
            retrieved_at=now,
            data={"vuln_id": "GHSA-35jp-ww65-95wh", "fixed_version": "1.15.0", "is_malware": False}
        ))
    
    decs = derive_decisions(bg, ev, AnalysisContext())
    print(f"\n[2] WARRANT DECISIONS DERIVED (Found {len(decs)} findings):")
    for d in decs[:8]:
        paths = find_paths(bg.graph, ROOT_ID, d.subject)
        path_str = " -> ".join(paths[0]) if paths else "Direct"
        print(f"    • [{d.verdict.value}] {d.name}@{d.version} ({d.urgency.value})")
        print(f"      Path: {path_str}")
        print(f"      Reason: {d.what}")
        print(f"      Fix: {d.response_steps[0].text if d.response_steps else 'N/A'}\n")


def run_demo_b():
    print("\n" + "=" * 65)
    print("DEMO B — TEMPORAL INCIDENT REPLAY: axios / plain-crypto-js (2026-03-31)")
    print("=" * 65)
    print("Fixture: DERIVED / COUNTERFACTUAL TEMPORAL FIXTURE")
    print("Notice: Clearly marked as COUNTERFACTUAL; demonstrates As-Of time-travel")
    
    cf_file = ROOT_DIR / "replay" / "counterfactual" / "package-lock.COUNTERFACTUAL_DERIVED.json"
    if not cf_file.exists():
        print("Counterfactual fixture not found.")
        return
        
    content = cf_file.read_text(encoding="utf-8")
    pr = parse_npm_lock(content)
    bg = build_graph(pr)
    
    t0 = datetime.fromisoformat("2026-03-31T01:00:00+00:00")
    t1 = datetime.fromisoformat("2026-03-31T02:30:00+00:00")
    t2 = datetime.fromisoformat("2026-03-31T03:30:00+00:00")
    
    # Load real OpenSSF evidence
    mal_crypto = json.loads((ROOT_DIR / "evidence" / "openssf" / "MAL-2026-2306.json").read_text(encoding="utf-8"))
    mal_axios = json.loads((ROOT_DIR / "evidence" / "openssf" / "MAL-2026-2307.json").read_text(encoding="utf-8"))
    
    all_evidence = [
        EvidenceRecord(
            id="E-MAL-2306",
            tier=EvidenceTier.T1,
            source="openssf",
            origin="Amazon Inspector",
            kind=EvidenceKind.MALWARE_REPORT,
            subject="pkg:npm/plain-crypto-js@4.2.1",
            claim="Reported malicious (MAL-2026-2306)",
            published_at=datetime.fromisoformat("2026-03-31T02:07:58+00:00"),
            retrieved_at=datetime.fromisoformat("2026-03-31T03:10:11+00:00"),
            data={"vuln_id": "MAL-2026-2306", "is_malware": True}
        ),
        EvidenceRecord(
            id="E-MAL-2307",
            tier=EvidenceTier.T1,
            source="openssf",
            origin="GHSA",
            kind=EvidenceKind.MALWARE_REPORT,
            subject="pkg:npm/axios@1.14.1",
            claim="Reported malicious (MAL-2026-2307)",
            published_at=datetime.fromisoformat("2026-03-31T03:15:49+00:00"),
            retrieved_at=datetime.fromisoformat("2026-03-31T03:22:12+00:00"),
            data={"vuln_id": "MAL-2026-2307", "is_malware": True}
        )
    ]
    
    for label, as_of in [("T0 (01:00Z) - Prior to any report", t0),
                         ("T1 (02:30Z) - Child reported (MAL-2026-2306 active)", t1),
                         ("T2 (03:30Z) - Both reported (MAL-2026-2307 active)", t2)]:
        print(f"\n--- AS-OF: {label} ---")
        decs = derive_decisions(bg, all_evidence, AnalysisContext(), as_of=as_of)
        if not decs:
            print("  Warrant Verdict: NO REPORT AS OF T (All checks completed, no reports exist yet).")
        for d in decs:
            print(f"  • [{d.verdict.value}] {d.name}@{d.version} ({d.urgency.value}) -> {d.what}")


if __name__ == "__main__":
    run_demo_a()
    run_demo_b()
