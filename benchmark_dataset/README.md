# Warrant-2.1 Real-World Benchmark Dataset

Authoritative, verifiable benchmark evaluation suite for **Warrant-2.1: Software Supply Chain Risk Analyzer**.

---

## 1. Directory Structure

```
benchmark_dataset/
├── projects/
│   ├── primary/               # PRIMARY REAL CANDIDATE: slackapi/slack-github-action @ a8dafde
│   │   ├── package-lock.json  # Real unmodified npm lockfile v3 (94 packages, 3 direct)
│   │   ├── package.json       # Project manifest
│   │   └── provenance.json    # Commit, date, source URL, SHA-256
│   ├── backup_yargs/          # BACKUP CANDIDATE: yargs/yargs @ 10f1dda (492 packages)
│   │   ├── package-lock.json
│   │   ├── package.json
│   │   └── provenance.json
│   └── control_cheerio/       # CONTROL / CLEAN CANDIDATE: cheeriojs/cheerio @ dfc08da (426 packages)
│       ├── package-lock.json
│       ├── package.json
│       └── provenance.json
│
├── evidence/                  # REAL SECURITY EVIDENCE (Retrieved from upstream authoritative stores)
│   ├── openssf/               # Real OpenSSF/OSV MAL records (MAL-2026-2306, 2307, 4596, 10541)
│   ├── npm/                   # Real npm registry packuments & publication time maps
│   ├── github/                # Real GitHub Advisory Database entries
│   └── kev/                   # CISA Known Exploited Vulnerabilities catalog subset
│
├── incidents/                 # REAL HISTORICAL INCIDENT DATA
│   └── axios/                 # Chronological multi-clock timeline of the 2026-03-31 compromise
│
├── replay/                    # REPLAY FIXTURES
│   ├── real/                  # Real projects replayed under As-Of constraints
│   └── counterfactual/        # DERIVED / COUNTERFACTUAL temporal fixture (clearly labelled)
│
├── manifests/                 # AUDIT TRAIL & INTEGRITY
│   ├── dataset_manifest.json  # Full metadata inventory
│   └── checksums.sha256       # SHA-256 digests for all files in this dataset
│
└── tools/                     # REPRODUCTION & VALIDATION SCRIPTS
    ├── verify_dataset.py      # Run automated verification suite (checksums, syntax, graph, PC-01)
    └── run_judge_demo.py      # Interactive judge demonstration script (Demo A & Demo B)
```

---

## 2. Two Distinct Benchmarks

### Demo A — Primary Real Project (`slackapi/slack-github-action`)
- **Input:** `benchmark_dataset/projects/primary/package-lock.json`
- **Authenticity:** Real, unmodified open-source lockfile from commit `a8dafde` (2026-04-01).
- **Graph:** 94 packages (3 direct: `@actions/core`, `@actions/github`, `@slack/web-api`; 91 transitive), 118 edges, 0 cycles.
- **Truthful Findings:**
  - 5 `UPGRADE` decisions (real CVE advisories on transitive dependencies with known fix versions).
  - 5 `REVIEW` decisions (scoped variant lookalike heuristics and unmaintained package indicators).
  - 0 false `INCIDENT` alerts (verifiable absence of malware).

### Demo B — Temporal Incident Replay (`axios / plain-crypto-js`)
- **Input:** `benchmark_dataset/replay/counterfactual/package-lock.COUNTERFACTUAL_DERIVED.json`
- **Notice:** Clearly marked as a **COUNTERFACTUAL FIXTURE** — not an authentic project state.
- **Demonstration:** Shows Warrant's As-Of bitemporal time-travel:
  - `T0 (01:00 UTC)`: `NO REPORT AS OF T` (no advisory published yet).
  - `T1 (02:30 UTC)`: `MAL-2026-2306` published for `plain-crypto-js@4.2.1`. Child becomes `INCIDENT`; parent `axios@1.14.1` carries incident via path (`R1'`).
  - `T2 (03:30 UTC)`: `MAL-2026-2307` published for `axios@1.14.1`. Both show `INCIDENT`.

---

## 3. How to Verify and Run

From project root (`Mindspark/`):

```bash
# 1. Run full verification suite (checksums, graph integrity, PC-01 placeholder test)
python benchmark_dataset/tools/verify_dataset.py

# 2. Run both judge demos (Demo A and Demo B) via CLI
python benchmark_dataset/tools/run_judge_demo.py
```
