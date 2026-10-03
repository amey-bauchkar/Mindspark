# Warrant — Software Supply Chain Risk Analyzer

Evidence-backed dependency analysis. One decision per risky dependency, computed from a printed rule table — not a black-box score.

## Quick start

### Backend
```bash
cd warrant/backend
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### Frontend
```bash
cd warrant/frontend
npm install
npm run dev
```

Then open **http://localhost:5173**.

---

## What it does

Upload a `package-lock.json` (npm v2/v3) or a pinned `requirements.txt`. For each risky package you get:

| Field | What it tells you |
|---|---|
| **Verdict** | INCIDENT · ACT NOW · UPGRADE · MONITOR · REVIEW · CANNOT ASSESS · NO KNOWN FINDING |
| **Evidence** | Source, tier (T1/T2/T3), quote, link — everything used to reach the verdict |
| **Dependency path** | Full root→package chain in the resolved graph |
| **What wasn't checked** | Explicit list of checks that did not run and why |
| **Remediation** | Copyable commands, containment checklist for incidents |
| **Derivation** | Rule ID (e.g. `R1 ← E0001`) so the verdict is reproducible |

---

## Decision rule table

Rules are applied top-down, first match wins. Stored as **data** in `backend/app/engine/rules.py` and rendered live on `/methodology`.

| Rule | Trigger | Verdict |
|---|---|---|
| R1 | Active malware report (OSV MAL-\*, OpenSSF) | INCIDENT |
| R1' | Ancestor of an R1 node in the graph | INCIDENT (carry) |
| R2 | CISA KEV or EPSS ≥ threshold on prod path | ACT NOW |
| R3 | Advisory with fix, prod path | UPGRADE |
| R4 | Advisory, dev/optional path only | MONITOR |
| R5 | Heuristic/license signal only (no T1/T2) | REVIEW |
| R6 | Required check could not run, or an active advisory has no published fix on a prod path | CANNOT ASSESS |
| R7 | All checks ran, nothing found | NO KNOWN FINDING |

Evidence counts only while it is active: published on or before the as-of time and not yet withdrawn.
EPSS and CISA KEV entries looked up for an advisory's CVE count only while that advisory is active.
A fixed version is taken from the advisory range that contains the installed version, never a downgrade.

**As-of (time-travel) view.** `GET /api/reports/{id}?as_of=…` re-runs the same rules on the report's
stored graph and evidence, keeping only what was active at that time. No provider is queried. Evidence
without a publication date (EPSS, KEV, registry heuristics) reflects what was retrieved at analysis time,
and the view says so.

---

## Evidence tiers

| Tier | Meaning |
|---|---|
| **T1** | Named authority confirms malicious or exploited in the wild |
| **T2** | Vulnerability advisory matching the exact purl@version |
| **T3** | Heuristic signal (lookalike name, staleness, very new) |
| **CONTEXT** | Scope, depth, install-script flag, user answers |
| **ABSENT** | A check that could not run (never treated as clean) |

---

## Public data sources

- **[OSV](https://osv.dev)** — vulnerabilities and malware reports (MAL-\*)
- **[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)** — exploited vulnerabilities
- **[EPSS](https://www.first.org/epss)** — exploitation probability scores
- **[deps.dev](https://deps.dev)** — license metadata
- **[npm registry](https://registry.npmjs.org)** — publish times, metadata

All keyless. No account required.

---

## Warrant Watch — continuous dependency monitoring

> A continuous security-evidence monitor for the exact dependency versions already analysed by Warrant.

Warrant does not stop after the first analysis. After analysing a `package-lock.json`, click
**Monitor this project** on the report. Warrant remembers the exact dependency state it analysed and keeps
checking for **new security evidence** about those exact versions, with no re-upload. When the evidence changes
a decision, it re-runs the existing decision engine, compares old vs new, records a **security-change event**,
notifies you in the app, and keeps the updated analysis available.

```
analysed lockfile ─▶ Monitor this project ─▶ stored dependency snapshot + baseline decisions
                                                       │  scheduler, every WATCH_INTERVAL_MINUTES
                                                       ▼
        existing pipeline: graph ▶ OSV / KEV / EPSS ▶ derive_decisions (R1–R7) ▶ report
                                                       │
                old vs new decision ─▶ meaningful? ─▶ SECURITY CHANGE DETECTED + updated report
```

It is **not** a code scanner, runtime agent, malware sandbox or exploit simulator, and it does not claim to
monitor every security event on the internet. It never installs or executes packages.

### What is monitored

| Evidence | Source (existing providers) | Can change a decision via |
|---|---|---|
| New vulnerability advisory for the exact `purl@version` | OSV | R3 UPGRADE / R4 MONITOR |
| New malicious-package report (OpenSSF `MAL-*`) | OSV | R1 INCIDENT, R1' carry to ancestors |
| Advisory withdrawal | OSV `withdrawn` | de-escalation |
| Advisory correction (e.g. fixed version) | OSV record fields | changed response |
| CISA KEV listing of an advisory's CVE | CISA KEV catalogue | R2 ACT NOW (prod) |
| EPSS crossing the threshold (score jitter below it is ignored) | FIRST EPSS | R2 ACT NOW (prod) |

Security-evidence caches (`osv_*`, `cisa_kev`, `epss_*`) are re-fetched on every live check; registry and
license caches are reused.

### When is a change "meaningful"?

Verdicts, urgencies, qualifiers and responses all come from the existing engine. Watch adds no score of its own.

| Previous → current | Event |
|---|---|
| any → UPGRADE / ACT NOW / INCIDENT (escalation) | always; INCIDENT and ACT NOW are **high** priority (from the engine's urgency) |
| NO KNOWN FINDING → MONITOR | yes (a new advisory exists) |
| NO KNOWN FINDING → REVIEW | only if security evidence changed (heuristic drift is silent) |
| same actionable verdict with changed urgency / qualifier / response / fix version / rule, or new T1 evidence | yes (`EVIDENCE_CHANGE`) |
| actionable → lower, e.g. advisory withdrawn | yes (`DE_ESCALATION`, never presented as "safe") |
| same verdict + extra advisory with the same fix, text-only edits, EPSS jitter | no event (the check records "evidence changed") |

### Failure handling, idempotency, time

- **Provider failure is never a clean result.** If OSV is unreachable the check is `failed` and previous
  decisions are kept. If KEV, EPSS, an OSV record or the npm registry fails, the check is `partial`:
  escalations backed by evidence that *was* retrieved are still reported, but nothing is de-escalated.
  Messages read e.g. *"Monitoring partially completed — CISA KEV unavailable."*
- **No duplicate alerts.** Events carry a dedupe key and are committed in the same SQLite transaction as the
  new baseline (compare-and-swap on a revision number). Re-checking unchanged evidence, or restarting the app
  or the scheduler, never repeats an alert.
- **The clocks stay separate.** Evidence publication time, observation time, detection time and report
  generation time are recorded separately, and every re-analysis has its own as-of. The original analysis is
  never modified, and monitored reports are kept beyond the 24 h report TTL.

### Running it

Monitoring runs automatically inside the API process: an asyncio scheduler starts with the app, so there are
no extra services. Restart the backend after upgrading so the scheduler starts.

| Variable | Default | Meaning |
|---|---|---|
| `WATCH_ENABLED` | `1` | `0` turns Watch off completely; analysis behaves exactly as before |
| `WATCH_SCHEDULER_ENABLED` | `1` | Run the background scheduler |
| `WATCH_INTERVAL_MINUTES` | `60` | Time between live checks per monitored project |
| `WATCH_REPLAY_INTERVAL_SECONDS` | `10` | DEMO / REPLAY: delay before the check that follows each recorded release (idle replays fall back to the live interval) |
| `WATCH_TICK_SECONDS` | `5` | How often the scheduler looks for due checks |

In the UI, every npm report has a Warrant Watch panel showing status, dependencies monitored, last and next
check, evidence as-of, security changes, and Check now / Pause / Resume / Stop controls. There is also an
in-app alert banner, and `/watch` lists all monitored projects. A manual live check runs a full re-analysis
against public providers, so it can be triggered once every 30 seconds per project. API: `POST /api/watch {report_id}`, `GET /api/watch`,
`GET /api/watch/{id}`, `GET /api/watch/by-report/{report_id}`, `POST /api/watch/{id}/check|pause|resume|disable`,
`POST /api/watch/{id}/events/ack`, `GET /api/watch/alerts`.

### Demo / replay (DEMO / REPLAY / SIMULATED EVENT)

To show monitoring without waiting days for a real advisory, open **Watch → Replay demo**:

1. **Start replay** — Warrant analyses a recorded project at a simulated start time and enables monitoring.
2. **Release next recorded evidence** — the simulated clock moves to the next moment real recorded evidence became available.
3. Within about 10 s the scheduler detects it on its own, re-runs the engine and shows the old vs new decision.

| Scenario | Project | What happens |
|---|---|---|
| `slack-action-axios-2026-04` | **Real**, unmodified `slackapi/slack-github-action@a8dafde` lockfile (2026-04-01) | 2026-04-09: real `GHSA-3p68-rc4w-qgx5` → `axios@1.14.0` NO KNOWN FINDING → UPGRADE. A second axios advisory with the same outcome raises no alert. 2026-04-14: `follow-redirects` → UPGRADE |
| `axios-compromise-2026-03-31` | Counterfactual lockfile pinning `axios@1.14.1` (labelled as such in the fixture) | Real `MAL-2026-2306` / `MAL-2026-2307`, released at their OSV import times: `plain-crypto-js@4.2.1` and `axios@1.14.1` → INCIDENT (high priority), then axios gets its own malware report (R1' → R1) |

All replay evidence is real: raw OSV/OpenSSF records, OSV's own match results, a CISA KEV subset, historical
EPSS scores and npm publish times. It was recorded by `backend/tools/record_watch_replay.py` from Warrant's
allowlisted hosts, and each file is pinned by SHA-256 in its `scenario.json` (verified on load). Nothing later
than the simulated clock is ever served. Every replay watch, check, event and report is labelled
**DEMO / REPLAY / SIMULATED EVENT** and is never presented as live.

### Watch limitations

- npm `package-lock.json` analyses only. requirements.txt and imported reports have no stored dependency state.
- Detection latency is bounded by `WATCH_INTERVAL_MINUTES` and by how quickly OSV / KEV / EPSS publish.
- Replay records are the snapshot taken when recorded. Availability is time-gated, but earlier text revisions of a record are not available.
- Heuristic age signals (staleness / freshness) are computed by the existing engine against the real current time, including in replay.

---

## Backend tests
```bash
cd warrant/backend
python -m pytest tests/ -v
```

Covers R1–R7, withdrawn record exclusion, as_of temporal filter, placeholder version trap, lookalike, CVSS, license rules, verifier (`tests/test_warrant.py`), security guards (`tests/test_security.py`), Warrant Watch (`tests/test_watch.py`) and regression tests for engine edge cases, graph resolution and paths, provider failure handling and the report API (`tests/test_hardening.py`). Provider tests run the real provider code against an offline fake of the public APIs; no network is needed.

## Project structure
```
warrant/
├── backend/
│   ├── app/
│   │   ├── main.py           # FastAPI app
│   │   ├── jobs.py           # Analysis orchestrator
│   │   ├── config.py         # Settings
│   │   ├── security.py       # Input sanitisation
│   │   ├── api/              # Routes
│   │   ├── engine/           # Decision engine (rules.py, decide.py)
│   │   ├── graph/            # Dependency graph builder
│   │   ├── licenses/         # SPDX parser + license rules
│   │   ├── models/           # Pydantic models
│   │   ├── parsers/          # npm lockfile + requirements.txt
│   │   ├── providers/        # OSV, EPSS, KEV, deps.dev, npm, cache, provider health
│   │   ├── signals/          # Lookalike, staleness, CVSS profile
│   │   └── watch/            # Warrant Watch: monitor, comparison, store, scheduler, replay feed
│   ├── fixtures/samples/     # Demo lockfiles
│   ├── fixtures/watch_replay/ # Recorded real-source evidence for DEMO / REPLAY scenarios
│   ├── tools/                # record_watch_replay.py (replay scenario recorder)
│   └── tests/                # pytest suite
└── frontend/
    ├── src/
    │   ├── routes/           # Landing, Analyze, Report, Methodology
    │   ├── lib/              # API client, types, format utils
    │   └── styles/           # Design tokens + global CSS
    └── vite.config.ts
```

---

## Known limitations

- Package-level analysis only — function-level reachability is not assessed
- Heuristic signals (lookalike, staleness) are never decisive alone — always REVIEW tier
- CANNOT ASSESS ≠ safe. A required check did not run
- NO KNOWN FINDING ≠ safe. All checks ran, as of this timestamp
- Only npm package-lock.json (v2/v3) and pinned requirements.txt supported
- EPSS threshold (0.10) and freshness horizon (72h) are defaults, not empirically validated
- Public data may lag behind actual events
- Up to 10 dependency paths are listed per package (shortest first, ties ordered by package id), and paths longer than 50 edges are not listed
- npm registry metadata is fetched for the first 50 direct dependencies; the others are reported as not fetched
- In offline fixtures mode (`OFFLINE_FIXTURES=1`), anything not in the recorded cache is reported as not checked. Nothing is fetched live and nothing is assumed clean
