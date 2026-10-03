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
| R6 | Required check could not run | CANNOT ASSESS |
| R7 | All checks ran, nothing found | NO KNOWN FINDING |

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

## Backend tests
```bash
cd warrant/backend
python -m pytest tests/ -v
```

27 tests covering R1–R7, withdrawn record exclusion, as_of temporal filter, placeholder version trap, lookalike, CVSS, license rules, verifier.

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
│   │   ├── providers/        # OSV, EPSS, KEV, deps.dev, npm, cache
│   │   └── signals/          # Lookalike, staleness, CVSS profile
│   ├── fixtures/samples/     # Demo lockfiles
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
