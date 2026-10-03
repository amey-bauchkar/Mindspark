# Warrant: Software Supply Chain Risk Analyzer — Build Plan and Antigravity Prompt

Sources analyzed: the Problem Statement (screenshot), the team's three research files, the Master Information file, and Deep Research Phases 1–4. Phases 5–10 do not exist yet and were not assumed.

Note: the Phase 2 file stops at §7 and the Phase 4 file stops at §25, though both refer to later sections. Only what is on the page was used.

---

## 1. Executive Understanding

**The PS** asks for a tool that takes a manifest or lock file and produces a clear, usable report covering five things: known vulnerabilities with severity, vulnerable transitive dependencies, suspicious packages, license issues, and attack paths from a deep weakness to the application.

**What the research says together:**
- Items 1–2 (known vulnerabilities, transitive dependencies) are free and commoditized. OSV-Scanner, Dependabot and Trivy all do them, so a plain CVE dashboard earns no credit.
- The hard parts are judging what matters (vulnerable ≠ exploitable ≠ priority), suspicious ≠ malicious, and attack paths. The recent big incidents (axios 2026, Shai-Hulud, xz) were malicious releases with no CVE.
- Free keyless real data (OSV, deps.dev, EPSS, CISA KEV, npm registry) covers almost everything. Real data beats mocks.
- Two warnings recur in the research: **"unknown must never look like safe"** and **no opaque scores**.
- Nothing here is a clean "first". Novelty confidence is MEDIUM-LOW, so the pitch is "one auditable, honest decision per risky dependency", not "first ever".

---

## 2. Research Synthesis

| Source | What it contributes | Status for MVP |
|---|---|---|
| **PS** | Five required outputs, input = manifest/lockfile, "clear, usable report" | Essential. Defines scope. |
| **Your skeleton** | Upload → parse → dashboard flow; 6 features (transitive mapper, typosquat, attack path/blast radius, license matrix, remediation, host-impact "deadliness") | Flow is Essential. Features 1, 3, 4 and 5 are Essential. Feature 2 is Essential as a labelled heuristic. Feature 6 is reshaped. |
| **Your plan** | Unified Risk Graph, fix optimizer, maintainer trust, context-aware licenses, slopsquatting, version-diff, lockfile time-travel, blast radius, reachability-lite, LLM summary, SBOM, stack (FastAPI, networkx, React, Cytoscape, SQLite) | Core + stack adopted. Context-aware licenses and blast radius are Useful. Fix optimizer is a "light" version. The rest is Future. |
| **Phase 1** | Five distinctions to keep apart; real free data sources; personas; the "unknown ≠ safe" rule; confidence tiers | Essential. Shapes the data model and UI language. |
| **Phase 2** | Commoditized vs thin areas; no free tool unifies path + trust signals + evidence tiers into one explained decision | Essential for positioning. |
| **Phase 3** | Selected concept "Warrant": evidence tiers T1/T2/T3, six verdict classes, response class depends on evidence class, narrow novelty claim | Essential. This is the product spine. |
| **Phase 4** | Decision object, printed rule table R0–R7, no scalar score, typed paths, freshness-aware abstention, as-of replay, LLM can never decide, lockfile v3 fields verified, axios replay data | Essential (decision table, path typing, abstention). The as-of slider is Useful. The rest is Future. |
| **Master Info** | "Why is this here?" explanation, evidence-labelled paths, one-ecosystem-deeply, dangerous-feature list (opaque AI score, malware sandbox, exploit simulator, legal oracle) | Essential as guardrails. |

**Overlaps resolved:** Your "Unified Risk Graph" and Phase 3's "Evidence-Ledger Verdicts" are the same idea. The graph is the data structure and the evidence-backed verdict is the output. Your "Blast Radius" and "Attack Path" features share one graph traversal.

---

## 3. Key Conflicts / Decisions

| Conflict | Decision and why |
|---|---|
| **Numeric risk score and "Deadliness score"** (your plan and skeleton) vs **no scalar score** (Phase 4, Master §19.2) | **No scalar.** Use named verdicts with a visible rule table. A black-box number is untrustworthy, and Phase 1 shows CVSS-style thresholds are poor prioritizers. Feature 6 becomes an **Impact profile**, a plain-English reading of the CVSS vector (network-reachable, no privileges needed, high confidentiality/integrity/availability impact), labelled "from CVSS vector, not confirmed exploitability". A vector cannot prove RCE or file-read, so we don't claim it. |
| **Levenshtein typosquat = "detector"** (your plan) vs **edit distance is not enough** (Phase 1 F4; malware heuristics have 15–97% false positives) | Keep it, but it only produces a **REVIEW** (T3 heuristic) flag, never INCIDENT. Copy says "lookalike of `x` (distance 1), heuristic only". Combine with age and last-publish metadata where fetched. |
| **"Reachability-lite" and "exploit simulator"** vs **call graphs are unsound; dangerous scope** | **Out.** Package-level paths only. "Reachability: not assessed" always appears in the Not-checked list. |
| **Multi-ecosystem input** (skeleton lists npm, poetry, requirements, pom) vs **one ecosystem deeply** | **`package-lock.json` (v2/v3) fully.** Pinned `requirements.txt` is accepted as a limited adapter: vulnerabilities and licenses work, but edges are unknown, so paths show **UNKNOWN**. This demonstrates "unknown ≠ safe" and shows the PS's other formats were considered. Maven and poetry are Future. |
| **LLM executive summary** (your plan) vs **LLM may never decide; extraction from malware advisories is probably unnecessary** | The summary is a **deterministic template first**. An optional LLM narrator is gated by a verifier and enabled only if an API key exists. No key means no LLM UI. |
| **Fix optimizer (minimal cut)** vs **feasibility** | Light version: show which direct dependency introduced the risk, the advisory's fixed version, a copyable `npm install` or `overrides` snippet, and a **Simulate fix** button that re-queries the fixed version. Labelled "simulated, not installed". |
| **Slopsquatting, version-diff, maintainer takeover, lockfile git time-travel, PR gate, SBOM/VEX, continuous monitoring** | **Future.** Each needs data or infrastructure we don't have. Architecture leaves provider slots. |
| **"DAG"** (skeleton) vs real npm graphs | npm graphs can have cycles (peer deps). Use a directed graph with a cycle guard. |
| **Phase 3 demo "CVE sorters show nothing"** | Dropped per Phase 4. Existing tools do surface MAL-* advisories, so the demo shows what Warrant decides and why. |
| **Bitemporal engine** vs prototype | Engine is a pure function of (graph, evidence, context, `as_of`). The only UI exposure is an **as-of slider**. |
| **"First/only" claims** (your plan: "first to unify") | Soften. UI copy never says first or only. |

---

## 4. Recommended Product

**Warrant** (working name; check for name clashes) takes a lockfile and returns **one explained decision per risky dependency** instead of a CVE list.

- **Core problem:** developers can't see what they're built from, and tools give flat alerts, opaque scores and no sign of what was never checked.
- **Primary user:** a developer or DevSecOps engineer deciding "what do I do first, and what exactly do I change?" The evidence drawer serves analysts. The summary line serves managers.
- **Central journey:** drop a lockfile → answer up to 3 context questions → see "1 incident, 2 act-now, 5 upgrade, 3 cannot-assess in 312 packages" → open a card → see evidence, path, certainty, action and what wasn't checked.
- **Value proposition:** every verdict is computed by a printed rule table from source-attributed evidence. Unknowns are explicit, and the response matches the kind of evidence (incident vs upgrade vs review).

Your six features fit naturally:

| Skeleton feature | Where it lives in Warrant |
|---|---|
| 1 Transitive mapper | Graph + "Introduced by" on every card |
| 2 Typosquat/suspicious | T3 evidence, REVIEW verdicts |
| 3 Attack path / blast radius | Path view + "If compromised…" dependents panel |
| 4 License matrix | Licenses tab, driven by the context questions |
| 5 Remediation | "What to do" + Simulate fix |
| 6 Host impact | Impact profile (no score) |

---

## 5. MVP

### Must Have

| Feature | What / why | Backend | Real API? |
|---|---|---|---|
| Lockfile upload (drag-drop, paste, samples) | Entry point (PS) | Yes | n/a |
| npm lockfile parser + **edge reconstruction** (nearest-ancestor resolution), scope (prod/dev/optional), `hasInstallScript` | Transitive visibility (PS 2), paths (PS 5) | Yes | n/a |
| Vulnerability + malware lookup via OSV batch (incl. `MAL-*`, aliases, withdrawn handling) | PS 1, 3 | Yes | **OSV, real** |
| EPSS + CISA KEV for CVE aliases | Prioritization (Phase 1 F8) | Yes | **Real** |
| Evidence records with tiers T1/T2/T3/Context/Absent | Phase 3 core | Yes | n/a |
| Printed decision table → 7 verdicts, no scalar | Core claim | Yes | n/a |
| Decision cards grouped by action, with "Not checked" always shown | Core UX | No | n/a |
| Path view (typed, ⚠ on install scripts) + "Why is this here?" | PS 5 | Yes | n/a |
| Typosquat lookalike heuristic (bundled top-package list; REVIEW only) | PS 3 | Yes | Optional registry metadata |
| License detection + context-aware conflict rules | PS 4 | Yes | deps.dev for missing licenses |
| Context questions (distribution, project license, scripts enabled), skipped = assumed and labelled | Context-aware reasoning | Yes | n/a |
| Methodology page that renders the *actual* rule table | Trust/auditability | Yes | n/a |
| Fixtures: replayed axios-style incident, legacy vulnerable app | Demo, labelled | Yes | Recorded real data |

### Should Have

| Feature | Notes |
|---|---|
| Light remediation: introduced-by, fixed version, command/overrides snippet, **Simulate fix** (re-query, verdict delta, labelled simulated) | Fix optimizer light |
| Impact profile from CVSS vector (plain English, no score) | Feature 6, reshaped |
| Blast radius panel ("what depends on this") | Reuses graph |
| **As-of slider**: re-derive decisions using only evidence published up to time T | Phase 4's temporal idea, pure function |
| JSON + Markdown report export | PS "usable report" |
| `requirements.txt` (pinned) adapter, direct-only | Shows UNKNOWN paths |
| Deterministic narrator + **verifier self-test** (a synthetic corrupted claim is rejected) | Verified narration, no LLM needed |
| Optional LLM narrator behind env key | Only if everything else is done |

### Future / Phase 2 (architecture leaves a slot, nothing built)

Release-diff, maintainer-trust scoring, slopsquatting, lockfile git-history forensics, PyPI/Maven full resolvers, SBOM/VEX/SARIF, draft PRs and CI gate, continuous monitoring, reachability/source-use analysis, org rollups, accounts, evaluation/metrics page, provenance checks.

---

## 6. User Journey

1. **Landing:** headline "Know what your software is really built from, and what to fix first." Primary action is a drop zone plus "Try a sample".
2. **Input:** drop `package-lock.json` or pick a sample.
3. **Context (≤3 questions):** how it's distributed, project license, whether install scripts run in CI/dev. Skipping is allowed, and skipped answers show as "assumed".
4. **Analysis screen:** a live checklist of real stages (parse, graph, OSV, EPSS/KEV, licenses, signals, decisions) with counts.
5. **Report:** summary sentence, verdict chips, action groups, decision cards.
6. **Card → drawer:** what's wrong, how we know, how certain, path, impact profile, what to do, not checked, derivation.
7. **Act:** copy commands, Simulate fix, export.
8. **Return:** reports reload by URL (kept 24 h locally), recent reports on the Analyze page, JSON export that can be re-imported.

---

## 7. Website / Route Structure

| Route | Purpose |
|---|---|
| `/` | Landing: value, how it works, honesty statement, samples |
| `/analyze` | Upload/paste/sample + 3 context questions |
| `/report/:id` | Main report (tabs: Decisions, Graph, Licenses, Coverage) |
| `/methodology` | The printed rule table, data sources, limits, glossary |
| `*` | 404 |

No login, pricing or blog pages. Full per-page detail (states, responsive behavior) is in the prompt.

---

## 8. UI/UX Direction

- Calm, light-first interface with a dark variant (follows system), restrained color used only for verdicts.
- Typography is Inter plus JetBrains Mono for package names and versions.
- **Verdict colors:** INCIDENT deep red, ACT NOW orange, UPGRADE amber, MONITOR blue, REVIEW violet. CANNOT ASSESS is hatched grey. NO KNOWN FINDING is neutral outline and **never green**.
- Graph shows only the selected path by default, so it doesn't turn into a hairball.
- Minimal motion (150 ms, reduced-motion respected). No neon, glow or glassmorphism.
- Plain English first, technical detail one click away.

---

## 9. Technical Architecture

- **Frontend:** React + Vite + TypeScript, Tailwind, React Router, TanStack Query, Cytoscape.js (+ dagre layout), lucide-react.
- **Backend:** Python FastAPI. A backend is needed because OSV/deps.dev/registry calls need batching, caching and backoff, and the engine is Python (networkx). It never executes `npm` or any user code.
- **Database:** SQLite for the API response cache and stored reports (24 h TTL).
- **Auth:** none. Anonymous, local-first. Uploaded files aren't persisted, only the derived report.
- **Real:** OSV (querybatch + vuln detail), deps.dev, npm registry metadata, EPSS, CISA KEV. All keyless.
- **Recorded (labelled):** replay fixtures captured from real responses, plus a recorded-data fallback if the network is down.
- **Mocked:** nothing in findings. No fabricated advisories or verdicts.
- **Extensibility:** an `EvidenceProvider` interface and the rule table as data, so later research can add signals and tune thresholds without rewriting the engine.

---

## 10. Prototype Development Plan

Order: inspect repo → scaffold → design tokens/layout → parser + graph + tests → providers + cache → engine → API/jobs → landing/analyze → report + cards → drawer + path graph → licenses + signals → remediation/simulate → as-of + export + methodology → states/responsive/a11y → record fixtures + QA → cleanup. The exact steps are in the prompt.

**Assumptions / open questions** (only 4 of 10 research phases exist, and Phases 5–10 may change these):
- EPSS threshold 0.10 and freshness horizon 72 h are defaults, configurable, and not validated.
- Whether an LLM beats regex for extraction is untested. The LLM is optional and last.
- The license rule table is a small hand-built subset, not a legal oracle.
- Edge reconstruction is not yet verified against `npm ls`. Add that as a test.
- Registry rate limits are unverified, so use caps, backoff and caching.

---

## 11. FINAL ANTIGRAVITY IMPLEMENTATION PROMPT

Copy everything inside the block below into Antigravity.

````
# ROLE
You are a senior full-stack engineer building a hackathon-quality but professional PROTOTYPE of a cybersecurity web product called "Warrant" (working name; subtitle "Software Supply Chain Risk Analyzer"). Build incrementally in the order given in "IMPLEMENTATION ORDER". Do not overbuild.

# 0. FIRST: INSPECT BEFORE YOU MODIFY
If a repository already exists: inspect folder structure, framework, package.json / pyproject, existing routes, components and styling BEFORE changing anything. Reuse what fits. Do not delete or overwrite unrelated work; modify only what this prototype needs. If the repo is empty, scaffold the structure in section 14. Prefer existing dependencies; install new packages only with clear value. If something is unspecified, make the smallest reasonable assumption, note it in a short ASSUMPTIONS section in README.md, and continue. Do not invent a different product.

# 1. PROJECT CONTEXT
## Problem statement (verbatim intent)
Modern applications depend on hundreds of third-party libraries, many pulled in indirectly as dependencies of dependencies. A vulnerability or malicious dependency in any of them can compromise the whole application. Developers and security teams lack a clear view of what their software is built from, so risks are hard to find and fix before exploitation.
TASK: Build a tool that takes a project (manifest or lock files) and produces a clear, usable report of what could go wrong. At minimum it must identify:
1. Security risks in dependencies: known vulnerabilities and severity.
2. Vulnerable transitive dependencies pulled in indirectly and easy to miss.
3. Suspicious packages: lookalike names, unmaintained packages, unusual behavior.
4. License issues: licenses that conflict with each other or with how the project is used.
5. Potential attack paths showing how a weakness deep in the dependency tree could reach the application.
(The event is a 24-hour cybersecurity hackathon; the product must be demonstrable with REAL data.)

## Product concept
One product: a lockfile analyzer that produces ONE explained, evidence-backed DECISION per risky dependency, instead of a flat CVE list. Every verdict is computed deterministically from typed, source-attributed EVIDENCE records using a printed rule table. Unknowns are explicit ("CANNOT ASSESS", "Not checked"), never shown as safe. The recommended response depends on the kind of evidence (incident vs upgrade vs review). There is NO numeric risk score.

## Primary user
A developer or DevSecOps engineer deciding "what do I do first, and what exactly do I change?" Secondary: security analyst (evidence drawer), manager (summary line).

## Core objective for this prototype
Upload package-lock.json → real analysis against public data → summary + decision cards grouped by action → evidence/path drawer → licenses → what was not checked → fix guidance → export. Plus a methodology page.

# 2. PRODUCT DECISIONS (do not deviate)
- No scalar/"deadliness"/"risk" score anywhere. Use verdict names + counts only.
- Package-level attack paths only. Never claim function-level reachability or exploit confirmation.
- npm package-lock.json (lockfileVersion 2 or 3) is the one deeply-supported ecosystem. Pinned requirements.txt is a limited adapter (no edges → paths UNKNOWN).
- Typosquat/lookalike and "stale/very new" signals are HEURISTIC (tier T3) and can only produce REVIEW, never INCIDENT.
- "Malicious" may only be stated when a named authority report (OSV MAL-* / OpenSSF / GHSA malware advisory) exists for the exact resolved version. Every such label must show the report ID.
- LLM never decides verdicts, severity, existence of a vulnerability or fix versions. The product must be fully functional with NO LLM.
- Never use the words "first", "only", "AI-powered scanner" in UI copy. Never say "secure" or "safe". Use "No known finding (scope, as-of time)".
- DEFERRED (do not build; leave a clean extension point only): release-diff analysis, maintainer-trust scoring, slopsquatting detection, git-history lockfile forensics, Maven/poetry/PyPI full resolvers, SBOM/VEX/SARIF export, draft PRs/CI gate, continuous monitoring, reachability/source-use analysis, accounts/auth, org dashboards, metrics/evaluation page, malware sandbox.

# 3. EVIDENCE MODEL
Evidence record (one per fact):
{ id: "E1", tier: "T1"|"T2"|"T3"|"CONTEXT"|"ABSENT", source: "osv"|"deps.dev"|"npm-registry"|"epss"|"kev"|"lockfile"|"heuristic"|"user", origin: string (e.g., "amazon-inspector", "GHSA", "OpenSSF"), kind: "malware_report"|"advisory"|"kev"|"epss"|"lookalike"|"stale"|"very_new"|"license"|"install_script"|"scope"|"unresolved_source"|..., subject: "pkg:npm/name@version", claim: short plain statement, url?: string, published_at?: ISO, retrieved_at: ISO, quote?: string, withdrawn: boolean, data: object }
Tiers: T1 Reported (named authority says malicious, or CISA KEV exploited) · T2 Advisory (vulnerability advisory matching the exact resolved version) · T3 Heuristic (our rules on metadata; never decisive alone) · CONTEXT (scope, path, depth, install-script flag, user-declared answers) · ABSENT (a check that could not run, with reason).
Withdrawn OSV records are excluded from verdicts (kept in the evidence list marked "withdrawn"). Placeholder/"-security" versions (e.g., 0.0.1-security) must not trigger INCIDENT unless the resolved version matches. Match only on the exact resolved purl@version.

# 4. DECISION ENGINE (deterministic, pure function of graph + evidence + context + as_of)
Per risky node produce a Decision object:
{ subject, verdict, urgency, qualifier, exposure: { paths: string[][] (root→node), scope: "prod"|"dev"|"optional" (+ provenance), install_phase: "observed"|"unknown" , scripts_enabled: "declared"|"assumed" }, evidence_ids[], open_defeaters[], unrun_checks[], response: { class, steps[], commands[] }, as_of, derivation: ["R1 ← E3", ...] }
Verdicts: INCIDENT · ACT NOW · UPGRADE · MONITOR · REVIEW · CANNOT ASSESS · NO KNOWN FINDING.
Urgency: IMMEDIATE · OUT-OF-CYCLE · SCHEDULED · DEFER · NONE. Qualifier: ESTABLISHED · PROBABLE · POSSIBLE · UNKNOWN (PROBABLE when a T1 report has a single origin).
Rule table (store as DATA in backend/app/engine/rules.py or rules.json; the /methodology page renders THIS data; precedence top-down per node; a positive verdict is never masked by an abstention; unrun checks and open defeaters are always attached):
- R1: active T1 malware report matches the node's exact resolved version, any scope, any depth → INCIDENT / IMMEDIATE / response class "containment" (remove or pin to last version before first affected if determinable from data; assume secrets exposed on machines that installed it; rotate from a clean machine; check exposure window; human approval required).
- R1': ancestors of an R1 node are shown as "carries incident via path" (decision lives on the descendant).
- R2: T1 KEV, OR T2 with EPSS ≥ θ (default 0.10, configurable constant), on a node with a runtime-scope path → ACT NOW / IMMEDIATE or OUT-OF-CYCLE → response "minimal upgrade/override".
- R3: T2 advisory with a fixed version, runtime-scope path → UPGRADE / SCHEDULED.
- R4: T2 only on dev/optional-only paths → MONITOR / DEFER.
- R5: T3-only (lookalike, stale, very new), license flag, or unresolved source conflict → REVIEW / SCHEDULED (human review; never auto-escalated).
- R6: none of R1–R5 AND (a required check could not run, OR package version younger than freshness horizon h (default 72h, needs registry publish time), OR identity unresolved e.g. git/file/tarball dependency, OR edges unknown) → CANNOT ASSESS (state the reason).
- R7: all required checks completed, nothing found → NO KNOWN FINDING (always print scope and as-of).
Scope rule: a node is "prod" if ANY root→node path uses only non-dev, non-optional edges; "dev/optional" only if ALL paths are. Use lockfile flags (dev/optional) and path computation; if they disagree show the more conservative one and note it.
Counting rule: count unique purl@version nodes, never paths or advisories.
Severity from OSV: show CVSS base severity text and vector as given, but they only inform display; they do not choose verdicts except via EPSS/KEV rules above.
as_of: every decision is computed with only evidence whose published_at ≤ as_of (default = now). Expose as_of via API param.

# 5. FEATURE BEHAVIOR

## 5.1 Parsing and graph (backend)
- Parse package-lock.json v2/v3 ("packages" map). Keys like "node_modules/a/node_modules/b". Root entry "" holds dependencies/devDependencies/optionalDependencies/peerDependencies.
- For each package, its dependency requirement map is resolved to a node using Node's nearest-ancestor node_modules lookup (walk up the key path, then top-level). Skip links/workspaces gracefully (mark ABSENT/unresolved). Record per node: name, version, resolved host, integrity presence, license (if present), dev, optional, hasInstallScript, depth, introduced_by (nearest direct ancestor(s)).
- Use networkx DiGraph with cycle guard (peer deps can create cycles). Path enumeration root→node via bounded DFS (cap paths per node, e.g., 10, and show "+N more").
- Detect non-registry sources (git+, file:, http tarball, link) → identity unresolved → CANNOT ASSESS ("not checked against registries").
- If lockfileVersion 1 or malformed: reject with a clear message (explain what's supported).
- requirements.txt adapter: only `name==version` lines; unpinned lines → CANNOT ASSESS ("version range, cannot resolve"); no edges → every path-based statement says "paths unknown, direct dependencies only". Never say "unreachable".
- Write pytest tests, including one that reconstructs edges for a small lockfile and (if npm is available offline) compares against `npm ls --all --json` generated from `npm install --package-lock-only --ignore-scripts` on a tiny project; if not available, test with a hand-built fixture.

## 5.2 Evidence providers (backend; each is a class with a common interface so new signals can be added later)
- OSV: POST https://api.osv.dev/v1/querybatch (chunks ≤1000 queries, package {purl} or {name, ecosystem:"npm", version}), then GET /v1/vulns/{id} for details (cache; fetch only for IDs found). Handle MAL-* ids, `withdrawn`, `aliases` (CVE/GHSA), `affected[].ranges` fixed events, `severity` (CVSS vectors), `published`, `modified`, `database_specific`.
- EPSS: https://api.first.org/data/v1/epss?cve=CVE-1,CVE-2 (batch). CISA KEV JSON feed (https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json), cache daily. Only applied to CVE aliases; for non-CVE items show "EPSS n/a, KEV n/a (no CVE)".
- deps.dev API v3 (https://api.deps.dev/v3/systems/npm/packages/{name}/versions/{version}) for license when the lockfile lacks it. Limit to nodes missing a license.
- npm registry (https://registry.npmjs.org/{name}) for publish `time` map and created date. To control request volume, fetch only for: direct dependencies, nodes with lookalike candidates, nodes with a T1/T2 finding. Others record an ABSENT "registry metadata not fetched" entry (shown in Coverage). Use bounded concurrency, timeouts, retries with exponential backoff, and SQLite caching (TTL: vulns 6h, KEV/EPSS 24h, registry 6h).
- Allowed outbound hosts are a FIXED allowlist (api.osv.dev, api.deps.dev, registry.npmjs.org, api.first.org, www.cisa.gov). Never fetch URLs taken from user input or lockfile fields.
- If a provider fails: record ABSENT evidence with the reason and continue. Never crash the analysis and never treat failure as "clean".
- Offline mode (env OFFLINE_FIXTURES=1): serve recorded real responses from backend/fixtures/recorded/ and show a persistent banner "Recorded data, not a live lookup".

## 5.3 Heuristic signals (tier T3, REVIEW only)
- Lookalike: compare each package name to a bundled curated list of popular npm packages (create backend/app/data/popular_npm.json with ~300 well-known names; state in its header that it is a curated seed list, not exhaustive). Use Damerau-Levenshtein and Jaro-Winkler plus simple checks (character swaps, hyphen/underscore variants, scope confusion). Exclude exact matches and names in the list. Message: "Name is 1 edit from `express` — heuristic only, not evidence of malice." Do not flag short names (<5 chars) unless distance 1 with a very popular package.
- Stale: last publish > 2 years (needs registry metadata) → "Possibly unmaintained (last release YYYY)". Very new: first published < 30 days → "Very new package". Both T3.
- Install script: node has hasInstallScript → CONTEXT evidence; on a path shows ⚠. It raises attention only.

## 5.4 Licenses (backend rules + UI tab)
- Inputs: SPDX license per node (lockfile, else deps.dev), context answers: distribution mode ∈ {SaaS / network service, Distributed app or binary, Internal tool only, Open-source library}, project license ∈ {Proprietary, MIT, Apache-2.0, GPL-3.0-or-later, Unknown}.
- Parse SPDX expressions (OR = pick the most permissive alternative and say so, AND = all apply, WITH = note exception). Write a small parser; do not add heavy dependencies unless needed.
- Rule table (data file, shown on /methodology): permissive (MIT, BSD-2/3-Clause, ISC, Apache-2.0, 0BSD, Unlicense, CC0-1.0, BlueOak-1.0.0) → OK. Weak copyleft (LGPL-*, MPL-2.0, EPL-*) → REVIEW if distributed. Strong copyleft (GPL-2.0-only/or-later, GPL-3.0-*) → CONFLICT if project is Proprietary and distributed; REVIEW otherwise. AGPL-3.0 → CONFLICT if Proprietary and (SaaS or distributed); REVIEW otherwise. GPL-2.0-only with Apache-2.0 project → CONFLICT (incompatibility). Source-available (SSPL, BUSL, Commons-Clause, Elastic) → REVIEW. UNLICENSED / "SEE LICENSE IN" / missing → REVIEW (no license) or CANNOT ASSESS (unknown). Missing license never shows as OK.
- Each issue shows the introducing path and the rule that fired. Footer on the tab: "Rule-based flags for review, not legal advice."
- License verdicts feed REVIEW (R5); they appear in the Licenses tab with labels CONFLICT / REVIEW / UNKNOWN / OK.

## 5.5 Impact profile (Should)
Parse CVSS v3.x vectors (and v4 base metrics if simple) from OSV severity into plain English: attack vector, complexity, privileges, user interaction, scope, C/I/A impact. Render as labelled chips with the caption "Read from the CVSS vector. This is not confirmed exploitability on your system." No score of our own, no "RCE" claims unless the advisory text itself says so (then quote it).

## 5.6 Remediation (Should)
For each decision: show "Introduced by" direct dependency(ies); fixed version from the advisory (OSV `fixed` event) if any; copyable commands: `npm install <direct>@<version>` for direct deps, and a package.json `"overrides"` snippet for transitive deps. For INCIDENT show the containment checklist (deterministic text) instead of "just upgrade". Never suggest a version the data does not contain; if unknown say "No fixed version in the advisory".
"Simulate fix" button: in memory, replace the node's version with the fixed version, re-query OSV/KEV/EPSS for that exact version, re-derive the decision, and show a before→after verdict delta. Label: "Simulated. Assumes the new version's own dependencies are unchanged; not installed." Check that no new T1/T2 evidence appears for the new version and report "New risks introduced: none found / N found".

## 5.7 Blast radius (Should)
On any node: list direct and transitive DEPENDENTS (reverse traversal), the direct dependencies that pull it in, scope, and install-script flag. Caption: "Structural only. We do not know what this package can access at runtime."

## 5.8 As-of slider (Should)
On the report header: "Evidence as of [date-time]" with a slider over distinct evidence timestamps (published_at). Changing it calls the engine with as_of and updates verdicts, with a banner "Replaying evidence known at this time; graph is the uploaded lockfile". Pure re-derivation, no new network calls.

## 5.9 Narration and verifier (Should)
- Default narrator: deterministic template that renders the decision as sentences from fields only. Label: "Generated from rules, no AI".
- Verifier (deterministic): given claims JSON {claim_type, entities, numbers, evidence_ids[]}, reject unless every evidence ID exists in the decision, every entity/number appears in the decision's evidence slice, and verdict words match the decision. Add a "Verifier self-test" control that submits a synthetic corrupted claim (labelled "synthetic test") and shows it rejected with the failing gate. This works without any LLM.
- OPTIONAL: LlmNarrator behind env LLM_PROVIDER/LLM_API_KEY. If unset, the UI shows nothing LLM-related. If set: temperature 0, no tools, evidence passed as inert delimited data with IDs, untrusted advisory text stripped of control/bidi characters and length-capped, output must be a closed JSON claim schema, must pass the verifier or fall back to the template; show "Verified" / "Rejected → template". Implement last and only if everything else is done.

## 5.10 Export
JSON report (full decisions + evidence + coverage, with schema_version) and Markdown summary. JSON can be re-imported on /analyze to view without re-running. Print stylesheet for the report page.

# 6. DATA AND SAMPLES
Samples (selectable on / and /analyze; all findings must come from real lookups or clearly labelled recorded real responses, NEVER hard-coded verdicts):
1. "Legacy Express app" — generate a real lockfile with pinned old versions (e.g., an old express plus old lodash/minimist/etc.) using `npm install --package-lock-only --ignore-scripts` in a scratch folder if npm is available; commit the resulting package-lock.json as backend/fixtures/samples/legacy-express/package-lock.json. Expect many T2 findings, deep transitive paths, mixed prod/dev. Add one git-URL dependency to produce a CANNOT ASSESS case, and one permissive plus one copyleft package to exercise licenses (choose real packages; do not invent license data).
2. "Incident replay: compromised axios release (Mar 2026)" — a RECONSTRUCTED lockfile fixture where axios@1.14.1 depends on plain-crypto-js@4.2.1 (which has an install script), labelled "Replay fixture: reconstructed lockfile; evidence is recorded from real OSV/OpenSSF records". At build time, if network is available, fetch live OSV records MAL-2026-2306 (plain-crypto-js) and MAL-2026-2307 (axios) and the npm registry `time` map for those versions, and store them in backend/fixtures/recorded/. Known reference data from research: MAL-2026-2306 was published 2026-03-31T02:07:58Z (single origin: Amazon Inspector), MAL-2026-2307's record appeared 2026-03-31T03:15:49Z; the dependency had a report about 68 minutes before its parent did. If you cannot fetch real records, STOP and tell the user instead of fabricating them. Note the trap: advisory affected lists can include the placeholder version 0.0.1-security; the exact-version rule must prevent a false INCIDENT on remediated state. Expected behavior with the as-of slider: at 02:10Z the decision lands on plain-crypto-js (INCIDENT, PROBABLE) and axios shows "carries incident via path"; after 03:15Z axios has its own report.
3. "Python requirements (limited)" — a small pinned requirements.txt: demonstrates vulnerabilities and licenses but "paths unknown".
Provide scripts/record_fixtures.py that regenerates recorded responses, and document it in the README.

# 7. WEBSITE PAGES AND ROUTES (React Router)
Global layout: top bar with logo "Warrant", links Analyze · Methodology, a small "Data: live / recorded" indicator, footer with honest limits ("Package-level analysis. Public data sources. Not legal advice. No code is executed.").

## `/` Landing
Purpose: explain value in 10 seconds. Sections: (1) Hero: headline "Know what your software is really built from — and what to fix first." Subhead: one sentence on lockfile → evidence-backed decisions. Actions: primary "Analyze a lockfile" (→/analyze), secondary "Try the incident replay". (2) "How it works" 4 steps (Drop lockfile · Rebuild the full tree · Check public evidence · Get decisions with proof). (3) A static, clearly-labelled EXAMPLE decision card illustrating the format (caption "Example output format"). (4) "What we check / what we don't" two columns (honesty). (5) Data sources strip (OSV, deps.dev, EPSS, CISA KEV, npm registry) as text, no fake logos. Responsive: single column on mobile, no horizontal scroll.

## `/analyze`
Left/main: drag-and-drop zone + "paste lockfile text" + file picker (accept .json, .txt; package-lock.json, requirements.txt). Under it: sample buttons (3 samples). Context form (≤3 questions, radio groups with "Not sure / skip → we'll assume"): distribution mode, project license, do install scripts run in your CI/dev machines. Right/below: "Recent reports" (from localStorage ids, with timestamp and counts). Actions: "Analyze" (disabled until input), "Import report JSON". States: empty (instructions), file too large (>5 MB), wrong type, invalid JSON, unsupported lockfile version (explain), network error with retry. On submit: POST then navigate to a progress view (same page or /report/:id with status) showing real stages with live counts: Parsing → Rebuilding graph (N packages) → Querying OSV (x/y) → EPSS & KEV → Licenses → Signals → Deriving decisions. Provide Cancel. If a stage fails partially, continue and show "partial results" notice.

## `/report/:id`
Header: project name/file, lockfile type, packages count (direct / transitive), analysis time, data badge (LIVE / RECORDED / REPLAY), as-of control (Should), export menu, "New analysis".
Summary sentence (large, plain): "1 incident · 2 act now · 6 upgrade · 3 cannot assess across 312 packages — as of <time>." plus a second line "Counts are unique package versions. Cannot-assess items are not safe items."
Verdict filter chips (click toggles; counts), search box, and sort (verdict priority default).
Tabs:
1. Decisions (default): "Do this first" action groups (grouped by introducing direct dependency or by response class, each line e.g. "Pin `axios` to 1.14.0 — resolves 1 incident"), then decision cards list. Card shows: verdict + urgency + qualifier badges; package purl@version (mono); "via direct-dep"; one-line WHAT; HOW WE KNOW (top evidence IDs, source, origin, time); PATH (breadcrumb with ⚠ on install-script hop); DO (short); NOT CHECKED (always visible, collapsed to a count + expand); buttons: Open details, Copy fix. Clicking opens the drawer. Include rolled-up "No known finding" and "Cannot assess" sections collapsed by default but with counts always visible.
2. Graph: Cytoscape view. Default shows only the paths to the selected decision (root → node, ⚠ markers, node colors by verdict, shape by direct/transitive). Controls: select decision (dropdown), "Show all paths", "Show full graph (collapsed by depth)", zoom/fit, node click → drawer. Text alternative: the same path as an ordered list below the graph. Include the Blast radius panel (Should) when a node is selected.
3. Licenses: summary counts (CONFLICT / REVIEW / UNKNOWN / OK), table (package, license, rule fired, introducing path, status), context chips showing the user's (or assumed) answers with an "Edit context" button that re-derives without re-fetching.
4. Coverage: "What we did and did not check" — a table of checks (vulnerability lookup, malware reports, EPSS/KEV, license, registry metadata, provenance, release diff, reachability) with status Ran / Partial / Not run / Not supported for this input, and reasons. Provenance, release diff and reachability are always "Not run (not in this version)". This tab is the honesty anchor.
Drawer (right side panel on desktop, full-screen sheet on mobile, focus-trapped, Esc closes): sections in this order: WHAT (verdict + one-line cause) · WHY IT MATTERS (exposure: scope, install-phase, assumed vs declared context) · HOW WE KNOW (evidence list: ID, tier badge, source, origin, published time, link, quote; withdrawn marked) · HOW CERTAIN (qualifier + open defeaters) · PATH ("Why is this here?": numbered chain with edge requirement ranges and scope) · IMPACT PROFILE (Should) · WHAT TO DO (steps, copyable commands, Simulate fix) · NOT CHECKED (always visible) · DERIVATION (rule IDs ← evidence IDs; "View rule table") · NARRATIVE (template, Verifier status, self-test).
Error/empty/loading: skeleton cards while loading; 404 report ("expired or never existed", link to Analyze, mention 24 h retention); failed analysis shows stage and reason with retry; zero findings shows NO KNOWN FINDING with scope + as-of and the Coverage link (never a green checkmark, never "secure").

## `/methodology`
Renders the live rule table (R0..R7) and license rule table from the same data the engine uses; sections: evidence tiers, verdict meanings, what "cannot assess" means, data sources and freshness, limitations (package-level paths, heuristics are not proof, license flags not legal advice, public data can lag), glossary of terms (direct vs transitive, CVE, KEV, EPSS, SPDX, install script). Parameters (EPSS threshold, freshness horizon) shown with "defaults, not validated".

## `*` 404 with link home.

# 8. UI/UX DESIGN SYSTEM
Tone: professional, trustworthy, technical, clean, premium; plain English first, details one click away. NOT neon/cyberpunk, no glow, no glassmorphism, no gratuitous animation, no cluttered dashboards.
Tokens (CSS variables; support light default and dark via prefers-color-scheme; define both):
Light: bg #F6F7F9, surface #FFFFFF, border #E3E6EB, text #0F172A, muted #5B6577, accent #1F4FD8.
Dark: bg #0E1116, surface #151A22, border #262D38, text #E6EAF0, muted #9AA4B2, accent #6C93FF.
Verdict colors (text/bg pairs, check contrast ≥ 4.5:1): INCIDENT #B42318 on #FEF3F2 · ACT NOW #C4320A on #FFF4ED · UPGRADE #B54708 on #FFFAEB · MONITOR #175CD3 on #EFF8FF · REVIEW #5925DC on #F4F3FF · CANNOT ASSESS grey #475467 with diagonal hatch pattern background · NO KNOWN FINDING neutral outline, NEVER green. Provide dark-mode equivalents.
Fonts: Inter (UI) and JetBrains Mono (package names, versions, IDs), self-hosted via @fontsource packages (no external font CDN). Scale: 12/14/16/20/28/40; line-height 1.5; max content width 1200px.
Components: Button (primary/secondary/ghost), Badge (verdict, tier, data-source), Card, Tabs, Drawer/Sheet, Table, Chip filter, Dropzone, Stepper/progress checklist, Callout (info/warning), CopyButton, Tooltip, Skeleton, EmptyState, ErrorState. Verdict is conveyed by text + icon + color (never color alone). Icons: lucide-react.
Layout: top nav; report uses a two-pane layout on desktop (list + drawer), single column on tablet, sheet on mobile.
Charts: no decorative charts. Use verdict count chips and one compact stacked bar of verdict counts; graph via Cytoscape (dagre layout).
Motion: 120–180 ms opacity/transform on drawer and hover only; respect prefers-reduced-motion.
Responsive: test at 1440, 1024, 768, 390 px; no horizontal page scroll; tables scroll inside their own container; touch targets ≥ 44 px.
Accessibility: semantic landmarks, labelled form controls, visible focus rings, keyboard operable dropzone/tabs/drawer, aria-live for progress, alt/aria labels for graph with the text path alternative, sufficient contrast.

# 9. TECH STACK
Frontend: React + Vite + TypeScript, Tailwind CSS, React Router, TanStack Query, Cytoscape.js + cytoscape-dagre, lucide-react, @fontsource/inter and @fontsource/jetbrains-mono. State: server state via TanStack Query; local UI state via React state; recent report IDs in localStorage. No Redux.
Backend: Python 3.11+, FastAPI, uvicorn, httpx (async), networkx, pydantic v2, rapidfuzz (string distance), pytest. SQLite via sqlite3 or SQLModel for cache + stored reports (24 h TTL purge).
No authentication in this version. Anonymous use; the uploaded file is parsed in memory and not stored; only the derived report is stored (24 h).
Config via environment: .env.example with OFFLINE_FIXTURES, EPSS_THRESHOLD, FRESHNESS_HOURS, LLM_PROVIDER, LLM_API_KEY, ALLOWED_ORIGINS. No hardcoded secrets; no keys required for core features.

# 10. API (backend, JSON)
POST /api/analyze (multipart: file or text, plus context JSON) → { report_id }
POST /api/analyze/sample/{sample_id} (+ context) → { report_id }
GET /api/reports/{id}/status → { stage, progress, partial, error? }
GET /api/reports/{id}?as_of=ISO → full report: { meta, summary, decisions[], evidence[], graph{nodes,edges}, licenses[], coverage[], context{declared|assumed} }
POST /api/reports/{id}/context → re-derive with new context (no re-fetch)
POST /api/reports/{id}/simulate-fix { subject, to_version } → { before, after, new_risks }
POST /api/verify-demo → verifier self-test result (synthetic claim)
GET /api/reports/{id}/export?format=json|md
GET /api/methodology → rule tables and parameters (same data the engine uses)
GET /api/samples, GET /api/health
Run analysis as a background task with progress polling (every ~700 ms). Pydantic models are the single source of truth; generate/mirror TypeScript types.

# 11. SECURITY REQUIREMENTS (even in a prototype)
- Never execute user-provided code, run npm/pip on user input, or run install scripts. Lockfiles are data only; parse JSON safely.
- Max upload 5 MB; max 5,000 packages; enforce JSON depth/size limits; validate types with pydantic; reject unknown file types; sanitize filenames (display only, never used as a path).
- Outbound requests only to the fixed allowlist; timeouts, retries with backoff, bounded concurrency; no SSRF vector.
- Treat all advisory/registry text as untrusted: render as plain text (no dangerouslySetInnerHTML), strip control/bidi/zero-width characters, cap lengths; if text matches simple prompt-injection heuristics, quarantine it and add a T3 INJECTION_SUSPECT evidence (cap at REVIEW) — relevant only to the optional LLM narrator.
- CORS restricted to ALLOWED_ORIGINS; basic rate limiting on analyze endpoints; do not log file contents.
- Pin dependency versions (lockfiles committed); no postinstall reliance; add a short "Our own supply chain" note in README (pinned deps, no install scripts needed).
- No secrets in code; .env.example only.

# 12. FUNCTIONAL vs MOCKED vs FUTURE (strict)
FUNCTIONAL (must really work): upload/paste/sample, lockfile parsing, edge reconstruction, graph, OSV/EPSS/KEV/deps.dev/registry lookups with cache, evidence records, decision engine, license rules, lookalike/stale/new heuristics, path view, filters/tabs/drawer, export/import, methodology page, as-of re-derivation, simulate fix, verifier self-test.
RECORDED (real data captured earlier, labelled on screen): replay fixtures and offline fallback.
MOCKED: nothing in findings. The only static "example" is the labelled sample card on the landing page.
FUTURE (extension points only, no implementation): see section 2 DEFERRED list. Provide the EvidenceProvider interface, the adapter interface (declares supported checks; unsupported → ABSENT evidence), and rules-as-data so later research can adjust without a rewrite.
NEVER display wording implying a scan, detection or analysis that did not actually run. Every check shown in Coverage must correspond to real code that ran or an explicit "Not run".

# 13. UX COPY RULES
Plain language; verdict labels exactly as defined; "Reported malicious (OpenSSF MAL-XXXX)" only with a report ID; "Lookalike name (heuristic)" not "typosquat detected"; "No known finding as of <time> for: <checks run>" not "secure"; "Cannot assess: <reason>" with hatched grey style; always show "Not checked". Use "assumed" labels wherever context was skipped.

# 14. PROJECT STRUCTURE (adapt to any existing repo)
warrant/
  README.md  (setup, run, env vars, assumptions, how to record fixtures, limits)
  backend/
    pyproject.toml / requirements.txt (pinned)
    app/
      main.py  api/ (routes_analyze.py, routes_reports.py, routes_misc.py)
      models/ (evidence.py, decision.py, report.py, context.py)
      parsers/ (npm_lock.py, requirements_txt.py, base.py)
      graph/ (build.py, paths.py, scope.py, blast.py)
      providers/ (base.py, osv.py, epss.py, kev.py, deps_dev.py, npm_registry.py, cache.py)
      signals/ (lookalike.py, staleness.py, cvss_profile.py)
      licenses/ (spdx.py, rules.py)
      engine/ (rules.py, decide.py, remediate.py, narrate.py, verify.py)
      data/ (popular_npm.json, license_rules.json)
      jobs.py  security.py  config.py
    fixtures/ (samples/, recorded/)
    scripts/record_fixtures.py
    tests/
  frontend/
    src/
      main.tsx  App.tsx  routes/ (Landing, Analyze, Report, Methodology, NotFound)
      components/ (ui/, report/ DecisionCard, Drawer, PathView, EvidenceList, CoverageTable, LicenseTable, ProgressChecklist, SummaryBar)
      graph/ (CytoscapeView.tsx)
      lib/ (api.ts, types.ts, format.ts, storage.ts)
      styles/ (tokens.css, index.css)
    index.html  vite.config.ts  tailwind.config.ts

# 15. IMPLEMENTATION ORDER
1. Inspect existing project (section 0). Report what you found in 5 lines, then proceed.
2. Scaffold backend + frontend (or adapt), set up pinned deps, .env.example, README skeleton.
3. Design system: tokens, fonts, base components, global layout/nav/footer, light/dark.
4. Backend: models (evidence, decision), npm lockfile parser, edge reconstruction, scope, paths, tests.
5. Backend: providers (OSV, EPSS, KEV, deps.dev, npm registry) with SQLite cache, backoff, allowlist, offline mode.
6. Backend: signals (lookalike, stale/new, install-script, CVSS profile) and license engine.
7. Backend: decision engine with rules-as-data, as_of, counting, derivation; unit tests for every rule R1–R7 (including placeholder-version trap and withdrawn records).
8. Backend: API, background jobs with progress, export, methodology endpoint.
9. Frontend: Landing page and Analyze page (dropzone, samples, context form, progress checklist, error states).
10. Frontend: Report page — summary, chips, action groups, decision cards (Decisions tab).
11. Frontend: Drawer with evidence, path ("Why is this here?"), not-checked, derivation; Graph tab (Cytoscape path view + text alternative).
12. Frontend: Licenses tab and Coverage tab; context editing.
13. Remediation: introduced-by, commands, Simulate fix, blast radius.
14. As-of slider, export/import, methodology page, verifier self-test and template narrator.
15. Record fixtures (scripts/record_fixtures.py) and verify the three samples end-to-end.
16. Responsive pass (1440/1024/768/390), accessibility pass (keyboard, focus, contrast, labels), loading/empty/error states.
17. Test navigation and all interactions; run backend tests; fix issues.
18. Optional LLM narrator (only if env key present and all above done). 
19. Clean up/refactor, finalize README with assumptions and known limits.

# 16. RULES FOR YOU (Antigravity)
1. Inspect before modifying; preserve unrelated work. 2. Build incrementally; core flow first. 3. Avoid unnecessary dependencies. 4. All buttons, tabs, filters, forms, the drawer and navigation must work. 5. Use real data; if you must use recorded data, label it. 6. Do not fake cybersecurity claims. 7. Responsive on desktop, tablet, mobile. 8. Accessible (semantic HTML, keyboard, labels, contrast). 9. Modular, readable, typed code. 10. Do not over-engineer: no Docker/Kubernetes/queues/auth/microservices. 11. If something is unspecified, make the smallest reasonable assumption, record it in README, continue. 12. If a real data source is unreachable while recording fixtures, say so instead of inventing data.

# 17. ACCEPTANCE CHECKLIST (verify before finishing)
- Uploading the Legacy Express sample produces real OSV findings, deep transitive paths, and a summary sentence; counts are unique package versions.
- The axios replay shows INCIDENT on plain-crypto-js with report ID, path with ⚠ install hop, "No CVE / KEV n/a / EPSS n/a", containment steps, and the as-of slider changes the decision/parent state; the 0.0.1-security placeholder does not produce a false INCIDENT.
- A git-URL dependency and the requirements.txt sample show CANNOT ASSESS / "paths unknown", never green.
- Licenses tab flags a copyleft package as CONFLICT only when context makes it a conflict, and changing context re-derives results.
- Every decision shows evidence with source/time, a path, and a "Not checked" list. No scalar score exists anywhere. No "safe/secure/first/only" wording.
- Methodology page renders the same rule table the engine uses. Coverage tab honestly lists unrun checks.
- Works with no LLM key. Tests pass. No secrets committed. Layout verified at 390 px with no horizontal page scroll.
````
