# Warrant — Verifiable Claims

Every claim below can be checked in the code or proven by an automated test. We list what Warrant does
**not** do as well, because over-claiming is the problem we set out to solve.

Run all proofs: `cd backend && python -m pytest tests/ -q` (185 tests, no network needed).

---

## 1. One decision per dependency, from a printed rule table — not a score

| Claim | Proof |
|---|---|
| Every risky package gets exactly one verdict: INCIDENT · ACT NOW · UPGRADE · MONITOR · REVIEW · CANNOT ASSESS · NO KNOWN FINDING | `backend/app/engine/decide.py` |
| Rules R1–R7 are stored as data and rendered live on `/methodology` (first match wins) | `backend/app/engine/rules.py` |
| Every verdict cites the rule and evidence IDs that produced it (e.g. `R1 ← E0001`) | `Decision.derivation` in `backend/app/models/decision.py` |
| The engine is deterministic: same input → identical output, no LLM, no randomness | `test_decisions_are_deterministic_and_carry_reason_sorted` |

## 2. Unknown is never shown as safe

| Claim | Proof |
|---|---|
| A check that could not run is recorded as ABSENT evidence and shown as CANNOT ASSESS, never as clean | `test_osv_outage_fails_check_and_never_reports_clean` |
| An active advisory with no published fix is never reported as "no known finding" | `test_prod_advisory_without_fix_is_never_no_known_finding` |
| A CISA KEV outage is reported as "not checked", not as "not exploited" | `test_kev_outage_is_recorded_per_cve_and_in_coverage` |
| Short, malformed or failed OSV responses produce ABSENT records for every affected package | `test_osv_short_or_malformed_batch_responses_are_never_clean` |
| Offline mode never silently goes live and never claims a clean result | `test_offline_fixture_mode_does_not_go_live_or_claim_a_clean_result` |
| The Coverage tab states exactly which checks ran, partially ran, or were not run | `_security_coverage` in `backend/app/jobs.py` |

## 3. Malware first — including packages that *carry* malware

| Claim | Proof |
|---|---|
| OpenSSF / OSV `MAL-*` reports on the exact resolved version → INCIDENT with a containment checklist | rule R1, `test_malware_report_gives_incident_high_priority_with_carry` |
| Every package that depends on a malicious one is flagged (R1' "carries incident") — e.g. axios@1.14.1 carrying plain-crypto-js@4.2.1 | `test_replay_malware_incident_scenario` |
| Registry placeholder versions (`0.0.1-security`) are never marked INCIDENT and never spread one | `test_placeholder_and_git_sources_never_carry_an_incident_to_ancestors` |

## 4. Exact versions, correct fixes

| Claim | Proof |
|---|---|
| Matching is per exact `package@version`, as answered by OSV — no fuzzy name matching for findings | `backend/app/providers/osv.py` |
| The recommended fix comes from the advisory range that contains the installed version — never a downgrade (axios 1.14.0 → 1.15.0, not 0.31.0) | `test_fixed_version_comes_from_the_range_containing_the_installed_version` |
| Nested dependencies resolve to the version actually installed (npm's own resolution order) | `test_dependency_resolves_to_its_own_nested_copy_first` |
| Withdrawn advisories stop affecting verdicts, including through their KEV/EPSS entries | `test_withdrawn_advisory_cannot_drive_verdict_through_derived_kev` |

## 5. Time-travel without hindsight

| Claim | Proof |
|---|---|
| "As-of" view re-runs the same rules on stored evidence, keeping only what was published (and not yet withdrawn) at that time | `test_as_of_view_rederives_without_future_evidence` |
| The original analysis is never modified | `test_original_analysis_is_unchanged_and_reproducible` |
| Timeline markers come only from dated evidence in the report — nothing invented | `frontend/src/lib/timeline.ts` |

## 6. It keeps watching — Warrant Watch

| Claim | Proof |
|---|---|
| Monitored projects are re-checked automatically against new evidence; no re-upload needed | `test_scheduler_runs_checks_automatically_in_app` |
| Only meaningful changes alert (EPSS jitter, text-only edits, an extra advisory with the same fix are ignored) | `test_epss_noise_below_threshold_is_not_an_event`, `test_text_only_advisory_modification_is_not_an_event` |
| The same evidence never alerts twice — across repeated checks, app restarts and scheduler restarts | `test_same_evidence_checked_repeatedly_creates_one_event`, `test_application_restart_does_not_duplicate_events` |
| A provider outage makes a check partial/failed and can never de-escalate a finding | `test_kev_outage_is_partial_and_cannot_de_escalate` |
| Alerts reach Slack, Teams or signed webhooks; delivery is retried and never duplicated | `test_security_change_is_delivered_once_per_channel` |
| CI keeps monitoring in step with what ships; new risky dependencies alert on merge | `test_lockfile_update_reports_introduced_and_removed_risk`, `test_ci_sync_creates_then_updates_one_project` |

## 7. Proven on a real attack, with real data

| Claim | Proof |
|---|---|
| The 31 Mar 2026 axios / plain-crypto-js compromise is replayed from **real recorded** OSV/OpenSSF records (MAL-2026-2306, MAL-2026-2307), released at their real import times | `backend/fixtures/watch_replay/axios-compromise-2026-03-31/` |
| A real, unmodified open-source lockfile (slackapi/slack-github-action) goes NO KNOWN FINDING → UPGRADE when the real advisory GHSA-3p68-rc4w-qgx5 appears | `test_replay_real_project_axios_advisory_is_deterministic` |
| Every recorded file is pinned by SHA-256 and verified on load | `test_replay_scenario_integrity_is_verified` |
| Simulated events are always labelled DEMO / REPLAY / SIMULATED EVENT | `test_replay_reports_are_labelled_simulated` |

## 8. Safe by design

| Claim | Proof |
|---|---|
| No package code is ever installed or executed — only lockfiles are parsed | `backend/app/parsers/` |
| Outbound requests only to allowlisted public sources; webhook URLs must be public https | `backend/app/security.py`, `test_channel_urls_are_validated` |
| Optional API keys (full / read-only) protect every endpoint | `test_api_key_and_read_only_key` |
| Provider text is sanitised (control / bidi characters, unsafe links removed) | `test_osv_records_are_validated_and_sanitised` |

## 9. Fast enough for real projects

| Measurement (offline, engine only) | Result |
|---|---|
| Real 492-package lockfile (yargs) | ≈ 0.3 s |
| 5,000-package graph | ≈ 5–8 s |

---

## What Warrant does **not** claim

- **No reachability analysis** — findings are package-level; we do not check whether the vulnerable function is called. Every report says so.
- **No zero-day detection** — Warrant acts on published evidence; detection is as fast as OSV / OpenSSF / CISA publish.
- **No "safe" verdict** — NO KNOWN FINDING means every check ran and found nothing *as of that time*.
- **Ecosystems:** npm (package-lock v1–v3) and pinned Python requirements.txt today.
- **Heuristics never decide alone** — lookalike / staleness signals can only produce REVIEW.
- EPSS threshold (0.10) and freshness window (72 h) are defaults, not empirically calibrated.
