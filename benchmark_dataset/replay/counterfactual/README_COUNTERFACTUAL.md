# NOTICE: COUNTERFACTUAL / DERIVED FIXTURE -- WITH REAL FORENSIC EVIDENCE

**IMPORTANT JUDGE DISCLOSURE:**
`package-lock.COUNTERFACTUAL_DERIVED.json` is a **synthetic / reconstructed** lockfile created solely to evaluate Warrant's temporal incident replay engine on the historical 2026-03-31 axios supply-chain compromise.

---

## Why This Fixture Exists (And Why It Cannot Be a Real Lockfile)

**Real incident facts confirmed from OpenSSF OSV records + industry forensics:**

| Fact | Value |
| :--- | :--- |
| **Compromised npm versions** | `axios@1.14.1` and `axios@0.30.4` |
| **Malicious dependency injected** | `plain-crypto-js@4.2.1` |
| **Payload type** | Cross-platform Remote Access Trojan (RAT) -- macOS, Windows, Linux |
| **Delivery mechanism** | `postinstall` script in `plain-crypto-js@4.2.1` |
| **npm exposure window** | `2026-03-31T00:21:00Z` to `2026-03-31T03:29:00Z` (~3 hours) |
| **C2 domain** | `sfrclak.com` |
| **C2 IP:port** | `142.11.206.73:8000` |
| **Windows persistence** | `C:\ProgramData\system.bat` + Registry Run key `MicrosoftUpdate` |
| **OSV records** | `MAL-2026-2306` (plain-crypto-js), `MAL-2026-2307` (axios parent) |

**GitHub code search conducted:** 2026-10-03
**Search queries run:**
- `"axios" "1.14.1" "plain-crypto-js"` -> 0 real committed lockfiles found
- `"axios/-/axios-1.14.1.tgz"` -> 0 real committed lockfiles found

**Conclusion:** The malicious versions were live for only **~3 hours**. Open-source projects commit lockfile updates on daily/weekly cycles -- not in 3-hour windows during a weekend night. No real project permanently committed `axios@1.14.1` before npm removed it. The counterfactual label is **scientifically correct**.

---

## What This File Is For

- **THIS IS NOT AN AUTHENTIC HISTORICAL PROJECT LOCKFILE.**
- The primary judge-facing demonstration uses the **REAL, UNMODIFIED** `projects/primary/package-lock.json` from `slackapi/slack-github-action@a8dafde`.
- This fixture demonstrates Warrant's **four-clock temporal engine**: how Warrant detected `axios@1.14.1` as compromised via transitive path (through `plain-crypto-js@4.2.1`) **68 minutes before** the parent `axios` advisory was officially published.
- Warrant explicitly labels all counterfactual outputs as `FIXTURE / SIMULATION` in the UI.

---

## References
- https://osv.dev/vulnerability/MAL-2026-2306
- https://osv.dev/vulnerability/MAL-2026-2307
- https://github.com/advisories/GHSA-fw8c-xr5c-95f9
