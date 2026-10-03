# Merge Plan: Janhavi's Features & Sebin's Features (Zero Data Loss)

> **For Agent:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Seamlessly merge all features from Janhavi's commit (`4f63dd9`: Live GitHub Repo Analyzer, Hero Studio UI, Decision Drawer, Graph Traversal & Timeline Slider) with all features from Sebin's branch (`feature/sebin-work`: Corporate License Policies, Banned Dependencies Blacklist, 100% Real Benchmark Dataset, and Audit Suite) so that 100% of both developers' code is preserved with zero conflicts and verified by automated tests.

**Architecture:** Perform a non-destructive Git merge into a clean staging state on `main`, surgically synthesize the 6 overlapping files to keep both feature sets active, verify against the 4 automated testing gates (Pytest, Data Audit, Benchmark Checksums, Vite/TypeScript build), and commit the unified result.

**Tech Stack:** Git, FastAPI (Python), React 19, TypeScript, Vite.

---

### Task 1: Non-Destructive Git Merge Invocation
**Files:**
- Repository Git tree

**Step 1: Verify current clean state on `main`**
Run: `git status`
Expected output: `On branch main`, `working tree clean`, `HEAD is at 4f63dd9`.

**Step 2: Initiate merge with `--no-commit`**
Run: `git merge feature/sebin-work --no-commit`
Expected output: Git automatically merges 54 non-conflicting files (benchmark dataset, documentation, evidence, GitHub client, styles, etc.).

**Step 3: List files staged vs files needing synthesis**
Run: `git status --porcelain`
Expected output: Confirmed list of automatically merged files and marked conflict/synthesis files.

---

### Task 2: Synthesize Shared Backend Types & Data
**Files:**
- Modify: `backend/app/data/popular_npm.json`
- Modify: `backend/app/api/routes_analyze.py`

**Step 1: Ensure `popular_npm.json` contains full download metrics and `crypto-js`**
Janhavi added `"crypto-js"` to the list. Sebin has the complete verified download count mapping including `"crypto-js": 60555319`. Keep the complete download count file from `feature/sebin-work`.

**Step 2: Synthesize `backend/app/api/routes_analyze.py`**
- **Keep Janhavi's addition:** `_load_sample_content(sample_id)` helper and `@router.post("/analyze/sample")` accepting JSON body.
- **Keep Sebin's addition:** `"slack-action": "slack-action"` in `SAMPLE_IDS` and sample directory.
- Verify exact `SAMPLE_IDS`:
```python
SAMPLE_IDS = {
    "slack-action": "slack-action",
    "legacy-express": "legacy-express",
    "axios-replay": "axios-replay",
    "python-requirements": "python-requirements",
}
```

---

### Task 3: Synthesize Analysis Pipeline & Test Suite
**Files:**
- Modify: `backend/app/jobs.py`
- Modify: `backend/tests/test_warrant.py`

**Step 1: Synthesize `backend/app/jobs.py`**
- **In `_build_graph_output` (Janhavi's feature):** Preserve `scope_provenance`, `license`, `introduced_by`, and `direct_dependents_count`.
- **In Stage 7 (Sebin's feature):** Preserve `company_policy` and `banned_dependencies` evidence emission:
```python
if context.company_policy or context.banned_dependencies:
    for purl, pkg in build.packages.items():
        lic_status, lic_rule, lic_note = classify_license(pkg.license, context, package_name=pkg.name, package_version=pkg.version)
        if lic_status == "CONFLICT" and lic_rule in ("LR8", "LR-BANNED-PKG"):
            evidence.append(EvidenceRecord(
                id=f"BAN-{pkg.name[:18].replace('/', '-').replace('@', '')}",
                tier=EvidenceTier.T2,
                source="corporate-policy",
                origin="Corporate Policy Enforcement",
                kind=EvidenceKind.BANNED_DEPENDENCY,
                subject=purl,
                claim=lic_note,
                retrieved_at=now,
                data={"policy": context.company_policy, "rule": lic_rule, "license": pkg.license, "package": pkg.name}
            ))
```
- **In Stage 8 (Sebin's feature):** Pass `package_name=pkg.name, package_version=pkg.version` to `classify_license`.

**Step 2: Synthesize `backend/tests/test_warrant.py`**
- Keep **Janhavi's test suite additions:**
  - `test_circular_dependency_breaking()`
  - `test_blast_radius()`
  - `test_blast_radius_caching()`
  - `test_lookalike_scoped_package_imitation()`
  - `test_lookalike_official_scope_whitelist()`
  - `test_lookalike_scoped_typosquat()`
  - `test_staleness_scoped_package()`
  - `test_staleness_deprecated_flag()`
  - `test_large_dependency_graph_performance()`
- Keep **Sebin's test suite additions:**
  - `test_company_policy_dataset_has_at_least_3_examples()`
  - `test_corporate_policy_google_bans_agpl()`
  - `test_corporate_policy_apache_bans_gpl()`
  - `test_corporate_policy_meta_bans_sspl()`
  - `test_corporate_policy_allows_permissive()`
  - `test_custom_organization_banned_dependencies()`

---

### Task 4: Synthesize Frontend Types, Studio UI & Licenses Tab
**Files:**
- Modify: `frontend/src/lib/types.ts`
- Modify: `frontend/src/routes/Analyze.tsx`
- Modify: `frontend/src/components/licenses/LicensesTab.tsx`

**Step 1: Synthesize `frontend/src/lib/types.ts`**
- Combine Janhavi's GitHub & graph types with Sebin's `CompanyPolicy` and `AnalysisContext` corporate policy fields:
```typescript
export interface CompanyPolicy {
  id: string;
  name: string;
  allowed_licenses: string[];
  banned_licenses: string[];
  restricted_licenses?: string[];
  rationale: string;
  source_url: string;
}

export interface AnalysisContext {
  distribution_mode?: 'SaaS' | 'Distributed' | 'Internal' | 'OpenSource';
  project_license?: 'Proprietary' | 'MIT' | 'Apache-2.0' | 'GPL-3.0-or-later';
  install_scripts_run?: boolean | null;
  company_policy?: string;
  banned_dependencies?: string[];
}
```

**Step 2: Synthesize `frontend/src/routes/Analyze.tsx`**
- **Janhavi's UI structure preserved:** Tab selector (`Manual / Upload` vs `GitHub Repository`), `GitHubRepoAnalyzer` component integration, Studio Hero layout, Recent reports with incident badges, Engine guarantee cards.
- **Sebin's Compliance controls preserved:**
  - Corporate policy radio selector (Google, Apache, Meta, Microsoft, None).
  - Organization Banned Dependencies blacklist input.
  - Primary sample button for `slack-action` (Slack GitHub Action @ a8dafde, 100% Real).
- **Wiring:** Context from the form (including `company_policy` and `banned_dependencies`) is forwarded to both File upload submissions and GitHub repo analysis submissions.

**Step 3: Synthesize `frontend/src/components/licenses/LicensesTab.tsx`**
- **Janhavi's UI structure preserved:** Table styling, column widths, and category filters.
- **Sebin's Policy UI preserved:**
  - Active Corporate Policy banner alert at top of the tab:
    ```tsx
    {context?.company_policy && (
      <div className="card" style={{ marginBottom: 'var(--space-6)', borderLeft: '4px solid var(--color-accent)' }}>
        ...
      </div>
    )}
    ```
  - `CONFLICT [BANNED]` badge and red highlight when `rule_fired === 'LR8' || rule_fired === 'LR-BANNED-PKG'`.

---

### Task 5: Execute 4-Gate Automated Verification
**Files:**
- All synthesized codebase files

**Step 1: Gate 1 — Backend Unit Test Suite**
Run: `pytest`
Expected output: **35+ passed** with 0 errors.

**Step 2: Gate 2 — Real Data Reality Audit**
Run: `python full_data_audit.py`
Expected output: `[ALL PASS] PROJECT IS 100% REAL DATA. Zero failures. Zero warnings.`

**Step 3: Gate 3 — Benchmark Dataset Cryptographic Checksums**
Run: `python benchmark_dataset/tools/verify_dataset.py`
Expected output: `ALL DATASET CHECKS PASSED (All 25 file hashes verified perfectly)`

**Step 4: Gate 4 — Frontend TypeScript & Vite Production Build**
Run: `npm run build` in `frontend/`
Expected output: `tsc && vite build` completes with **0 errors**.

---

### Task 6: Finalize Merge Commit
**Files:**
- Git repository

**Step 1: Review git status to confirm all files are staged**
Run: `git status`

**Step 2: Create unified merge commit**
Run: `git commit -m "feat: unify live GitHub repository analyzer & studio UI with corporate license policy & benchmark suite"`

**Step 3: Verify clean log on `main`**
Run: `git log -n 3 --oneline`
Expected output: Shows the unified merge commit at the top of `main`, with both Janhavi's history and Sebin's history intact.
