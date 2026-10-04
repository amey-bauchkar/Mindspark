# Remote UI Redesign & Enterprise Watch Ops Merge Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Seamlessly merge your local enterprise Watch continuous monitoring & ops suite (`3e7b7db`) with your teammates' remote console redesign and segregated malware quarantine (`dfd7122`) without losing a single line of work or breaking any tests.

**Architecture:** 
1. Git 3-way merge from `origin/main` into local `main` with safety backup branch `backup-watch-ops`.
2. Exact resolution of the 2 intersecting files (`frontend/src/App.tsx` and `frontend/src/styles/index.css`) preserving both `ThemedShell` + Live/Fixture pills and `<ApiKeyGate />` + Watch management styles.
3. Full verification through the 185 backend pytest suite, 10/10 data audit, and frontend TypeScript build.

**Tech Stack:** Git, FastAPI, React 19, TypeScript, Vite, Pytest, Python 3.14.

---

### Task 1: Safety & Branch State Verification

**Files:**
- Reference: Local branch `main` at `3e7b7db`
- Reference: Remote branch `origin/main` at `dfd7122`
- Backup: Local branch `backup-watch-ops` at `3e7b7db`

**Step 1: Verify backup branch exists**
Run: `git branch`
Expected: `backup-watch-ops` is present and points to `3e7b7db`.

**Step 2: Verify git status is clean**
Run: `git status`
Expected: `working tree clean`.

---

### Task 2: Execute Merge & Resolve `frontend/src/App.tsx`

**Files:**
- Modify: `frontend/src/App.tsx`

**Step 1: Initiate Git Merge**
Run: `git merge origin/main`
Expected: Auto-merging files, conflicts flagged in `frontend/src/App.tsx` and `frontend/src/styles/index.css`.

**Step 2: Resolve `frontend/src/App.tsx` Conflict**
Combine teammate changes (`ThemedShell`, `Nav` offline pill, `getHealth` import) with our `<ApiKeyGate />` import and JSX element:
- Add `import { ApiKeyGate } from './components/ApiKeyGate';`
- Place `<ApiKeyGate />` inside `ThemedShell` right after `<WatchAlerts />` and before `<main className="main-content" id="main-content">`.

**Step 3: Verify `frontend/src/App.tsx` has zero conflict markers**
Run: `git diff --check frontend/src/App.tsx`
Expected: Zero conflict markers.

---

### Task 3: Resolve `frontend/src/styles/index.css`

**Files:**
- Modify: `frontend/src/styles/index.css`

**Step 1: Resolve CSS Conflict**
Retain all teammates' newly added styling for the enterprise report console and segregated malware quarantine, and ensure the 40 lines of `.watch-manage`, `.watch-ci`, `.watch-triage`, `.watch-channel-form` are cleanly appended at the end of the file.

**Step 2: Verify `frontend/src/styles/index.css` has zero conflict markers**
Run: `git diff --check frontend/src/styles/index.css`
Expected: Zero conflict markers.

---

### Task 4: Complete Merge Commit

**Files:**
- Stage: `frontend/src/App.tsx`, `frontend/src/styles/index.css`

**Step 1: Stage resolved files**
Run: `git add frontend/src/App.tsx frontend/src/styles/index.css`

**Step 2: Create Merge Commit**
Run: `git commit -m "merge: integrate enterprise report console redesign with watch monitoring & ops suite"`
Expected: Merge commit created successfully.

---

### Task 5: End-to-End Verification

**Step 1: Run Backend Pytest Suite**
Run: `python -m pytest` in `backend/`
Expected: `185 passed`.

**Step 2: Run Cryptographic Data Audit**
Run: `python full_data_audit.py` in workspace root
Expected: `10/10 PASS`, 0 failures, 25 SHA-256 hashes match.

**Step 3: Run Frontend TypeScript & Vite Production Build**
Run: `npm run build` in `frontend/`
Expected: `tsc && vite build` succeeds with 0 errors.

**Step 4: Live UI Verification in Browser**
Navigate to:
- `http://localhost:5173/analyze` & `http://localhost:5173/report/...` -> Verify teammates' segregated malware quarantine and square console styling.
- `http://localhost:5173/watch` -> Verify your Watch monitoring health strip, CI integration snippet, manage drawer, and triage controls.

---

### Task 6: Push to GitHub Remote

**Step 1: Push merged main to origin**
Run: `git push origin main`
Expected: Successfully pushed to `https://github.com/amey-bauchkar/Mindspark`.
