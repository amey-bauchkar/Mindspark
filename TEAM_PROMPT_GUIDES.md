# Team Prompt Guides — Warrant Supply Chain Risk Analyzer

Use these tailored prompts for each team member. When each person opens their Antigravity IDE, they should paste their respective prompt into the chat.

---

## 🎨 PROMPT FOR JANHAVI (UI/UX & Design Experience)

```text
You are working on the project "Warrant — Software Supply Chain Risk Analyzer".
My role on the team is UI/UX, Design Systems, and Drawer/License Experience.

Here are the strict workspace rules and file boundaries to avoid merge conflicts:
- MY DEDICATED FILES & FOLDERS:
  1. `frontend/src/styles/` (tokens.css, style.css — design tokens, animations, responsive layout, dark/light theme).
  2. `frontend/src/components/ui/` (VerdictChip.tsx, TierBadge.tsx, CopyButton.tsx, Skeletons, Modal primitives).
  3. `frontend/src/components/drawer/` (DecisionDrawer.tsx — the slide-out details panel with "What", "Why it matters", "How we know", evidence cards, "How certain", Simulate Fix button & result, Verifier demo button & result, and unrun checks).
  4. `frontend/src/components/licenses/` (LicensesTab.tsx — license compliance breakdown table, status summary cards).
- DO NOT MODIFY:
  - `frontend/src/components/graph/` (Tanmay's domain)
  - `frontend/src/components/decisions/` (Tanmay's domain)
  - `frontend/src/components/asof/` (Tanmay's domain)
  - `backend/` (Adi's domain)
  - `frontend/src/routes/Report.tsx` (Coordinator shell; import your components here only if props change)

MY REFINEMENT TASKS:
1. Design System & Never-Green Rule:
   - Ensure the "never-green" rule is strictly honored: NO_KNOWN_FINDING must remain neutral slate/grey (#344054 / #9AA4B2), never green.
   - Refine typography, padding, card borders, subtle drop-shadows, and transitions in `tokens.css`.
2. Decision Drawer Polish:
   - Enhance the readability of the evidence cards (T1/T2/T3 badges, quotes with blockquotes, monospace purls, clear advisory links).
   - Ensure the "Simulate Fix" button and the "Verifier Self-Test" result card look sleek, modern, and distinct.
3. Licenses Tab UX:
   - Refine the license status cards (CONFLICT, REVIEW, OK, UNKNOWN) with clear visual cues and clean table column formatting.
4. Micro-interactions:
   - Add hover states, smooth transitions, and keyboard escape handling for interactive elements.

First, inspect my files (`frontend/src/components/drawer/DecisionDrawer.tsx` and `frontend/src/styles/tokens.css`) and suggest the first UI/UX refinement steps.
```

---

## 📊 PROMPT FOR TANMAY (Cytoscape Visualizer, Action Groups & As-Of)

```text
You are working on the project "Warrant — Software Supply Chain Risk Analyzer".
My role on the team is Interactive Graph Visualizations, Priority Action Groups, and Temporal As-Of Time-Travel.

Here are the strict workspace rules and file boundaries to avoid merge conflicts:
- MY DEDICATED FILES & FOLDERS:
  1. `frontend/src/components/graph/` (GraphTab.tsx — Cytoscape.js interactive graph, dagre hierarchical layout, node inspection, blast-radius visual highlights).
  2. `frontend/src/components/decisions/` (ActionGroups.tsx, DecisionCard.tsx — "Do This First: Immediate Containment" vs "Plan Remediation" vs "Monitor" priority group containers).
  3. `frontend/src/components/asof/` (AsOfSlider.tsx — Temporal time-travel rewind UI to re-derive report states at a past date).
- DO NOT MODIFY:
  - `frontend/src/components/drawer/` (Janhavi's domain)
  - `frontend/src/components/licenses/` (Janhavi's domain)
  - `frontend/src/styles/tokens.css` (Janhavi's domain)
  - `backend/` (Adi's domain)

MY REFINEMENT TASKS:
1. Cytoscape Dependency Visualizer (`frontend/src/components/graph/GraphTab.tsx`):
   - Refine the Cytoscape graph canvas: polish node sizing (root node larger, direct dependencies medium, transitive smaller), verdict badge colors matching tokens, and curved bezier edges.
   - When a node is clicked, highlight its ancestor paths and its downstream blast radius (all packages that depend on it).
   - Provide smooth zoom controls (Zoom in, Zoom out, Fit view, Reset).
2. "Do This First" Action Groups (`frontend/src/components/decisions/ActionGroups.tsx`):
   - Make the "Do This First" container for INCIDENT and ACT_NOW visually prominent with red/orange accent headers and containment checklist badges.
   - Ensure smooth toggling between "Priority Groups" and "Flat List" views.
3. As-Of Time-Travel Slider (`frontend/src/components/asof/AsOfSlider.tsx`):
   - Refine the date-picker / timeline slider so evaluators can visually select past dates (e.g., March 2026 for the Axios incident) and trigger `getReport(id, asOf)`.

First, inspect my files (`frontend/src/components/graph/GraphTab.tsx` and `frontend/src/components/decisions/ActionGroups.tsx`) and explain what we can refine right now.
```

---

## ⚙️ PROMPT FOR ADI (Data Layer, Graph Logic & Intake Engine)

```text
You are working on the project "Warrant — Software Supply Chain Risk Analyzer".
My role on the team is the Data Layer, Parser Edge Reconstruction, Graph Analytics, and Intake Engine.

Here are the strict workspace rules and file boundaries to avoid merge conflicts:
- MY DEDICATED FILES & FOLDERS:
  1. `backend/app/parsers/` (npm_lock.py, requirements_txt.py — lockfile parsing, transitive depth calculation, edge reconstruction).
  2. `backend/app/graph/` (build.py — NetworkX dependency graph construction, cycle handling, scope propagation, attack paths, blast radius calculation).
  3. `backend/app/api/` (routes_analyze.py, routes_reports.py — intake endpoints, report re-import `/api/reports/import`).
  4. `frontend/src/components/analyze/` (ReportReimport.tsx — the drag-and-drop report JSON re-import UI).
  5. `backend/fixtures/` and tests (Axios replay fixture, test suites).
- DO NOT MODIFY:
  - `frontend/src/components/drawer/` (Janhavi's domain)
  - `frontend/src/components/graph/` (Tanmay's domain)
  - `frontend/src/components/decisions/` (Tanmay's domain)
  - `frontend/src/styles/` (Janhavi's domain)

MY REFINEMENT TASKS:
1. Fix Parser Depth Bug (`backend/app/parsers/npm_lock.py`):
   - Notice in `_depth_from_key`: lockfile direct dependency keys (e.g. `node_modules/axios`) were calculating depth 0 instead of connecting as direct children to `__root__`, causing some dependency paths to appear disconnected. Ensure direct dependencies have depth 1 from `__root__`.
2. Blast Radius & Graph API:
   - Ensure `blast_radius()` in `backend/app/graph/build.py` accurately computes the full downstream dependent tree count for any package purl.
3. Report Re-import (`/api/reports/import`):
   - Verify that uploaded exported Warrant JSON reports (`warrant-report-*.json`) load cleanly into SQLite cache without crashing or triggering external network calls.
4. Signal Refinements:
   - Verify `backend/app/signals/lookalike.py` and `backend/app/signals/staleness.py` handle scoped package edge cases (e.g. `@plain/crypto-js` lookalike matching `crypto-js`).

First, inspect `backend/app/parsers/npm_lock.py` and `backend/app/graph/build.py` and let's check the edge reconstruction logic.
```
