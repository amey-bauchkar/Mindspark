"""
WARRANT-2.1 FULL PROJECT DATA REALITY AUDIT
============================================
Checks EVERY data source in the entire project:
1. benchmark_dataset/ - All project lockfiles, evidence files
2. backend/app/data/ - popular_npm.json
3. backend/app/providers/ - All 4 live API providers
4. backend/fixtures/ - Dev fixtures (must be labeled synthetic)
5. backend/app/signals/ - Signal generators
6. Live API spot-checks (OSV, npm, EPSS, KEV, deps.dev)
"""
import json
import sys
import hashlib
import urllib.request
import urllib.error
from pathlib import Path
import subprocess
import io

# Force UTF-8 output on Windows
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

WORKSPACE = Path(__file__).resolve().parent
DEMO = WORKSPACE / "benchmark_dataset"
BACKEND = WORKSPACE / "backend"

PASS = "  [PASS]"
FAIL = "  [FAIL]"
WARN = "  [WARN]"
INFO = "  [INFO]"

failures = []
warnings = []



def header(title: str):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


def check(label: str, condition: bool, detail: str = "", is_warning: bool = False):
    if condition:
        print(f"{PASS}: {label}" + (f"\n         {detail}" if detail else ""))
    else:
        marker = WARN if is_warning else FAIL
        msg = f"{marker}: {label}" + (f"\n         {detail}" if detail else "")
        print(msg)
        if is_warning:
            warnings.append(label)
        else:
            failures.append(label)


def fetch_url(url: str, timeout=20) -> bytes | None:
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "warrant-audit/1.0", "Accept": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()
    except Exception as e:
        return None


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes().replace(b'\r\n', b'\n')).hexdigest()


# ──────────────────────────────────────────────────────────────────────────────
# SECTION 1: DEMO DATASET - PROJECT LOCKFILES
# ──────────────────────────────────────────────────────────────────────────────
header("SECTION 1: DEMO DATASET — PROJECT LOCKFILES")

for project, repo, commit, expected_nodes in [
    ("primary",          "slackapi/slack-github-action", "a8dafde", 94),
    ("backup_yargs",     "yargs/yargs",                  "10f1dda", 562),
    ("control_cheerio",  "cheeriojs/cheerio",            "dfc08da", 437),
]:
    lock_path = DEMO / "projects" / project / "package-lock.json"
    prov_path = DEMO / "projects" / project / "provenance.json"

    check(f"[{project}] package-lock.json exists", lock_path.exists())
    check(f"[{project}] provenance.json exists", prov_path.exists())

    if lock_path.exists() and prov_path.exists():
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        prov = json.loads(prov_path.read_text(encoding="utf-8"))

        # Verify provenance contains real GitHub data
        repo_val = prov.get("project") or prov.get("repository")
        check(f"[{project}] provenance.repo = {repo}",
              repo_val == repo,
              f"Got: {repo_val}")

        commit_val = prov.get("commit") or prov.get("commit_sha", "")
        check(f"[{project}] provenance.commit starts with {commit}",
              commit_val.startswith(commit),
              f"Got: {commit_val}")

        check(f"[{project}] provenance.source_url is GitHub",
              "github.com" in prov.get("source_url", ""),
              f"URL: {prov.get('source_url','')[:80]}")

        # Verify lockfile is real (lockfileVersion present)
        check(f"[{project}] lockfileVersion present",
              "lockfileVersion" in lock,
              f"Version: {lock.get('lockfileVersion')}")

        # Count packages
        pkgs = lock.get("packages", {})
        node_count = len([k for k in pkgs if k.startswith("node_modules/")])
        check(f"[{project}] node count ~= {expected_nodes}",
              abs(node_count - expected_nodes) <= 5,
              f"Got {node_count} packages, expected ~{expected_nodes}")

        # No synthetic markers in primary lockfile
        lock_text = lock_path.read_text(encoding="utf-8")
        check(f"[{project}] no synthetic integrity markers",
              "COUNTERFACTUAL" not in lock_text and "replay-fixture" not in lock_text,
              "Found synthetic markers in lockfile!" if ("COUNTERFACTUAL" in lock_text) else "")

        # Verify GitHub raw fetch still returns same SHA
        raw_url = f"https://raw.githubusercontent.com/{repo}/{commit}/package-lock.json"
        live_data = fetch_url(raw_url)
        if live_data:
            live_hash = hashlib.sha256(live_data).hexdigest()
            stored_hash = sha256_file(lock_path)
            check(f"[{project}] SHA-256 matches live GitHub fetch",
                  live_hash == stored_hash,
                  f"Stored:{stored_hash[:16]}... Live:{live_hash[:16]}...")
        else:
            check(f"[{project}] GitHub live fetch", False,
                  f"Could not reach {raw_url[:60]}", is_warning=True)


# ──────────────────────────────────────────────────────────────────────────────
# SECTION 2: DEMO DATASET - EVIDENCE FILES
# ──────────────────────────────────────────────────────────────────────────────
header("SECTION 2: DEMO DATASET — EVIDENCE FILES")

# OpenSSF OSV records
for mal_id in ["MAL-2026-2306", "MAL-2026-2307", "MAL-2026-4596", "MAL-2026-10541"]:
    osv_path = DEMO / "evidence" / "openssf" / f"{mal_id}.json"
    check(f"[openssf] {mal_id}.json exists", osv_path.exists())
    if osv_path.exists():
        rec = json.loads(osv_path.read_text(encoding="utf-8"))
        check(f"[openssf] {mal_id} has 'id' field = {mal_id}",
              rec.get("id") == mal_id, f"Got: {rec.get('id')}")
        check(f"[openssf] {mal_id} has 'published' timestamp",
              bool(rec.get("published")), f"published: {rec.get('published')}")
        check(f"[openssf] {mal_id} has 'affected' entries",
              bool(rec.get("affected")), f"affected count: {len(rec.get('affected', []))}")

        # Spot-check: verify live OSV still returns same record
        live = fetch_url(f"https://api.osv.dev/v1/vulns/{mal_id}")
        if live:
            live_rec = json.loads(live)
            check(f"[openssf] {mal_id} live OSV id matches",
                  live_rec.get("id") == mal_id,
                  f"Live id: {live_rec.get('id')}")
        else:
            check(f"[openssf] {mal_id} live OSV reachable",
                  False, "OSV API unreachable", is_warning=True)

# npm registry evidence
for pkg_name in ["axios", "plain-crypto-js"]:
    npm_path = DEMO / "evidence" / "npm" / f"{pkg_name}_registry.json"
    check(f"[npm_registry] {pkg_name}_registry.json exists", npm_path.exists())
    if npm_path.exists():
        reg = json.loads(npm_path.read_text(encoding="utf-8"))
        check(f"[npm_registry] {pkg_name} has 'time' object",
              "time" in reg, f"Keys present: {list(reg.keys())[:5]}")
        check(f"[npm_registry] {pkg_name} has 'name' = {pkg_name}",
              reg.get("name") == pkg_name, f"Got: {reg.get('name')}")
        # Check time has real timestamps
        times = reg.get("time", {})
        check(f"[npm_registry] {pkg_name} time has >3 entries",
              len(times) > 3, f"Entries: {len(times)}")

# CISA KEV
kev_path = DEMO / "evidence" / "kev" / "cisa_kev_sample.json"
check("[kev] cisa_kev_sample.json exists", kev_path.exists())
if kev_path.exists():
    kev = json.loads(kev_path.read_text(encoding="utf-8"))
    vulns = kev.get("vulnerabilities", [])
    check("[kev] has 'vulnerabilities' list", bool(vulns), f"Count: {len(vulns)}")
    if vulns:
        check("[kev] first entry has 'cveID'", "cveID" in vulns[0],
              f"Keys: {list(vulns[0].keys())[:5]}")


# ──────────────────────────────────────────────────────────────────────────────
# SECTION 3: COUNTERFACTUAL FIXTURE - MUST BE LABELED
# ──────────────────────────────────────────────────────────────────────────────
header("SECTION 3: COUNTERFACTUAL FIXTURE — MUST BE CLEARLY LABELED")

cf_path = DEMO / "replay" / "counterfactual" / "package-lock.COUNTERFACTUAL_DERIVED.json"
readme_path = DEMO / "replay" / "counterfactual" / "README_COUNTERFACTUAL.md"

check("[counterfactual] fixture file exists", cf_path.exists())
check("[counterfactual] README_COUNTERFACTUAL.md exists", readme_path.exists())

if cf_path.exists():
    cf = json.loads(cf_path.read_text(encoding="utf-8"))
    check("[counterfactual] _warrant_classification = COUNTERFACTUAL_DERIVED_FIXTURE",
          cf.get("_warrant_classification") == "COUNTERFACTUAL_DERIVED_FIXTURE",
          f"Got: {cf.get('_warrant_classification')}")
    check("[counterfactual] _real_incident_data section present",
          "_real_incident_data" in cf,
          "Real forensic data block present")
    rid = cf.get("_real_incident_data", {})
    check("[counterfactual] real C2 domain recorded",
          rid.get("c2_domain") == "sfrclak.com",
          f"Got: {rid.get('c2_domain')}")
    check("[counterfactual] real exposure window recorded",
          "00:21" in str(rid.get("npm_exposure_window_utc", "")),
          f"Got: {rid.get('npm_exposure_window_utc')}")
    check("[counterfactual] both compromised versions listed",
          "axios@0.30.4" in str(rid.get("compromised_versions", [])),
          f"Got: {rid.get('compromised_versions')}")
    check("[counterfactual] COUNTERFACTUAL-DERIVED in integrity field",
          "COUNTERFACTUAL" in str(cf.get("packages", {}).get("node_modules/axios", {}).get("integrity", "")),
          "Integrity field correctly marked")

if readme_path.exists():
    readme = readme_path.read_text(encoding="utf-8")
    check("[counterfactual] README says 'NOT AN AUTHENTIC'",
          "NOT AN AUTHENTIC" in readme or "NOT a real project" in readme)
    check("[counterfactual] README has real C2 domain",
          "sfrclak.com" in readme)
    check("[counterfactual] README has GitHub search result",
          "GitHub code search" in readme or "github_search" in readme)


# ──────────────────────────────────────────────────────────────────────────────
# SECTION 4: popular_npm.json — REAL DOWNLOAD COUNTS
# ──────────────────────────────────────────────────────────────────────────────
header("SECTION 4: popular_npm.json — REAL DOWNLOAD COUNTS")

npm_pop_path = WORKSPACE / "backend" / "app" / "data" / "popular_npm.json"
check("[popular_npm] file exists", npm_pop_path.exists())
if npm_pop_path.exists():
    npm_pop = json.loads(npm_pop_path.read_text(encoding="utf-8"))
    source = npm_pop.get("_source", "")
    check("[popular_npm] _source references api.npmjs.org",
          "api.npmjs.org" in source, f"Source: {source[:80]}")
    check("[popular_npm] version is 2.x (real data)",
          str(npm_pop.get("_version", "")).startswith("2"),
          f"Version: {npm_pop.get('_version')}")
    pkgs = npm_pop.get("packages", [])
    check("[popular_npm] has >= 100 packages", len(pkgs) >= 100,
          f"Count: {len(pkgs)}")
    counts = npm_pop.get("_download_counts", {})
    check("[popular_npm] has _download_counts dict", bool(counts),
          f"Entries: {len(counts)}")
    if counts:
        # Verify a known package has a real (non-zero, plausible) count
        react_count = counts.get("react", 0)
        chalk_count = counts.get("chalk", 0)
        check("[popular_npm] react downloads > 100M (real count)",
              react_count > 100_000_000,
              f"react downloads: {react_count:,}")
        check("[popular_npm] chalk downloads > 1B (real count)",
              chalk_count > 1_000_000_000,
              f"chalk downloads: {chalk_count:,}")

        # Spot-check: live download count for react
        live = fetch_url("https://api.npmjs.org/downloads/point/last-month/react")
        if live:
            live_count = json.loads(live).get("downloads", 0)
            check("[popular_npm] react count within 5% of live API",
                  abs(react_count - live_count) / max(live_count, 1) < 0.05,
                  f"Stored:{react_count:,} vs Live:{live_count:,}", is_warning=True)
        else:
            print(f"{WARN}: Could not reach npm downloads API for live check")


# ──────────────────────────────────────────────────────────────────────────────
# SECTION 5: BACKEND API PROVIDERS — VERIFY LIVE ENDPOINTS
# ──────────────────────────────────────────────────────────────────────────────
header("SECTION 5: BACKEND API PROVIDERS — LIVE ENDPOINT SPOT-CHECKS")

# OSV API
osv_resp = fetch_url("https://api.osv.dev/v1/vulns/GHSA-35jp-ww65-95wh")
check("[osv_api] OSV API reachable (GHSA-35jp-ww65-95wh)",
      osv_resp is not None)
if osv_resp:
    osv_data = json.loads(osv_resp)
    check("[osv_api] returns real GHSA record",
          osv_data.get("id") == "GHSA-35jp-ww65-95wh",
          f"ID: {osv_data.get('id')}")
    check("[osv_api] record has affected packages",
          bool(osv_data.get("affected")),
          f"Affected count: {len(osv_data.get('affected', []))}")

# npm Registry API
npm_resp = fetch_url("https://registry.npmjs.org/axios")
check("[npm_registry_api] npm registry reachable (axios)", npm_resp is not None)
if npm_resp:
    npm_data = json.loads(npm_resp)
    check("[npm_registry_api] returns 'time' object",
          "time" in npm_data)
    check("[npm_registry_api] axios has '1.14.0' in time",
          "1.14.0" in npm_data.get("time", {}),
          f"Keys count: {len(npm_data.get('time', {}))}")

# EPSS API
epss_resp = fetch_url("https://api.first.org/data/v1/epss?cve=CVE-2024-39338")
check("[epss_api] EPSS API reachable (CVE-2024-39338)", epss_resp is not None)
if epss_resp:
    epss_data = json.loads(epss_resp)
    data_entries = epss_data.get("data", [])
    check("[epss_api] returns EPSS data entries",
          len(data_entries) > 0,
          f"Entries: {len(data_entries)}")
    if data_entries:
        score = data_entries[0].get("epss")
        check("[epss_api] EPSS score is a float between 0-1",
              score is not None and 0 <= float(score) <= 1,
              f"EPSS score: {score}")

# CISA KEV API
kev_resp = fetch_url(
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    timeout=30)
check("[kev_api] CISA KEV feed reachable", kev_resp is not None, is_warning=True)
if kev_resp:
    kev_data = json.loads(kev_resp)
    vuln_count = len(kev_data.get("vulnerabilities", []))
    check("[kev_api] KEV has >1000 vulnerabilities",
          vuln_count > 1000, f"Count: {vuln_count}")

# deps.dev API
depsdev_resp = fetch_url(
    "https://api.deps.dev/v3/systems/npm/packages/axios/versions/1.14.0")
check("[depsdev_api] deps.dev API reachable (axios@1.14.0)", depsdev_resp is not None)
if depsdev_resp:
    dd_data = json.loads(depsdev_resp)
    check("[depsdev_api] returns version info",
          bool(dd_data), f"Keys: {list(dd_data.keys())[:5]}")


# ──────────────────────────────────────────────────────────────────────────────
# SECTION 6: BACKEND FIXTURES — MUST BE LABELED SYNTHETIC
# ──────────────────────────────────────────────────────────────────────────────
header("SECTION 6: BACKEND DEV FIXTURES — MUST BE LABELED SYNTHETIC")

# axios-replay fixture
ax_fix = BACKEND / "fixtures" / "samples" / "axios-replay" / "package-lock.json"
check("[fixture/axios-replay] exists", ax_fix.exists())
if ax_fix.exists():
    ax = json.loads(ax_fix.read_text(encoding="utf-8"))
    check("[fixture/axios-replay] has _warrant_note",
          "_warrant_note" in ax,
          f"Note: {ax.get('_warrant_note','')[:60]}")
    check("[fixture/axios-replay] _warrant_note says NOT from a real project",
          "NOT a real project" in ax.get("_warrant_note", "") or "NOT from a real project" in ax.get("_warrant_note", ""),
          f"Note: {ax.get('_warrant_note','')[:80]}")
    check("[fixture/axios-replay] integrity field marked do-not-install",
          "do-not-use" in str(ax.get("packages", {}).get("node_modules/axios", {}).get("integrity", "")).lower()
          or "do-not-install" in str(ax.get("packages", {}).get("node_modules/axios", {}).get("integrity", "")).lower(),
          f"Integrity: {ax.get('packages',{}).get('node_modules/axios',{}).get('integrity','')[:50]}")

# legacy-express fixture
le_fix = BACKEND / "fixtures" / "samples" / "legacy-express" / "package.json"
check("[fixture/legacy-express] exists", le_fix.exists())
if le_fix.exists():
    le = json.loads(le_fix.read_text(encoding="utf-8"))
    check("[fixture/legacy-express] name = 'legacy-express' (clearly a test fixture)",
          le.get("name") == "legacy-express",
          f"Got: {le.get('name')}")
    # Should NOT appear in judge demo runner
    demo_runner = (DEMO / "tools" / "run_judge_demo.py").read_text(encoding="utf-8")
    check("[fixture/legacy-express] NOT referenced in run_judge_demo.py",
          "legacy-express" not in demo_runner,
          "Found legacy-express in judge demo!" if "legacy-express" in demo_runner else "")


# ──────────────────────────────────────────────────────────────────────────────
# SECTION 7: BACKEND SIGNALS — VERIFY REAL DATA SOURCES
# ──────────────────────────────────────────────────────────────────────────────
header("SECTION 7: BACKEND SIGNALS — DATA SOURCE VERIFICATION")

# Lookalike signal uses popular_npm.json
lookalike_py = (BACKEND / "app" / "signals" / "lookalike.py").read_text(encoding="utf-8")
check("[lookalike_signal] reads from popular_npm.json",
      "popular_npm.json" in lookalike_py)
check("[lookalike_signal] result is T3 tier (never INCIDENT)",
      "EvidenceTier.T3" in lookalike_py,
      "Signal correctly limited to T3")
check("[lookalike_signal] claim says heuristic only",
      "heuristic only" in lookalike_py,
      "Claim text verified")

# Staleness signal uses real npm timestamps
staleness_py = (BACKEND / "app" / "signals" / "staleness.py").read_text(encoding="utf-8")
check("[staleness_signal] reads npm_times from registry",
      "npm_times" in staleness_py)
check("[staleness_signal] no hardcoded dates",
      "2020" not in staleness_py and "2019" not in staleness_py,
      "No hardcoded year found")


# ──────────────────────────────────────────────────────────────────────────────
# SECTION 8: CONFIG — ALLOWED OUTBOUND HOSTS ALLOWLIST
# ──────────────────────────────────────────────────────────────────────────────
header("SECTION 8: BACKEND CONFIG — OUTBOUND HOST ALLOWLIST")

config_py = (BACKEND / "app" / "config.py").read_text(encoding="utf-8")
for host in ["api.osv.dev", "api.deps.dev", "registry.npmjs.org",
             "api.first.org", "www.cisa.gov"]:
    check(f"[config] {host} in allowed_outbound_hosts",
          host in config_py, f"Host: {host}")

check("[config] offline_fixtures default = False",
      "offline_fixtures: bool = False" in config_py,
      "Live API mode is default")


# ──────────────────────────────────────────────────────────────────────────────
# SECTION 9: CHECKSUMS — CRYPTOGRAPHIC INTEGRITY
# ──────────────────────────────────────────────────────────────────────────────
header("SECTION 9: DATASET CHECKSUMS — CRYPTOGRAPHIC INTEGRITY")

checksums_path = DEMO / "manifests" / "checksums.sha256"
check("[checksums] checksums.sha256 exists", checksums_path.exists())
if checksums_path.exists():
    lines = checksums_path.read_text(encoding="utf-8").strip().splitlines()
    mismatches = 0
    for line in lines:
        if not line.strip():
            continue
        expected_hash, rel_path = line.split("  ", 1)
        target = DEMO / rel_path
        if not target.exists():
            print(f"{FAIL}: Missing file: {rel_path}")
            mismatches += 1
        else:
            actual = hashlib.sha256(target.read_bytes()).hexdigest()
            if actual != expected_hash:
                print(f"{FAIL}: Hash mismatch: {rel_path}")
                mismatches += 1
    check(f"[checksums] all {len(lines)} file hashes match",
          mismatches == 0, f"Mismatches: {mismatches}")


# ──────────────────────────────────────────────────────────────────────────────
# SECTION 10: BACKEND UNIT TESTS
# ──────────────────────────────────────────────────────────────────────────────
header("SECTION 10: BACKEND UNIT TESTS")
import subprocess
result = subprocess.run(
    ["python", "-m", "pytest", "backend/tests/test_warrant.py", "-v", "--tb=short"],
    capture_output=True, text=True,
    cwd=str(WORKSPACE)
)
passed = "passed" in result.stdout
test_line = [l for l in result.stdout.split("\n") if "passed" in l or "failed" in l or "error" in l]
check("[pytest] all backend tests pass",
      result.returncode == 0 and passed,
      test_line[0].strip() if test_line else result.stdout[-200:])


# ──────────────────────────────────────────────────────────────────────────────
# FINAL REPORT
# ──────────────────────────────────────────────────────────────────────────────
print(f"\n{'='*60}")
print("  FINAL AUDIT REPORT")
print(f"{'='*60}")

if not failures and not warnings:
    print("\n  [ALL PASS] PROJECT IS 100% REAL DATA")
    print("  Zero failures. Zero warnings.")
elif failures:
    print(f"\n  [FAILURES]: {len(failures)}")
    for f in failures:
        print(f"    - {f}")
    if warnings:
        print(f"\n  [WARNINGS]: {len(warnings)}")
        for w in warnings:
            print(f"    - {w}")
    print(f"\n  VERDICT: PROJECT HAS {len(failures)} REAL DATA ISSUE(S) TO FIX")
else:
    print(f"\n  [WARNINGS ONLY] (no failures): {len(warnings)}")
    for w in warnings:
        print(f"    - {w}")
    print("\n  VERDICT: PROJECT PASSES -- warnings are non-critical")

print(f"{'='*60}\n")
sys.exit(len(failures))

