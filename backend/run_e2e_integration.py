"""End-to-end integration test — runs a real analysis of the legacy-express sample.

Usage:
  python backend/run_e2e_integration.py
"""
import requests
import time
import sys

BASE = "http://localhost:8000"


def main():
    print("=== Warrant E2E Integration Test ===\n")

    # 1. Health check
    try:
        h = requests.get(f"{BASE}/api/health", timeout=5).json()
    except Exception as e:
        print(f"ERROR: Cannot connect to {BASE}/api/health: {e}")
        print("Please start the backend server first: uvicorn app.main:app --port 8000")
        sys.exit(1)

    assert h["status"] == "ok", f"Health check failed: {h}"
    print(f"[OK] Health: status={h['status']}, offline={h['offline']}, epss_threshold={h['epss_threshold']}")

    # 2. Samples
    samples = requests.get(f"{BASE}/api/samples").json()["samples"]
    assert len(samples) >= 3, f"Expected 3+ samples, got {len(samples)}"
    print(f"[OK] Samples: {[s['id'] for s in samples]}")

    # 3. Methodology
    meth = requests.get(f"{BASE}/api/methodology").json()
    assert len(meth["rules"]) >= 7, f"Expected 7+ rules"
    assert len(meth["license_rules"]) >= 7, "Expected 7+ license rules"
    assert len(meth["verdict_definitions"]) >= 7, "Expected 7+ verdicts"
    print(f"[OK] Methodology: {len(meth['rules'])} rules, {len(meth['license_rules'])} license rules")

    # 4. Start analysis: legacy-express sample
    resp = requests.post(f"{BASE}/api/analyze/sample/legacy-express", data={"context": "{}"})
    assert resp.status_code == 200, f"Analyze failed: {resp.text}"
    report_id = resp.json()["report_id"]
    print(f"\n[OK] Analysis started: {report_id}")

    # 5. Poll status
    for i in range(120):
        status = requests.get(f"{BASE}/api/reports/{report_id}/status").json()
        stage = status.get("stage", "")
        pct = status.get("progress", 0)
        if i % 5 == 0 or stage == "done":
            print(f"  [{pct:3}%] {stage}")
        if stage == "done":
            break
        if status.get("error"):
            print(f"ERROR: {status['error']}")
            sys.exit(1)
        time.sleep(1)
    else:
        print("TIMEOUT: Analysis did not complete in 120s")
        sys.exit(1)

    # 6. Fetch report
    report = requests.get(f"{BASE}/api/reports/{report_id}").json()
    s = report["summary"]

    print(f"\n[OK] Report received:")
    print(f"  INCIDENT:       {s['incident']}")
    print(f"  ACT_NOW:        {s['act_now']}")
    print(f"  UPGRADE:        {s['upgrade']}")
    print(f"  MONITOR:        {s['monitor']}")
    print(f"  REVIEW:         {s['review']}")
    print(f"  CANNOT_ASSESS:  {s['cannot_assess']}")
    print(f"  NKF:            {s['no_known_finding']}")
    print(f"  TOTAL:          {s['total_packages']}")
    print(f"  ECOSYSTEM:      {s['ecosystem']}")
    print(f"  DATA_BADGE:     {s['data_badge']}")

    # 7. Validate report structure
    decisions = report["decisions"]
    evidence = report["evidence"]
    coverage = report["coverage"]
    licenses = report["licenses"]

    assert isinstance(decisions, list), "decisions must be a list"
    assert isinstance(evidence, list), "evidence must be a list"
    assert isinstance(coverage, list), "coverage must be a list"
    assert isinstance(licenses, list), "licenses must be a list"
    print(f"\n[OK] Decisions: {len(decisions)}, Evidence: {len(evidence)}, Coverage: {len(coverage)}, Licenses: {len(licenses)}")

    # 8. Validate each decision has required fields
    for dec in decisions:
        for field in ["subject", "name", "version", "verdict", "urgency", "qualifier", "exposure", "evidence_ids", "as_of", "derivation", "what"]:
            assert field in dec, f"Decision missing field: {field}"
        assert dec["verdict"] in ["INCIDENT","ACT_NOW","UPGRADE","MONITOR","REVIEW","CANNOT_ASSESS","NO_KNOWN_FINDING"], f"Invalid verdict: {dec['verdict']}"
        assert len(dec["derivation"]) > 0, f"No derivation for {dec['name']}"
    print(f"[OK] All {len(decisions)} decisions have required fields and derivations")

    # 9. Validate each decision has exposure paths (for npm)
    decisions_with_paths = [d for d in decisions if len(d["exposure"]["paths"]) > 0]
    print(f"[OK] {len(decisions_with_paths)}/{len(decisions)} decisions have dependency paths")

    # 10. Export endpoints
    json_export = requests.get(f"{BASE}/api/reports/{report_id}/export?format=json")
    assert json_export.status_code == 200
    md_export = requests.get(f"{BASE}/api/reports/{report_id}/export?format=md")
    assert md_export.status_code == 200
    print("[OK] Export endpoints work (JSON + Markdown)")

    # 11. Verifier self-test
    verify = requests.post(f"{BASE}/api/verify-demo", json={}).json()
    assert verify["passed"] == False, "Synthetic corrupted claim should FAIL"
    assert "gate" in verify
    print(f"[OK] Verifier self-test: claim correctly rejected at gate={verify['gate']}")

    # 12. Context update
    ctx_resp = requests.post(
        f"{BASE}/api/reports/{report_id}/context",
        json={"distribution_mode": "Distributed", "project_license": "Proprietary"},
    )
    assert ctx_resp.status_code == 200
    print("[OK] Context update endpoint works")

    # 13. Python requirements sample
    py_resp = requests.post(f"{BASE}/api/analyze/sample/python-requirements", data={"context": "{}"})
    py_id = py_resp.json()["report_id"]
    for _ in range(90):
        st = requests.get(f"{BASE}/api/reports/{py_id}/status").json()
        if st.get("stage") == "done": break
        if st.get("error"): print(f"Python sample error: {st['error']}"); sys.exit(1)
        time.sleep(1)
    py_report = requests.get(f"{BASE}/api/reports/{py_id}").json()
    print(f"[OK] Python sample: {py_report['summary']['total_packages']} packages, ecosystem={py_report['summary']['ecosystem']}")

    # 14. Axios replay sample
    ax_resp = requests.post(f"{BASE}/api/analyze/sample/axios-replay", data={"context": "{}"})
    ax_id = ax_resp.json()["report_id"]
    for _ in range(90):
        st = requests.get(f"{BASE}/api/reports/{ax_id}/status").json()
        if st.get("stage") == "done": break
        if st.get("error"): print(f"Axios sample error: {st['error']}"); sys.exit(1)
        time.sleep(1)
    ax_report = requests.get(f"{BASE}/api/reports/{ax_id}").json()
    print(f"[OK] Axios replay sample: {ax_report['summary']['total_packages']} packages")

    # 15. Summary
    print("\n=== ALL INTEGRATION TESTS PASSED ===")
    print(f"Report URL: http://localhost:5173/report/{report_id}")


if __name__ == "__main__":
    main()
