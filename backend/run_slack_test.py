import asyncio
import urllib.request
import json
from app.jobs import run_analysis
from app.providers.cache import load_report

async def test():
    url = "https://raw.githubusercontent.com/slackapi/slack-github-action/a8dafde/package-lock.json"
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    content = urllib.request.urlopen(req, timeout=15).read().decode("utf-8")
    rid = "test-slack-run"
    print("Running analysis on slackapi/slack-github-action @ a8dafde...")
    await run_analysis(rid, content, "package-lock.json", {})
    rep = load_report(rid)
    print("Report completed!")
    print(f"Total findings decisions: {len(rep['decisions'])}")
    print("Summary:", json.dumps(rep["summary"], indent=2))
    for d in rep["decisions"]:
        print(f"  [{d['verdict']}] {d['subject']} (scope={d['exposure']['scope']}): {d['what']}")
    
    print("\nCoverage checks:")
    for c in rep.get("coverage", []):
        print(f"  {c['check']}: {c['status']} ({c.get('reason') or ''})")

asyncio.run(test())
