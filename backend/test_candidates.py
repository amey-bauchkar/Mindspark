import urllib.request
import json
from app.parsers.npm_lock import parse_npm_lock
from app.graph.build import build_graph, ROOT_ID

candidates = [
    ("slackapi/slack-github-action", "a8dafde"),
    ("yargs/yargs", "10f1dda"),
    ("cheeriojs/cheerio", "dfc08da")
]

for repo, commit in candidates:
    url = f"https://raw.githubusercontent.com/{repo}/{commit}/package-lock.json"
    print(f"\n==========================================")
    print(f"Candidate: {repo} @ {commit}")
    print(f"==========================================")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            content = resp.read().decode("utf-8")
        data = json.loads(content)
        lv = data.get("lockfileVersion")
        pr = parse_npm_lock(content)
        bg = build_graph(pr)
        total_nodes = len(bg.packages)
        direct_nodes = len([p for p in bg.packages.values() if p.is_direct])
        transitive_nodes = total_nodes - direct_nodes
        total_edges = bg.graph.number_of_edges()
        prod_count = len([p for p in bg.packages.values() if p.scope == "prod"])
        dev_count = len([p for p in bg.packages.values() if p.scope == "dev"])
        
        print(f"  Lockfile Version: {lv}")
        print(f"  Total Unique Packages: {total_nodes}")
        print(f"  Direct Dependencies: {direct_nodes}")
        print(f"  Transitive Dependencies: {transitive_nodes}")
        print(f"  Graph Total Edges: {total_edges}")
        print(f"  Scopes -> Prod: {prod_count}, Dev: {dev_count}")
        print(f"  Cycles Detected: {bg.cycles_detected}")
        print(f"  Warnings: {len(bg.warnings)}")
        if bg.warnings:
            for w in bg.warnings[:3]:
                print(f"    - {w}")
    except Exception as e:
        print(f"  Error evaluating {repo}: {e}")
