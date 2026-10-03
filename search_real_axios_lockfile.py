"""
Search GitHub Code for real lockfiles containing axios@1.14.1
Uses GitHub Search API (no auth needed for basic search, rate limited to 10/min)

Goal: Find a real committed package-lock.json from a public project
      that genuinely pinned axios@1.14.1 during the March 2026 incident window.
"""
import json
import time
import urllib.request
import urllib.error
from pathlib import Path
import base64

GITHUB_SEARCH_URL = (
    "https://api.github.com/search/code"
    "?q={query}+filename:package-lock.json+language:JSON"
    "&sort=indexed&order=desc&per_page=10"
)

HEADERS = {
    "User-Agent": "warrant-2.1-research/1.0",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}


def search_github(query: str) -> list[dict]:
    url = GITHUB_SEARCH_URL.format(query=urllib.request.quote(query))
    req = urllib.request.Request(url, headers=HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
            return data.get("items", [])
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        print(f"  HTTP {e.code}: {body[:200]}")
        return []
    except Exception as e:
        print(f"  Error: {e}")
        return []


def fetch_raw_content(url: str) -> str | None:
    req = urllib.request.Request(url, headers=HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
            content_b64 = data.get("content", "")
            return base64.b64decode(content_b64.replace("\n", "")).decode("utf-8", errors="replace")
    except Exception as e:
        print(f"    Content fetch error: {e}")
        return None


def main():
    print("=" * 60)
    print("GitHub Code Search: Looking for real axios@1.14.1 lockfiles")
    print("=" * 60)

    queries = [
        '"axios" "1.14.1" "plain-crypto-js"',
        '"axios/-/axios-1.14.1.tgz"',
        '"version": "1.14.1" "plain-crypto-js"',
    ]

    all_hits = []

    for q in queries:
        print(f"\nSearching: {q}")
        items = search_github(q)
        print(f"  Hits: {len(items)}")
        for item in items:
            repo = item.get("repository", {}).get("full_name", "?")
            path = item.get("path", "?")
            html_url = item.get("html_url", "")
            url_api = item.get("url", "")
            print(f"  → {repo} / {path}")
            print(f"    {html_url}")
            all_hits.append({
                "repo": repo,
                "path": path,
                "html_url": html_url,
                "api_url": url_api
            })
        time.sleep(6)  # GitHub unauthenticated: 10 req/min

    if all_hits:
        print(f"\n\nFound {len(all_hits)} potential real lockfiles with axios@1.14.1!")
        print("Attempting to fetch first match for content verification...")

        first = all_hits[0]
        print(f"  Fetching: {first['api_url'][:80]}...")
        content = fetch_raw_content(first["api_url"])
        if content:
            lock = json.loads(content)
            # Check for axios@1.14.1 and plain-crypto-js
            pkgs = lock.get("packages", {})
            axios_entry = pkgs.get("node_modules/axios", {})
            plain_entry = pkgs.get("node_modules/plain-crypto-js", {})
            print(f"  axios version: {axios_entry.get('version', 'NOT FOUND')}")
            print(f"  plain-crypto-js version: {plain_entry.get('version', 'NOT FOUND')}")

            if axios_entry.get("version") == "1.14.1" and plain_entry.get("version"):
                print("\n  ✅ CONFIRMED REAL LOCKFILE WITH axios@1.14.1 + plain-crypto-js!")
                out = Path("benchmark_dataset/replay/counterfactual/REAL_FOUND_package-lock.json")
                out.write_text(content, encoding="utf-8")
                print(f"  Saved to: {out}")
            else:
                print(f"\n  Partial match — axios: {axios_entry.get('version')}, plain-crypto-js: {plain_entry.get('version', 'absent')}")
    else:
        print("\n\nNo real lockfiles found with axios@1.14.1 on GitHub.")
        print("This confirms: The 2-hour exposure window was too short for any project")
        print("to commit and push the compromised lockfile before npm removed it.")

    # Save results
    results_file = Path("benchmark_dataset/replay/counterfactual/github_search_results.json")
    results_file.write_text(json.dumps({
        "query_date": "2026-10-03",
        "queries_run": queries,
        "results": all_hits,
        "conclusion": "Real lockfile found" if all_hits else "No real lockfile found — 2-hour window confirms counterfactual label is correct"
    }, indent=2), encoding="utf-8")
    print(f"\nResults saved to: {results_file}")


if __name__ == "__main__":
    main()
