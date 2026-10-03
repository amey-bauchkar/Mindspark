#!/usr/bin/env python3
"""
Record a Warrant Watch DEMO / REPLAY scenario from REAL public sources.

For the exact package versions in a sample lockfile, this queries only Warrant's
allowlisted hosts (api.osv.dev, www.cisa.gov, api.first.org, registry.npmjs.org) and
stores the raw responses, so the replay runs deterministically and offline. Nothing is
installed or executed. Every stored file is pinned by SHA-256 in scenario.json and
verified when the scenario is loaded.

Usage (from backend/):
  python tools/record_watch_replay.py --id slack-action-axios-2026-04 --sample slack-action \
      --start 2026-04-01T12:00:00Z --end 2026-04-14T23:59:59Z \
      --title "..." --description "..." --authenticity "..." --source-url "..."
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import httpx

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

from app.config import get_settings  # noqa: E402
from app.graph.build import build_graph  # noqa: E402
from app.parsers.npm_lock import parse_npm_lock  # noqa: E402
from app.providers.osv import _purl_to_query  # noqa: E402
from app.security import check_url_allowlist  # noqa: E402
from app.watch.replay import REPLAY_DIR, REPLAY_LABEL, RecordedFeed, _dt, record_available_at  # noqa: E402

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/{id}"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
REGISTRY = "https://registry.npmjs.org/{name}"


def get(client: httpx.Client, url: str, **kw) -> httpx.Response:
    assert check_url_allowlist(url), f"host not allowlisted: {url}"
    resp = client.request(kw.pop("method", "GET"), url, timeout=60, **kw)
    resp.raise_for_status()
    return resp


def write_json(base: Path, rel: str, data) -> str:
    path = base / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--id", required=True)
    ap.add_argument("--sample", required=True, help="fixtures/samples/<sample>/package-lock.json")
    ap.add_argument("--start", required=True)
    ap.add_argument("--end", required=True)
    ap.add_argument("--title", required=True)
    ap.add_argument("--description", default="")
    ap.add_argument("--authenticity", required=True)
    ap.add_argument("--source-url", default=None)
    ap.add_argument("--note", action="append", default=[])
    args = ap.parse_args()

    start, end = _dt(args.start), _dt(args.end)
    lock = BACKEND / "fixtures" / "samples" / args.sample / "package-lock.json"
    build = build_graph(parse_npm_lock(lock.read_text(encoding="utf-8")))
    purls = list(build.packages)
    # Exactly the packages the pipeline requests registry metadata for (jobs.analyze_npm_lock, stage 5)
    direct = list(dict.fromkeys(p.name for p in build.packages.values() if p.is_direct))[:50]
    out = REPLAY_DIR / args.id
    files: dict[str, str] = {}
    retrieved_at = datetime.now(timezone.utc).isoformat()

    with httpx.Client(headers={"Accept": "application/json"}) as client:
        # 1. OSV: advisories + OpenSSF MAL-* records for the exact resolved versions
        # OSV decides which records affect each exact purl (querybatch); the replay reuses that verdict.
        matches: dict[str, list[str]] = {}
        for i in range(0, len(purls), 500):
            chunk = purls[i:i + 500]
            res = get(client, OSV_BATCH, method="POST", json={"queries": [_purl_to_query(p) for p in chunk]}).json()
            for purl, r in zip(chunk, res.get("results", [])):
                if r.get("vulns"):
                    matches[purl] = [v["id"] for v in r["vulns"]]
        ids = {vid for vids in matches.values() for vid in vids}
        records = []
        for vid in sorted(ids):
            rec = get(client, OSV_VULN.format(id=vid)).json()
            available = record_available_at(rec)
            if available and available <= end:
                records.append(rec)
        osv_files = []
        for rec in records:
            rel = f"osv/{rec['id']}.json"
            files[rel] = write_json(out, rel, rec)
            osv_files.append(rel)
        kept = {r["id"] for r in records}
        files["osv_matches.json"] = write_json(out, "osv_matches.json", {
            "source": OSV_BATCH, "retrieved_at": retrieved_at,
            "matches": {purl: [v for v in vids if v in kept] for purl, vids in matches.items() if set(vids) & kept},
        })
        cves = sorted({a for r in records for a in r.get("aliases", []) if a.startswith("CVE-")})

        # 2. CISA KEV: the subset of the live catalogue covering these CVEs (dateAdded gates availability)
        kev = get(client, KEV_URL).json()
        listed = [
            {k: v.get(k) for k in ("cveID", "dateAdded", "vendorProject", "product", "vulnerabilityName")}
            for v in kev.get("vulnerabilities", []) if v.get("cveID") in cves
        ]
        files["kev.json"] = write_json(out, "kev.json", {
            "source": KEV_URL, "retrieved_at": retrieved_at, "catalog_version": kev.get("catalogVersion"),
            "cves_checked": cves, "vulnerabilities": listed,
        })

        # 3. EPSS: historical daily scores for the start day and every day the feed changes
        feed = RecordedFeed(osv_records=records)
        days = sorted({start.date().isoformat()} | {t.date().isoformat() for t in feed.change_times(start, end)})
        scores: dict[str, dict[str, float]] = {}
        for day in days:
            scores[day] = {}
            if cves:
                data = get(client, EPSS_URL, params={"cve": ",".join(cves), "date": day}).json()
                scores[day] = {d["cve"]: float(d["epss"]) for d in data.get("data", []) if d.get("epss") is not None}
        files["epss.json"] = write_json(out, "epss.json", {
            "source": EPSS_URL, "retrieved_at": retrieved_at, "cves_checked": cves, "scores": scores,
        })

        # 4. npm registry publish times for direct dependencies (staleness/freshness signals)
        registry = {}
        for name in direct:
            times = get(client, REGISTRY.format(name=name.replace("/", "%2F"))).json().get("time", {})
            kept = {k: v for k, v in times.items() if (_dt(v) or end) <= end}
            rel = f"registry/{name.replace('@', '').replace('/', '__')}.json"
            files[rel] = write_json(out, rel, kept)
            registry[name] = rel

    manifest = {
        "id": args.id,
        "title": args.title,
        "description": args.description,
        "label": REPLAY_LABEL,
        "project": {
            "sample_id": args.sample,
            "filename": "package-lock.json",
            "authenticity": args.authenticity,
            "source_url": args.source_url,
            "package_count": len(purls),
        },
        "clock": {"start": start.isoformat(), "end": end.isoformat()},
        "recorded_at": retrieved_at,
        "recorded_by": "backend/tools/record_watch_replay.py",
        "availability_rule": "OSV record available at its earliest OpenSSF import_time when present, else its "
                             "`published` time; KEV from dateAdded; EPSS from the latest recorded day <= clock.",
        "matching": "Which records affect which exact purl is OSV's own querybatch result (osv_matches.json).",
        "notes": [
            "Evidence is real: raw records returned by OSV, CISA KEV, FIRST EPSS and the npm registry on recorded_at.",
            "Record content is the snapshot retrieved on recorded_at; availability is gated by the record's own "
            "publication/import time and later withdrawal/modification timestamps are hidden from the replay clock.",
            *args.note,
        ],
        "sources": {"osv": osv_files, "osv_matches": "osv_matches.json", "kev": "kev.json", "epss": "epss.json",
                    "registry": registry},
        "files": files,
    }
    write_json(out, "scenario.json", manifest)
    print(f"Recorded {len(records)} OSV records, {len(cves)} CVEs, {len(listed)} KEV entries, "
          f"{len(days)} EPSS days, {len(registry)} registry entries -> {out}")
    for t in feed.change_times(start, end):
        print("  step", t.isoformat(), [r["id"] for r in records if record_available_at(r) == t])


if __name__ == "__main__":
    get_settings()
    main()
