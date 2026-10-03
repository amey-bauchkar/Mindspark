"""
DEMO / REPLAY evidence feed for Warrant Watch.

Serves *recorded* real-source evidence (raw OSV / OpenSSF records, a CISA KEV subset,
historical EPSS scores, npm registry publish times) as it existed at a simulated clock,
through the same `EvidenceProviders` interface the live pipeline uses. OSV records are
converted by the live provider's own `build_osv_evidence`, so no matching or decision
logic is duplicated.

Temporal rules (nothing from the future of the replay clock is ever served):
- An OSV record becomes available at its earliest OpenSSF/OSV import time when known
  (`database_specific.malicious-packages-origins[].import_time`), else its `published` time.
- `withdrawn` / `modified` timestamps later than the clock are hidden.
- KEV entries count from their `dateAdded`; EPSS uses the latest recorded day ≤ clock.
- Registry publish times later than the clock are dropped.
- Matching is OSV's own: the recorder stores OSV's querybatch result for each exact
  resolved purl, so the replay never re-implements version-range matching.

Every replay watch, check, event and report is labelled DEMO / REPLAY / SIMULATED EVENT.
"""
from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

from ..jobs import EvidenceProviders
from ..models.evidence import EvidenceRecord
from ..providers.health import report_provider_issue
from ..providers.osv import build_osv_evidence

REPLAY_LABEL = "DEMO / REPLAY / SIMULATED EVENT"
REPLAY_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures" / "watch_replay"


def _dt(value: str | None) -> datetime | None:
    if not value:
        return None
    dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def record_available_at(record: dict) -> datetime | None:
    """When a recorded OSV record could first have been observed by a monitor."""
    origins = (record.get("database_specific") or {}).get("malicious-packages-origins") or []
    imports = [_dt(o.get("import_time")) for o in origins if o.get("import_time")]
    imports = [t for t in imports if t]
    published = _dt(record.get("published"))
    if imports:
        earliest = min(imports)
        return max(earliest, published) if published else earliest
    return published


def record_as_of(record: dict, clock: datetime) -> dict | None:
    """The record as a monitor could have seen it at `clock`, or None if not yet available."""
    available = record_available_at(record)
    if available is None or available > clock:
        return None
    shaped = copy.deepcopy(record)
    withdrawn = _dt(shaped.get("withdrawn"))
    if withdrawn and withdrawn > clock:
        shaped.pop("withdrawn", None)
    modified = _dt(shaped.get("modified"))
    if modified and modified > clock:
        shaped.pop("modified", None)
    return shaped


@dataclass
class RecordedFeed:
    osv_records: list[dict] = field(default_factory=list)
    osv_matches: dict[str, list[str]] = field(default_factory=dict)  # purl → record ids (OSV's own match)
    kev: dict | None = None            # {"vulnerabilities": [{"cveID", "dateAdded", ...}], ...}
    epss: dict | None = None           # {"scores": {"YYYY-MM-DD": {"CVE-…": 0.01}}, ...}
    registry_times: dict[str, dict] = field(default_factory=dict)

    def change_times(self, after: datetime, until: datetime | None = None) -> list[datetime]:
        """Times at which the feed's content changes (record released/withdrawn, KEV addition)."""
        times: set[datetime] = set()
        for rec in self.osv_records:
            for t in (record_available_at(rec), _dt(rec.get("withdrawn"))):
                if t:
                    times.add(t)
        for entry in (self.kev or {}).get("vulnerabilities", []):
            t = _dt(entry.get("dateAdded"))
            if t:
                times.add(t)
        return sorted(t for t in times if t > after and (until is None or t <= until))

    def released_between(self, start: datetime, end: datetime) -> list[dict]:
        """Describe what became available in (start, end] — for the replay UI."""
        out = []
        for rec in self.osv_records:
            available = record_available_at(rec)
            if available and start < available <= end:
                out.append({"id": rec.get("id"), "change": "published", "published_at": rec.get("published"),
                            "available_at": available.isoformat(), "summary": rec.get("summary", "")[:160]})
            withdrawn = _dt(rec.get("withdrawn"))
            if withdrawn and start < withdrawn <= end:
                out.append({"id": rec.get("id"), "change": "withdrawn", "available_at": withdrawn.isoformat()})
        for entry in (self.kev or {}).get("vulnerabilities", []):
            added = _dt(entry.get("dateAdded"))
            if added and start < added <= end:
                out.append({"id": entry.get("cveID"), "change": "added to CISA KEV", "available_at": added.isoformat()})
        return out

    def providers(self, clock: datetime) -> EvidenceProviders:
        feed = self

        records = {rec["id"]: rec for rec in feed.osv_records}

        async def osv_batch(purls: list[str]) -> list[EvidenceRecord]:
            ids_for_purl: dict[str, list[str]] = {}
            details: dict[str, dict] = {}
            for purl in purls:
                for vid in feed.osv_matches.get(purl, []):
                    shaped = record_as_of(records[vid], clock) if vid in records else None
                    if shaped is None:
                        continue
                    ids_for_purl.setdefault(purl, []).append(vid)
                    details[vid] = shaped
            return build_osv_evidence(ids_for_purl, details, clock)

        async def kev() -> set[str]:
            if feed.kev is None:
                report_provider_issue("kev", "CISA KEV is not part of this replay feed", scope="not_checked")
                return set()
            return {
                e["cveID"] for e in feed.kev.get("vulnerabilities", [])
                if e.get("cveID") and (_dt(e.get("dateAdded")) or clock) <= clock
            }

        async def epss(cves: list[str]) -> dict[str, float]:
            if not cves:
                return {}
            days = sorted(d for d in ((feed.epss or {}).get("scores") or {}) if d <= clock.date().isoformat())
            if not days:
                report_provider_issue("epss", f"EPSS not recorded for {clock.date()} in this replay feed",
                                      scope="not_checked", count=len(cves))
                return {}
            scores = feed.epss["scores"][days[-1]]
            return {c: float(scores[c]) for c in cves if c in scores}

        async def licenses(packages: list[tuple[str, str]]) -> dict:
            return {}  # Replay uses lockfile license fields only (no network)

        async def npm_times(packages: list[tuple[str, str]]) -> dict[str, dict | None]:
            out: dict[str, dict | None] = {}
            for name, _ in packages:
                times = feed.registry_times.get(name)
                if times is None:
                    out[name] = None
                    continue
                out[name] = {k: v for k, v in times.items() if (_dt(v) or clock) <= clock}
            return out

        return EvidenceProviders(osv_batch=osv_batch, epss=epss, kev=kev, licenses=licenses, npm_times=npm_times)


@dataclass
class Scenario:
    id: str
    title: str
    description: str
    project: dict
    start: datetime
    end: datetime
    feed: RecordedFeed
    meta: dict

    def lockfile_path(self) -> Path:
        return REPLAY_DIR.parent / "samples" / self.project["sample_id"] / self.project.get("filename", "package-lock.json")

    def next_change_after(self, clock: datetime) -> datetime | None:
        upcoming = self.feed.change_times(clock, self.end)
        return upcoming[0] if upcoming else None

    def summary(self) -> dict:
        steps = self.feed.change_times(self.start, self.end)
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "label": REPLAY_LABEL,
            "project": self.project,
            "start": self.start.isoformat(),
            "end": self.end.isoformat(),
            "steps": [t.isoformat() for t in steps],
            "recorded_at": self.meta.get("recorded_at"),
            "notes": self.meta.get("notes", []),
        }


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@lru_cache(maxsize=8)
def load_scenario(scenario_id: str) -> Scenario:
    if not scenario_id.replace("-", "").replace("_", "").isalnum():
        raise KeyError(scenario_id)
    base = REPLAY_DIR / scenario_id
    manifest_path = base / "scenario.json"
    if not manifest_path.is_file():
        raise KeyError(scenario_id)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    # Integrity: every recorded file must match the digest captured when it was recorded.
    for rel, digest in manifest.get("files", {}).items():
        path = (base / rel).resolve()
        if base.resolve() not in path.parents or _sha256(path) != digest:
            raise ValueError(f"Replay scenario {scenario_id}: recorded file {rel} failed integrity check")

    def load(rel: str):
        return json.loads((base / rel).read_text(encoding="utf-8"))

    sources = manifest.get("sources", {})
    feed = RecordedFeed(
        osv_records=[load(rel) for rel in sources.get("osv", [])],
        osv_matches=load(sources["osv_matches"])["matches"] if sources.get("osv_matches") else {},
        kev=load(sources["kev"]) if sources.get("kev") else None,
        epss=load(sources["epss"]) if sources.get("epss") else None,
        registry_times={name: load(rel) for name, rel in sources.get("registry", {}).items()},
    )
    return Scenario(
        id=manifest["id"],
        title=manifest["title"],
        description=manifest.get("description", ""),
        project=manifest["project"],
        start=_dt(manifest["clock"]["start"]),
        end=_dt(manifest["clock"]["end"]),
        feed=feed,
        meta=manifest,
    )


def list_scenarios() -> list[dict]:
    out = []
    if REPLAY_DIR.is_dir():
        for child in sorted(REPLAY_DIR.iterdir()):
            if (child / "scenario.json").is_file():
                try:
                    out.append(load_scenario(child.name).summary())
                except (KeyError, ValueError):
                    continue
    return out
