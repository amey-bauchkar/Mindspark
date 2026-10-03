"""
Dependency snapshot — the exact resolved dependency state of an analysed npm lockfile,
reduced to what the graph builder and decision engine consume.

A snapshot round-trips to a ParseResult, so Warrant Watch can rebuild the identical
graph with `build_graph` and re-run the existing pipeline without the original upload.

Deliberately NOT stored: integrity hashes, version-range requirements, registry
tarball URLs (kept only for git/file sources, which the engine cites), or any other
lockfile content.
"""
from __future__ import annotations

from typing import Any

from .npm_lock import ParseResult, ParsedPackage

SNAPSHOT_VERSION = 1

# Analysis-context keys the pipeline reads (see jobs._parse_context). Anything else is dropped.
CONTEXT_KEYS = (
    "distribution_mode",
    "project_license",
    "install_scripts_run",
    "company_policy",
    "banned_dependencies",
)


def clean_context(context_data: dict | None) -> dict:
    if not isinstance(context_data, dict):
        return {}
    return {k: context_data[k] for k in CONTEXT_KEYS if k in context_data}


def snapshot_from_parse(parse: ParseResult, filename: str, context_data: dict | None) -> dict[str, Any]:
    packages = []
    for pp in parse.packages.values():
        packages.append({
            "purl": pp.purl,
            "name": pp.name,
            "version": pp.version,
            "depth": pp.depth,
            "dev": pp.dev,
            "optional": pp.optional,
            "peer": pp.peer,
            "has_install_script": pp.has_install_script,
            "is_git_or_file": pp.is_git_or_file,
            "is_workspace_link": pp.is_workspace_link,
            "license": pp.license,
            "resolved_url": pp.resolved_url if pp.is_git_or_file else None,
            "edges": dict(getattr(pp, "resolved_edges", {}) or {}),
        })
    return {
        "snapshot_version": SNAPSHOT_VERSION,
        "kind": "npm-lockfile",
        "filename": filename,
        "context": clean_context(context_data),
        "lockfile_version": parse.lockfile_version,
        "name": parse.name,
        "root_version": parse.root_version,
        "root_purl": parse.root_purl,
        "warnings": list(parse.warnings),
        "packages": packages,
    }


def parse_from_snapshot(snapshot: dict[str, Any]) -> ParseResult:
    if snapshot.get("kind") != "npm-lockfile" or snapshot.get("snapshot_version") != SNAPSHOT_VERSION:
        raise ValueError("Unsupported dependency snapshot")
    packages: dict[str, ParsedPackage] = {}
    for p in snapshot["packages"]:
        pp = ParsedPackage(
            name=p["name"],
            version=p["version"],
            purl=p["purl"],
            resolved_url=p.get("resolved_url"),
            integrity=None,
            dev=bool(p["dev"]),
            optional=bool(p["optional"]),
            peer=bool(p.get("peer", False)),
            has_install_script=bool(p["has_install_script"]),
            license=p.get("license"),
            dependencies={},
            dev_dependencies={},
            optional_dependencies={},
            peer_dependencies={},
            depth=int(p["depth"]),
            key="",
            is_git_or_file=bool(p["is_git_or_file"]),
            is_workspace_link=bool(p.get("is_workspace_link", False)),
        )
        # Same attribute the lockfile parser sets for the graph builder.
        pp.__dict__["resolved_edges"] = dict(p.get("edges") or {})
        packages[pp.purl] = pp
    return ParseResult(
        lockfile_version=int(snapshot["lockfile_version"]),
        name=snapshot["name"],
        root_version=snapshot["root_version"],
        packages=packages,
        root_purl=snapshot["root_purl"],
        warnings=list(snapshot.get("warnings") or []),
    )
