"""
npm package-lock.json parser (lockfileVersion 2 and 3).

Key algorithm: nearest-ancestor node_modules resolution.
The "packages" map uses keys like:
  ""                       → root
  "node_modules/a"         → top-level package a
  "node_modules/a/node_modules/b"  → nested b under a
For each package's dependency on X, find the nearest ancestor key that
provides X by walking up the key path.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SUPPORTED_VERSIONS = {2, 3}
MAX_PACKAGES = 5_000
MAX_FILE_BYTES = 5 * 1024 * 1024  # 5 MB

GIT_OR_FILE_PATTERNS = re.compile(
    r'^(git\+|git://|github:|bitbucket:|gitlab:|file:|'
    r'http://(?!registry\.npmjs\.org)|'
    r'https://(?!registry\.npmjs\.org))',
    re.IGNORECASE,
)


@dataclass
class ParsedPackage:
    name: str
    version: str
    purl: str                           # pkg:npm/name@version
    resolved_url: str | None
    integrity: str | None
    dev: bool
    optional: bool
    peer: bool
    has_install_script: bool
    license: str | None
    dependencies: dict[str, str]        # name → version requirement
    dev_dependencies: dict[str, str]
    optional_dependencies: dict[str, str]
    peer_dependencies: dict[str, str]
    depth: int
    key: str                            # original packages map key
    is_git_or_file: bool = False
    is_workspace_link: bool = False
    introduced_by: list[str] = field(default_factory=list)  # filled by graph builder


@dataclass
class ParseResult:
    lockfile_version: int
    name: str                           # root package name
    root_version: str
    packages: dict[str, ParsedPackage]  # purl → package
    root_purl: str
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _make_purl(name: str, version: str) -> str:
    # Encode scoped names: @scope/pkg → pkg:npm/%40scope%2Fpkg@version
    encoded = name.replace("@", "%40").replace("/", "%2F")
    return f"pkg:npm/{encoded}@{version}"


def _package_name_from_key(key: str) -> str:
    """
    Extract the npm package name from a packages-map key.
    Examples:
      "node_modules/express"               → "express"
      "node_modules/a/node_modules/b"      → "b"
      "node_modules/@scope/pkg"            → "@scope/pkg"
      "node_modules/a/node_modules/@s/p"   → "@s/p"
    """
    # Split on /node_modules/ to get the last segment
    parts = key.split("/node_modules/")
    last = parts[-1]  # e.g. "express" or "@scope/pkg"
    # Strip any leading "node_modules/" if the key itself starts with it (depth-0 key)
    if last.startswith("node_modules/"):
        last = last[len("node_modules/"):]
    return last


def _depth_from_key(key: str) -> int:
    return key.count("/node_modules/")


def _resolve_nearest_ancestor(key: str, dep_name: str, packages_raw: dict) -> str | None:
    """
    Node's nearest-ancestor algorithm:
    Walk up the key path looking for node_modules/<dep_name>.
    Return the resolved version string or None.
    """
    parts = key.split("/node_modules/")
    # Try from longest ancestor chain down to top-level
    for i in range(len(parts) - 1, -1, -1):
        candidate_prefix = "/node_modules/".join(parts[:i])
        if candidate_prefix:
            candidate_key = f"{candidate_prefix}/node_modules/{dep_name}"
        else:
            candidate_key = f"node_modules/{dep_name}"
        if candidate_key in packages_raw:
            return packages_raw[candidate_key].get("version")
    return None


def parse_npm_lock(content: str) -> ParseResult:
    """Parse a package-lock.json string and return a ParseResult."""
    # Size guard (content in chars; close enough to bytes for ASCII-heavy JSON)
    if len(content) > MAX_FILE_BYTES:
        raise ValueError(f"Lockfile too large (>{MAX_FILE_BYTES // 1024 // 1024} MB)")

    try:
        data: dict = json.loads(content)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON: {e}") from e

    if not isinstance(data, dict):
        raise ValueError("Lockfile must be a JSON object")

    lv = data.get("lockfileVersion")
    if lv not in SUPPORTED_VERSIONS:
        raise ValueError(
            f"Unsupported lockfileVersion {lv!r}. "
            f"Warrant supports versions {sorted(SUPPORTED_VERSIONS)}. "
            "Run `npm install` to regenerate a v2/v3 lockfile."
        )

    packages_raw: dict[str, dict] = data.get("packages", {})
    warnings: list[str] = []

    root_entry = packages_raw.get("", {})
    root_name = data.get("name") or root_entry.get("name") or "unknown"
    root_version = data.get("version") or root_entry.get("version") or "0.0.0"
    root_purl = _make_purl(root_name, root_version)

    parsed: dict[str, ParsedPackage] = {}
    name_version_to_purl: dict[tuple[str, str], str] = {}

    # Count guard
    total_keys = len([k for k in packages_raw if k != ""])
    if total_keys > MAX_PACKAGES:
        raise ValueError(f"Lockfile contains {total_keys} packages; limit is {MAX_PACKAGES}.")

    # First pass: create ParsedPackage objects
    for key, pkg_data in packages_raw.items():
        if key == "":
            continue  # root handled separately

        if not isinstance(pkg_data, dict):
            warnings.append(f"Skipping malformed entry: {key!r}")
            continue

        # Detect workspace links
        if pkg_data.get("link"):
            warnings.append(f"Workspace link skipped: {key!r} (CANNOT ASSESS — not a registry package)")
            continue

        name = pkg_data.get("name") or _package_name_from_key(key)
        version = pkg_data.get("version", "")
        if not version:
            warnings.append(f"No version for {key!r}; skipping")
            continue

        resolved_url = pkg_data.get("resolved")
        is_git_or_file = bool(resolved_url and GIT_OR_FILE_PATTERNS.match(resolved_url))
        if not resolved_url:
            # Could be a file: or git: dep too
            pass

        purl = _make_purl(name, version)

        pp = ParsedPackage(
            name=name,
            version=version,
            purl=purl,
            resolved_url=resolved_url,
            integrity=pkg_data.get("integrity"),
            dev=bool(pkg_data.get("dev", False)),
            optional=bool(pkg_data.get("optional", False)),
            peer=bool(pkg_data.get("peer", False)),
            has_install_script=bool(pkg_data.get("hasInstallScript", False)),
            license=pkg_data.get("license"),
            dependencies=pkg_data.get("dependencies", {}),
            dev_dependencies=pkg_data.get("devDependencies", {}),
            optional_dependencies=pkg_data.get("optionalDependencies", {}),
            peer_dependencies=pkg_data.get("peerDependencies", {}),
            depth=_depth_from_key(key),
            key=key,
            is_git_or_file=is_git_or_file,
        )
        # Prefer the first purl we see for a given (name, version) pair
        if purl not in parsed:
            parsed[purl] = pp
            name_version_to_purl.setdefault((name, version), purl)

    # Second pass: resolve dependencies to build edge map
    # We need a key→purl map for the ancestor-resolution algorithm
    key_to_purl: dict[str, str] = {}
    for key, pkg_data in packages_raw.items():
        if key == "":
            continue
        if pkg_data.get("link"):
            continue
        name = pkg_data.get("name") or _package_name_from_key(key)
        version = pkg_data.get("version", "")
        if version:
            key_to_purl[key] = _make_purl(name, version)

    # Build resolved dependency edges: for each package, resolve its deps
    for key, pkg_data in packages_raw.items():
        if pkg_data.get("link"):
            continue
        name = pkg_data.get("name") or _package_name_from_key(key)
        version = pkg_data.get("version", "")
        if not version:
            continue
        src_purl = _make_purl(name, version)
        if src_purl not in parsed:
            continue

        all_deps = {
            **pkg_data.get("dependencies", {}),
            **pkg_data.get("devDependencies", {}),
            **pkg_data.get("optionalDependencies", {}),
            **pkg_data.get("peerDependencies", {}),
        }
        # Store resolved edges in the package object as a "resolved_edges" data field
        # We'll use this in graph/build.py
        resolved_edges: dict[str, str] = {}  # dep_name → dep_purl
        for dep_name in all_deps:
            resolved_version = _resolve_nearest_ancestor(key, dep_name, packages_raw)
            if resolved_version:
                dep_purl = _make_purl(dep_name, resolved_version)
                resolved_edges[dep_name] = dep_purl
        # Attach to package
        parsed[src_purl].__dict__.setdefault("resolved_edges", resolved_edges)

    if not parsed:
        warnings.append("No packages found in this lockfile.")

    return ParseResult(
        lockfile_version=lv,
        name=root_name,
        root_version=root_version,
        packages=parsed,
        root_purl=root_purl,
        warnings=warnings,
        errors=[],
    )
