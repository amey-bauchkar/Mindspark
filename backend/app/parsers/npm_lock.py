"""
npm package-lock.json parser (lockfileVersion 1, 2, and 3).

Key algorithm: nearest-ancestor node_modules resolution.
The "packages" map uses keys like:
  ""                                      → root
  "node_modules/a"                        → top-level package a
  "node_modules/@scope/pkg"               → top-level scoped package
  "node_modules/a/node_modules/b"         → nested b under a
  "node_modules/a/node_modules/@scope/c"  → nested scoped package under a

For lockfileVersion 1, the nested "dependencies" tree is converted to the standard
node_modules ancestor map representation to ensure identical, deterministic graph
reconstruction across all schema versions.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SUPPORTED_VERSIONS = {1, 2, 3}
MAX_PACKAGES = 10_000
MAX_FILE_BYTES = 10 * 1024 * 1024  # 10 MB

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
    """Encode scoped and unscoped package names to standard Package URL (purl)."""
    encoded = name.replace("@", "%40").replace("/", "%2F")
    return f"pkg:npm/{encoded}@{version}"


def _package_name_from_key(key: str) -> str:
    """
    Extract the npm package name from a packages-map key.
    Examples:
      "node_modules/express"                         → "express"
      "node_modules/a/node_modules/b"                → "b"
      "node_modules/@scope/pkg"                      → "@scope/pkg"
      "node_modules/a/node_modules/@scope/pkg"       → "@scope/pkg"
      "packages/my-pkg"                              → "my-pkg"
    """
    if not key:
        return ""
    parts = key.split("/node_modules/")
    last = parts[-1]
    if last.startswith("node_modules/"):
        last = last[len("node_modules/"):]
    if "/" in last and not last.startswith("@"):
        last = last.split("/")[-1]
    return last.strip()


def _depth_from_key(key: str) -> int:
    """
    Compute dependency tree depth from package-lock key.
    - "" -> 0 (root)
    - "node_modules/axios" -> 1 (direct child of __root__)
    - "node_modules/@scope/pkg" -> 1 (direct child of __root__)
    - "node_modules/a/node_modules/b" -> 2 (transitive)
    - "node_modules/a/node_modules/@scope/b" -> 2 (transitive)
    - "node_modules/a/node_modules/b/node_modules/c" -> 3 (transitive)
    """
    if not key:
        return 0
    normalized = key if key.startswith("/") else f"/{key}"
    count = normalized.count("/node_modules/")
    if count == 0 and key.startswith("node_modules/"):
        return 1
    return max(count, 1) if ("node_modules" in key) else 0


def _resolve_nearest_ancestor(key: str, dep_name: str, packages_raw: dict) -> str | None:
    """
    Node's nearest-ancestor resolution algorithm:
    Walk up the key path looking for node_modules/<dep_name>.
    Return the resolved version string or None.
    """
    if not isinstance(packages_raw, dict):
        return None

    parts = key.split("/node_modules/")
    # Try from longest ancestor chain down to top-level
    for i in range(len(parts) - 1, -1, -1):
        candidate_prefix = "/node_modules/".join(parts[:i])
        if candidate_prefix:
            candidate_key = f"{candidate_prefix}/node_modules/{dep_name}"
        else:
            candidate_key = f"node_modules/{dep_name}"

        if candidate_key in packages_raw:
            entry = packages_raw[candidate_key]
            if isinstance(entry, dict) and entry.get("version"):
                return str(entry.get("version"))

    # Fallback to top-level lookup
    top_key = f"node_modules/{dep_name}"
    if top_key in packages_raw and isinstance(packages_raw[top_key], dict):
        ver = packages_raw[top_key].get("version")
        if ver:
            return str(ver)

    return None


def _clean_deps_map(raw_val: Any) -> dict[str, str]:
    """Ensure dependency dictionaries are clean string -> string mappings."""
    if not isinstance(raw_val, dict):
        return {}
    return {str(k): str(v) for k, v in raw_val.items() if k}


def _convert_v1_dependencies(
    deps_dict: dict,
    prefix: str,
    packages_out: dict[str, dict],
    warnings: list[str],
    visited: set[str] | None = None,
) -> None:
    """
    Recursively convert a lockfileVersion 1 nested 'dependencies' tree
    into flat/nested packages_raw mapping with 'node_modules/...' keys.
    """
    if not isinstance(deps_dict, dict):
        return
    if visited is None:
        visited = set()

    for name, info in deps_dict.items():
        if not isinstance(info, dict):
            continue

        key = f"{prefix}/node_modules/{name}" if prefix else f"node_modules/{name}"
        if key in visited:
            continue
        visited.add(key)

        # In v1, 'requires' specifies child dependency requirements
        requires = info.get("requires", {})
        if not isinstance(requires, dict):
            requires = {}

        raw_ver = info.get("version")
        version = str(raw_ver).strip() if raw_ver is not None else "0.0.0"

        pkg_entry = {
            "name": name,
            "version": version,
            "resolved": info.get("resolved"),
            "integrity": info.get("integrity"),
            "dev": bool(info.get("dev", False)),
            "optional": bool(info.get("optional", False)),
            "dependencies": requires,
            "license": info.get("license"),
        }
        packages_out[key] = pkg_entry

        # Recurse for nested dependencies if present
        nested = info.get("dependencies")
        if isinstance(nested, dict) and nested:
            _convert_v1_dependencies(nested, key, packages_out, warnings, visited)


def parse_npm_lock(content: str) -> ParseResult:
    """
    Parse a package-lock.json string (versions 1, 2, and 3) and return a standardized ParseResult.
    Handles scoped packages, workspaces, edge reconstruction, and fault-tolerant fallbacks.
    """
    if len(content) > MAX_FILE_BYTES:
        raise ValueError(f"Lockfile too large (>{MAX_FILE_BYTES // 1024 // 1024} MB)")

    try:
        data: dict = json.loads(content)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON: {e}") from e

    if not isinstance(data, dict):
        raise ValueError("Lockfile must be a JSON object")

    warnings: list[str] = []
    errors: list[str] = []

    # Determine lockfile version
    lv = data.get("lockfileVersion")
    if lv is None:
        if "packages" in data and isinstance(data["packages"], dict):
            lv = 3
        elif "dependencies" in data and isinstance(data["dependencies"], dict):
            lv = 1
        else:
            lv = 1
            warnings.append("Missing lockfileVersion; defaulting parser to version 1 schema.")
    else:
        try:
            lv = int(lv)
        except (ValueError, TypeError):
            warnings.append(f"Unrecognized lockfileVersion format {lv!r}; defaulting to version 3.")
            lv = 3

    if lv not in SUPPORTED_VERSIONS:
        raise ValueError(
            f"Unsupported lockfileVersion {lv!r}. "
            f"Warrant supports versions {sorted(SUPPORTED_VERSIONS)}."
        )

    # Build packages_raw dictionary
    packages_raw: dict[str, dict] = {}

    if lv in (2, 3) and "packages" in data and isinstance(data["packages"], dict):
        packages_raw = data["packages"]
    elif "dependencies" in data and isinstance(data["dependencies"], dict):
        # Convert v1 schema (or v2 without packages block)
        root_name = str(data.get("name") or "unknown")
        root_version = str(data.get("version") or "0.0.0")
        packages_raw[""] = {
            "name": root_name,
            "version": root_version,
            "dependencies": _clean_deps_map(data.get("dependencies")),
            "devDependencies": _clean_deps_map(data.get("devDependencies")),
        }
        _convert_v1_dependencies(data["dependencies"], "", packages_raw, warnings)
    elif "packages" in data and isinstance(data["packages"], dict):
        packages_raw = data["packages"]
    else:
        warnings.append("No package manifests ('packages' or 'dependencies') found in lockfile.")

    root_entry = packages_raw.get("", {}) if isinstance(packages_raw.get(""), dict) else {}
    root_name = str(data.get("name") or root_entry.get("name") or "unknown")
    root_version = str(data.get("version") or root_entry.get("version") or "0.0.0")
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
        is_workspace = bool(pkg_data.get("link") or pkg_data.get("workspaces"))
        if is_workspace:
            warnings.append(f"Workspace link noted: {key!r}")

        name = str(pkg_data.get("name") or _package_name_from_key(key))
        raw_version = pkg_data.get("version")
        version = str(raw_version).strip() if raw_version is not None else ""
        if not version:
            version = "0.0.0"
            warnings.append(f"No version declared for {key!r}; defaulted to '0.0.0'")

        resolved_url = str(pkg_data.get("resolved")) if pkg_data.get("resolved") else None
        is_git_or_file = bool(resolved_url and GIT_OR_FILE_PATTERNS.match(resolved_url))

        purl = _make_purl(name, version)
        depth = _depth_from_key(key)

        pp = ParsedPackage(
            name=name,
            version=version,
            purl=purl,
            resolved_url=resolved_url,
            integrity=str(pkg_data.get("integrity")) if pkg_data.get("integrity") else None,
            dev=bool(pkg_data.get("dev", False)),
            optional=bool(pkg_data.get("optional", False)),
            peer=bool(pkg_data.get("peer", False)),
            has_install_script=bool(pkg_data.get("hasInstallScript", False)),
            license=str(pkg_data.get("license")) if pkg_data.get("license") else None,
            dependencies=_clean_deps_map(pkg_data.get("dependencies")),
            dev_dependencies=_clean_deps_map(pkg_data.get("devDependencies")),
            optional_dependencies=_clean_deps_map(pkg_data.get("optionalDependencies")),
            peer_dependencies=_clean_deps_map(pkg_data.get("peerDependencies")),
            depth=depth,
            key=key,
            is_git_or_file=is_git_or_file,
            is_workspace_link=is_workspace,
        )

        # Prefer the first purl or lowest depth for a given (name, version) pair
        if purl not in parsed:
            parsed[purl] = pp
            name_version_to_purl[(name, version)] = purl
        elif depth < parsed[purl].depth:
            parsed[purl].depth = depth

    # Second pass: resolve dependencies to build edge map
    for key, pkg_data in packages_raw.items():
        if not isinstance(pkg_data, dict):
            continue

        name = str(pkg_data.get("name") or _package_name_from_key(key))
        raw_ver = pkg_data.get("version")
        version = str(raw_ver).strip() if raw_ver is not None else "0.0.0"
        src_purl = _make_purl(name, version)

        if src_purl not in parsed and key != "":
            continue

        all_deps = {
            **_clean_deps_map(pkg_data.get("dependencies")),
            **_clean_deps_map(pkg_data.get("devDependencies")),
            **_clean_deps_map(pkg_data.get("optionalDependencies")),
            **_clean_deps_map(pkg_data.get("peerDependencies")),
        }

        resolved_edges: dict[str, str] = {}
        for dep_name in all_deps:
            resolved_version = _resolve_nearest_ancestor(key, dep_name, packages_raw)
            if resolved_version:
                dep_purl = _make_purl(dep_name, resolved_version)
                resolved_edges[dep_name] = dep_purl

        if src_purl in parsed:
            # Store resolved edges in the package object for graph builder
            parsed[src_purl].__dict__["resolved_edges"] = resolved_edges

    if not parsed:
        warnings.append("No packages found in this lockfile.")

    return ParseResult(
        lockfile_version=lv,
        name=root_name,
        root_version=root_version,
        packages=parsed,
        root_purl=root_purl,
        warnings=warnings,
        errors=errors,
    )
