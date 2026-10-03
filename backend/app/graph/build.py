"""
Graph builder — converts ParseResult into a high-performance networkx DiGraph with:
- Strict, conservative scope propagation (prod > dev > optional)
- Ultra-fast O(V + E) cycle detection and breaking
- Bounded DFS and shortest-path path enumeration
- Fast memoized blast radius (reverse dependency traversal)
- Enriched node metadata for Cytoscape / Attack Path Visualizer
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any

import networkx as nx

from ..parsers.npm_lock import ParseResult, ParsedPackage

MAX_PATHS_PER_NODE = 10   # cap for display
MAX_PATH_DEPTH = 50       # DFS depth limit

ROOT_ID = "__root__"

SCOPE_PRIORITY = {"prod": 0, "dev": 1, "optional": 2}


@dataclass
class GraphPackage:
    purl: str
    name: str
    version: str
    scope: str          # "prod" | "dev" | "optional"
    scope_provenance: str
    depth: int
    is_direct: bool
    has_install_script: bool
    is_git_or_file: bool
    license: str | None
    resolved_url: str | None
    introduced_by: list[str] = field(default_factory=list)   # direct dependency names that pull this in
    direct_dependents_count: int = 0
    total_dependents_count: int = 0


@dataclass
class BuildResult:
    graph: nx.DiGraph
    packages: dict[str, GraphPackage]   # purl → GraphPackage
    root_purl: str
    root_name: str
    warnings: list[str] = field(default_factory=list)
    cycles_detected: bool = False
    _blast_cache: dict[str, dict] = field(default_factory=dict, repr=False)


def _initial_scope(pp: ParsedPackage) -> str:
    if pp.optional:
        return "optional"
    if pp.dev:
        return "dev"
    return "prod"


def _merge_scope(parent: str, child_own: str) -> str:
    """If parent is dev/optional, child cannot be higher than parent scope."""
    if parent == "optional" or child_own == "optional":
        return "optional"
    if parent == "dev":
        return "dev"
    return child_own


def _better_scope(a: str, b: str) -> str:
    """prod > dev > optional (most conservative wins)."""
    return a if SCOPE_PRIORITY.get(a, 2) <= SCOPE_PRIORITY.get(b, 2) else b


def _break_cycles_fast(G: nx.DiGraph, max_iterations: int = 500) -> tuple[bool, list[str]]:
    """
    Break cycles in G in O(k * (V + E)) time by finding back-edges iteratively.
    Much faster than exponential simple_cycles enumeration on large or dense graphs.
    """
    cycles_detected = False
    warnings = []
    cycle_count = 0

    while cycle_count < max_iterations:
        try:
            cycle = nx.find_cycle(G, orientation="original")
            cycles_detected = True
            cycle_count += 1
            # Remove the last edge in the cycle (u -> v) to break it
            edge = cycle[-1]
            u, v = edge[0], edge[1]
            G.remove_edge(u, v)
        except nx.NetworkXNoCycle:
            break

    if cycles_detected:
        warnings.append(
            f"Dependency cycles detected: {cycle_count} cycle(s) broken by removing feedback edges."
        )

    return cycles_detected, warnings


def _propagate_scope(G: nx.DiGraph, packages: dict[str, GraphPackage]) -> None:
    """
    BFS from root; a node is prod if reachable via at least one prod path.
    More conservative scope wins (prod > dev > optional).
    """
    scope_map: dict[str, str] = {ROOT_ID: "prod"}
    queue = deque([ROOT_ID])

    while queue:
        node = queue.popleft()
        parent_scope = scope_map.get(node, "dev")

        for child in G.successors(node):
            child_pkg = packages.get(child)
            if child_pkg is None:
                continue

            child_own_scope = child_pkg.scope
            if node == ROOT_ID:
                effective_scope = child_own_scope
            else:
                effective_scope = _merge_scope(parent_scope, child_own_scope)

            current_scope = scope_map.get(child)
            if current_scope is None:
                scope_map[child] = effective_scope
                child_pkg.scope = effective_scope
                if node != ROOT_ID:
                    child_pkg.scope_provenance = f"propagated from {node}"
                if G.has_edge(node, child):
                    G.edges[node, child]["scope"] = effective_scope
                queue.append(child)
            else:
                better = _better_scope(current_scope, effective_scope)
                if better != current_scope:
                    scope_map[child] = better
                    child_pkg.scope = better
                    if node != ROOT_ID:
                        child_pkg.scope_provenance = f"propagated from {node}"
                    if G.has_edge(node, child):
                        G.edges[node, child]["scope"] = better
                    queue.append(child)
                else:
                    if G.has_edge(node, child) and "scope" not in G.edges[node, child]:
                        G.edges[node, child]["scope"] = effective_scope

    # Apply final scopes
    for purl, scope in scope_map.items():
        if purl in packages:
            packages[purl].scope = scope


def build_graph(parse: ParseResult) -> BuildResult:
    """
    Build a NetworkX DiGraph from ParseResult with scope propagation, cycle guard,
    and pre-computed dependent statistics.
    """
    G = nx.DiGraph()
    packages: dict[str, GraphPackage] = {}
    warnings = list(parse.warnings)

    G.add_node(ROOT_ID, label=parse.name, is_root=True)

    # 1. Build node set
    for purl, pp in parse.packages.items():
        scope = _initial_scope(pp)
        gp = GraphPackage(
            purl=purl,
            name=pp.name,
            version=pp.version,
            scope=scope,
            scope_provenance="lockfile-flags",
            depth=pp.depth,
            is_direct=(pp.depth == 1),
            has_install_script=pp.has_install_script,
            is_git_or_file=pp.is_git_or_file,
            license=pp.license,
            resolved_url=pp.resolved_url,
            introduced_by=[],
        )
        packages[purl] = gp
        G.add_node(purl, **gp.__dict__)

    # 2. Build edges using resolved_edges
    for purl, pp in parse.packages.items():
        resolved_edges: dict[str, str] = getattr(pp, "resolved_edges", {}) or pp.__dict__.get("resolved_edges", {})

        if pp.depth == 1:
            # Direct dependency → connect from root
            G.add_edge(ROOT_ID, purl, requirement=None, scope=packages[purl].scope)

        for dep_name, dep_purl in resolved_edges.items():
            if dep_purl in packages:
                G.add_edge(purl, dep_purl, requirement=dep_name, scope=packages[dep_purl].scope)

    # 3. High-performance cycle detection and breaking (O(k * (V + E)))
    cycles_detected, cycle_warnings = _break_cycles_fast(G)
    warnings.extend(cycle_warnings)

    # 4. Scope propagation (prod > dev > optional)
    _propagate_scope(G, packages)

    # 5. Populate dependent statistics and introduced_by
    for purl, gp in packages.items():
        if gp.is_direct:
            gp.introduced_by = [ROOT_ID]
        else:
            predecessors = list(G.predecessors(purl))
            direct_preds = [
                p for p in predecessors
                if p != ROOT_ID and p in packages and packages[p].is_direct
            ]
            gp.introduced_by = direct_preds if direct_preds else [p for p in predecessors if p != ROOT_ID][:3]

        gp.direct_dependents_count = len([p for p in G.predecessors(purl) if p != ROOT_ID])

    return BuildResult(
        graph=G,
        packages=packages,
        root_purl=parse.root_purl,
        root_name=parse.name,
        warnings=warnings,
        cycles_detected=cycles_detected,
    )


def find_paths(
    G: nx.DiGraph,
    root: str,
    target: str,
    max_paths: int = MAX_PATHS_PER_NODE,
    cutoff: int = MAX_PATH_DEPTH,
) -> list[list[str]]:
    """
    Find up to max_paths paths from root to target.
    Validates reachability in O(V + E) first to avoid wasted search.
    """
    if target not in G or root not in G:
        return []
    if root == target:
        return [[root]]

    if not nx.has_path(G, root, target):
        return []

    paths: list[list[str]] = []
    try:
        path_gen = nx.all_simple_paths(G, source=root, target=target, cutoff=cutoff)
        for p in path_gen:
            paths.append(p)
            if len(paths) >= max_paths:
                break
    except Exception:
        # Fallback bounded DFS
        def dfs(current: str, path: list[str], visited: set[str]) -> None:
            if len(paths) >= max_paths or len(path) > cutoff:
                return
            if current == target:
                paths.append(list(path))
                return
            for neighbor in G.successors(current):
                if neighbor not in visited:
                    visited.add(neighbor)
                    path.append(neighbor)
                    dfs(neighbor, path, visited)
                    path.pop()
                    visited.discard(neighbor)

        dfs(root, [root], {root})

    return paths


def blast_radius(
    G: nx.DiGraph,
    node: str,
    packages: dict[str, GraphPackage] | None = None,
    cache: dict[str, dict] | None = None,
) -> dict:
    """
    List all dependent packages that rely on `node` (reverse traversal).
    In graph G (edges caller -> dependency), dependents that rely on `node`
    are the ancestors of `node` in G (excluding ROOT_ID).
    Utilizes caching for O(1) repeated lookups.
    """
    if cache is not None and node in cache:
        return cache[node]

    if node not in G:
        res = {
            "direct_dependents": [],
            "all_dependents": [],
            "count": 0,
        }
        if cache is not None:
            cache[node] = res
        return res

    direct_dependents = [d for d in G.predecessors(node) if d != ROOT_ID]
    dependents = [d for d in nx.ancestors(G, node) if d != ROOT_ID]
    
    res = {
        "direct_dependents": direct_dependents,
        "all_dependents": dependents,
        "count": len(dependents),
    }
    if cache is not None:
        cache[node] = res
    return res
