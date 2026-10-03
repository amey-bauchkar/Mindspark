"""
Graph builder — converts ParseResult into a networkx DiGraph with:
- Proper scope propagation (prod wins over dev)
- Cycle detection and guard
- Bounded DFS path enumeration
- Blast radius (reverse traversal)
"""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Generator

import networkx as nx

from ..parsers.npm_lock import ParseResult, ParsedPackage

MAX_PATHS_PER_NODE = 10   # cap for display
MAX_PATH_DEPTH = 50       # DFS depth limit

ROOT_ID = "__root__"


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
    introduced_by: list[str]   # direct dependency names that pull this in


@dataclass
class BuildResult:
    graph: nx.DiGraph
    packages: dict[str, GraphPackage]   # purl → GraphPackage
    root_purl: str
    root_name: str
    warnings: list[str] = field(default_factory=list)
    cycles_detected: bool = False


def build_graph(parse: ParseResult) -> BuildResult:
    G = nx.DiGraph()
    packages: dict[str, GraphPackage] = {}
    warnings = list(parse.warnings)
    cycles_detected = False

    G.add_node(ROOT_ID, label=parse.name, is_root=True)

    # Build node set
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

    # Add edges from ROOT to direct deps
    root_entry = {}
    root_deps = {}
    for dep_name, req in parse.packages.items():
        pass  # Just iterate, handled below

    # Build edges using resolved_edges stored by parser
    for purl, pp in parse.packages.items():
        resolved_edges: dict[str, str] = getattr(pp, "resolved_edges", {}) or pp.__dict__.get("resolved_edges", {})

        if pp.depth == 1:
            # Direct dependency → connect from root
            G.add_edge(ROOT_ID, purl, requirement=None, scope=packages[purl].scope)

        for dep_name, dep_purl in resolved_edges.items():
            if dep_purl in packages:
                G.add_edge(purl, dep_purl, requirement=dep_name, scope=packages[dep_purl].scope)
            # else: dependency not in lockfile (optional/peer missing)

    # Cycle detection and breaking
    try:
        cycles = list(nx.simple_cycles(G))
        if cycles:
            cycles_detected = True
            warnings.append(f"Dependency cycles detected (likely peer deps): {len(cycles)} cycles. Breaking by removing back edges.")
            for cycle in cycles:
                # Remove the last edge in each cycle to break it
                if len(cycle) >= 2:
                    G.remove_edge(cycle[-1], cycle[0])
    except Exception:
        pass

    # Scope propagation: a node is "prod" if ANY root→node path uses only non-dev, non-optional edges
    _propagate_scope(G, packages)

    # introduced_by: nearest direct ancestors
    for purl, gp in packages.items():
        if gp.is_direct:
            gp.introduced_by = [ROOT_ID]
        else:
            predecessors = list(G.predecessors(purl))
            direct_preds = [p for p in predecessors if p != ROOT_ID and packages.get(p, None) and packages[p].is_direct]
            gp.introduced_by = direct_preds if direct_preds else predecessors[:3]

    return BuildResult(
        graph=G,
        packages=packages,
        root_purl=parse.root_purl,
        root_name=parse.name,
        warnings=warnings,
        cycles_detected=cycles_detected,
    )


def _initial_scope(pp: ParsedPackage) -> str:
    if pp.optional:
        return "optional"
    if pp.dev:
        return "dev"
    return "prod"


def _propagate_scope(G: nx.DiGraph, packages: dict[str, GraphPackage]) -> None:
    """
    BFS from root; a node is prod if reachable via at least one prod path.
    More conservative scope wins (prod > dev/optional).
    """
    scope_map: dict[str, str] = {ROOT_ID: "prod"}
    queue = deque([ROOT_ID])
    visited = {ROOT_ID}

    while queue:
        node = queue.popleft()
        parent_scope = scope_map.get(node, "dev")

        for child in G.successors(node):
            child_pkg = packages.get(child)
            if child_pkg is None:
                continue
            child_own_scope = child_pkg.scope
            # If parent is prod and child's own scope isn't optional or dev-forced,
            # it may be prod. If the child declares itself dev but a prod parent uses it, it's still prod.
            effective_scope = _merge_scope(parent_scope, child_own_scope)

            existing = scope_map.get(child, "dev")
            better = _better_scope(existing, effective_scope)
            if better != existing:
                scope_map[child] = better
                child_pkg.scope = better
                child_pkg.scope_provenance = f"propagated from {node}"

            if child not in visited:
                visited.add(child)
                queue.append(child)

    # Apply final scopes
    for purl, scope in scope_map.items():
        if purl in packages:
            packages[purl].scope = scope


def _merge_scope(parent: str, child_own: str) -> str:
    """If parent is prod, child is prod too (unless child is explicitly optional)."""
    if parent == "prod" and child_own != "optional":
        return "prod"
    return child_own


def _better_scope(a: str, b: str) -> str:
    """prod > dev > optional (most conservative wins)."""
    order = {"prod": 0, "dev": 1, "optional": 2}
    return a if order.get(a, 2) <= order.get(b, 2) else b


def find_paths(G: nx.DiGraph, root: str, target: str, max_paths: int = MAX_PATHS_PER_NODE) -> list[list[str]]:
    """Find up to max_paths paths from root to target using bounded DFS."""
    paths: list[list[str]] = []

    def dfs(current: str, path: list[str], visited: set[str]) -> None:
        if len(paths) >= max_paths:
            return
        if len(path) > MAX_PATH_DEPTH:
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


def blast_radius(G: nx.DiGraph, node: str, packages: dict[str, GraphPackage]) -> dict:
    """List all nodes that depend on `node` (reverse traversal)."""
    dependents = list(nx.ancestors(G.reverse(copy=False), node)) if node in G else []
    direct_dependents = list(G.predecessors(node))
    return {
        "direct_dependents": [d for d in direct_dependents if d != ROOT_ID],
        "all_dependents": [d for d in dependents if d != ROOT_ID],
        "count": len(dependents),
    }
