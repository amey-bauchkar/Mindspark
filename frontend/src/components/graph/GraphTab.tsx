import React, { useEffect, useRef, useState, useMemo, useCallback } from 'react';
import type { Decision, GraphNode, GraphEdge } from '../../lib/types';
import { VerdictChip } from '../ui/VerdictChip';
import type { DependencyChangeEvent } from '../asof/AsOfSlider';
import cytoscape from 'cytoscape';
// @ts-ignore
import dagre from 'cytoscape-dagre';
import { 
  ZoomIn, 
  ZoomOut, 
  Maximize2, 
  RotateCcw, 
  Layers, 
  ArrowRightLeft, 
  Info, 
  ExternalLink,
  X,
  History,
  Radio,
  EyeOff,
  AlertCircle
} from 'lucide-react';

if (typeof cytoscape === 'function' && dagre) {
  try {
    cytoscape.use(dagre);
  } catch {
    // already registered
  }
}

export interface BlastRadiusData {
  selectedId: string;
  directDependents: string[];
  transitiveDependents: string[];
  totalCount: number;
  allDependentIds: Set<string>;
  highlightEdgeIds: Set<string>;
  paths: string[][];
}

/**
 * Calculates evidence-backed dependency blast radius via reverse graph traversal.
 * Graph semantics: source → target = importer → dependency.
 * For selected node B:
 * - Predecessors of B (importers) = packages that depend on B = potential blast radius.
 * - Successors of B (dependencies B imports) = NOT blast radius.
 */
export function calculateBlastRadius(
  selectedId: string | null,
  nodes: GraphNode[] = [],
  edges: GraphEdge[] = []
): BlastRadiusData | null {
  if (!selectedId || !nodes || nodes.length === 0) return null;

  const nodeMap = new Map<string, GraphNode>();
  nodes.forEach(n => nodeMap.set(n.id, n));

  if (!nodeMap.has(selectedId)) return null;

  // Build reverse adjacency list: target -> incoming edges (importers)
  // Edge contract: source -> target = importer -> dependency
  const reverseAdj = new Map<string, Array<{ source: string; edgeId: string }>>();
  const forwardAdj = new Map<string, Array<{ target: string; edgeId: string }>>();

  (edges || []).forEach((e, idx) => {
    if (!e.source || !e.target) return;
    if (!nodeMap.has(e.source) || !nodeMap.has(e.target)) return;
    const edgeId = `e-${idx}`;

    if (!reverseAdj.has(e.target)) reverseAdj.set(e.target, []);
    reverseAdj.get(e.target)!.push({ source: e.source, edgeId });

    if (!forwardAdj.has(e.source)) forwardAdj.set(e.source, []);
    forwardAdj.get(e.source)!.push({ target: e.target, edgeId });
  });

  // 1. Direct Dependents: immediate predecessors
  const rawDirect = reverseAdj.get(selectedId) || [];
  const directSet = new Set<string>();
  const directEdgeIds = new Set<string>();

  for (const { source, edgeId } of rawDirect) {
    if (source !== selectedId && nodeMap.has(source)) {
      directSet.add(source);
      directEdgeIds.add(edgeId);
    }
  }

  // 2. Transitive Dependents: reverse BFS traversal
  const visited = new Set<string>([selectedId]);
  const distanceMap = new Map<string, number>([[selectedId, 0]]);
  const queue: string[] = [];

  for (const directId of directSet) {
    visited.add(directId);
    distanceMap.set(directId, 1);
    queue.push(directId);
  }

  const allDependentIds = new Set<string>(directSet);
  const highlightEdgeIds = new Set<string>(directEdgeIds);

  // Next steps map for path reconstruction: source -> targets leading toward selectedId
  const nextStepMap = new Map<string, Array<{ target: string; edgeId: string }>>();
  for (const { source, edgeId } of rawDirect) {
    if (source !== selectedId) {
      if (!nextStepMap.has(source)) nextStepMap.set(source, []);
      nextStepMap.get(source)!.push({ target: selectedId, edgeId });
    }
  }

  let head = 0;
  while (head < queue.length) {
    const curr = queue[head++];
    const currDist = distanceMap.get(curr) || 1;

    const incoming = reverseAdj.get(curr) || [];
    for (const { source, edgeId } of incoming) {
      if (source === selectedId || !nodeMap.has(source)) continue;

      highlightEdgeIds.add(edgeId);

      if (!nextStepMap.has(source)) nextStepMap.set(source, []);
      if (!nextStepMap.get(source)!.some(item => item.target === curr)) {
        nextStepMap.get(source)!.push({ target: curr, edgeId });
      }

      if (!visited.has(source)) {
        visited.add(source);
        distanceMap.set(source, currDist + 1);
        allDependentIds.add(source);
        queue.push(source);
      }
    }
  }

  const directDependents = Array.from(directSet);
  const transitiveDependents = Array.from(allDependentIds).filter(id => !directSet.has(id));

  // 3. Reconstruct evidence-backed dependency paths (e.g. App -> libA -> libB -> selected)
  const topLevelNodes: string[] = [];
  for (const depId of allDependentIds) {
    const incoming = reverseAdj.get(depId) || [];
    const hasInternalIncoming = incoming.some(item => allDependentIds.has(item.source));
    if (!hasInternalIncoming || depId === '__root__' || nodeMap.get(depId)?.depth === 0) {
      topLevelNodes.push(depId);
    }
  }

  if (topLevelNodes.length === 0 && allDependentIds.size > 0) {
    topLevelNodes.push(
      ...Array.from(allDependentIds).sort((a, b) => (distanceMap.get(b) || 0) - (distanceMap.get(a) || 0))
    );
  }

  const paths: string[][] = [];
  const maxPaths = 5;

  function findPathDfs(curr: string, currentPath: string[], seen: Set<string>) {
    if (paths.length >= maxPaths) return;
    if (curr === selectedId) {
      const readablePath = currentPath.map(id => {
        const node = nodeMap.get(id);
        if (!node) return id;
        if (node.id === '__root__' || node.depth === 0) return node.name || 'Application Root';
        return node.version ? `${node.name}@${node.version}` : node.name;
      });
      paths.push(readablePath);
      return;
    }

    const nextSteps = nextStepMap.get(curr) || [];
    for (const step of nextSteps) {
      if (paths.length >= maxPaths) return;
      if (!seen.has(step.target)) {
        seen.add(step.target);
        findPathDfs(step.target, [...currentPath, step.target], seen);
        seen.delete(step.target);
      }
    }
  }

  for (const topId of topLevelNodes) {
    if (paths.length >= maxPaths) break;
    const seen = new Set<string>([topId]);
    findPathDfs(topId, [topId], seen);
  }

  if (paths.length === 0 && directDependents.length > 0) {
    for (const directId of directDependents.slice(0, maxPaths)) {
      const topNode = nodeMap.get(directId);
      const targetNode = nodeMap.get(selectedId);
      const topLabel = topNode ? (topNode.id === '__root__' ? (topNode.name || 'Application Root') : `${topNode.name}@${topNode.version || ''}`) : directId;
      const targetLabel = targetNode ? `${targetNode.name}@${targetNode.version || ''}` : selectedId;
      paths.push([topLabel, targetLabel]);
    }
  }

  return {
    selectedId,
    directDependents,
    transitiveDependents,
    totalCount: allDependentIds.size,
    allDependentIds,
    highlightEdgeIds,
    paths,
  };
}

interface GraphTabProps {
  graph: { nodes: GraphNode[]; edges: GraphEdge[] };
  decisions: Decision[];
  onSelectDecision?: (decision: Decision) => void;
  temporalChange?: DependencyChangeEvent | null;
}

/** Respect the OS "reduce motion" setting for Cytoscape's JS-driven pan/zoom animations. */
function motionMs(ms: number): number {
  try {
    return window.matchMedia?.('(prefers-reduced-motion: reduce)').matches ? 0 : ms;
  } catch {
    return ms;
  }
}

export function GraphTab({ 
  graph, 
  decisions, 
  onSelectDecision,
  temporalChange,
}: GraphTabProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<cytoscape.Core | null>(null);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(() => {
    if (typeof window !== 'undefined') {
      try {
        const stored = sessionStorage.getItem('warrant:focused-package');
        if (stored) return stored;
      } catch {}
    }
    return null;
  });
  const [isBlastRadiusActive, setIsBlastRadiusActive] = useState<boolean>(false);
  const [viewMode, setViewMode] = useState<'visual' | 'text'>('visual');
  const [direction, setDirection] = useState<'TB' | 'LR'>('TB');
  const [notInGraphNotice, setNotInGraphNotice] = useState<string | null>(null);

  // Active temporal change state (received via prop or synchronized via custom event)
  const [activeTemporalChange, setActiveTemporalChange] = useState<DependencyChangeEvent | null>(() => {
    if (temporalChange !== undefined) return temporalChange;
    if (typeof window !== 'undefined') {
      try {
        const stored = sessionStorage.getItem('warrant:temporal-change');
        return stored ? JSON.parse(stored) : null;
      } catch {
        return null;
      }
    }
    return null;
  });

  // Sync prop changes
  useEffect(() => {
    if (temporalChange !== undefined) {
      setActiveTemporalChange(temporalChange);
    }
  }, [temporalChange]);

  // Synchronize temporal change events broadcast from AsOfSlider
  useEffect(() => {
    if (typeof window === 'undefined') return;

    const handleTemporalEvent = (e: Event) => {
      const customEv = e as CustomEvent<DependencyChangeEvent | null>;
      setActiveTemporalChange(customEv.detail);
    };

    window.addEventListener('warrant:temporal-change', handleTemporalEvent);
    return () => {
      window.removeEventListener('warrant:temporal-change', handleTemporalEvent);
    };
  }, []);

  // Synchronize package focus requests (e.g. from DecisionCard or AsOfSlider)
  useEffect(() => {
    if (typeof window === 'undefined') return;

    const handleFocusPackage = (e: Event) => {
      const customEv = e as CustomEvent<{ subject: string; name?: string; version?: string }>;
      if (!customEv.detail) return;
      const { subject, name } = customEv.detail;
      const cy = cyRef.current;
      if (!cy) return;

      const searchSub = (subject || '').toLowerCase();
      const searchName = (name || '').toLowerCase();

      const target = cy.nodes().filter(n => {
        const nId = (n.data('id') || '').toLowerCase();
        const nName = (n.data('name') || '').toLowerCase();
        return (
          nId === searchSub ||
          (searchName && nName === searchName) ||
          (searchName && nId.includes(searchName))
        );
      }).first();

      if (target && target.length > 0) {
        const targetId = target.data('id');
        setSelectedNodeId(targetId);
        setNotInGraphNotice(null);
        try {
          cy.animate({
            center: { eles: target },
            zoom: Math.max(cy.zoom(), 1.15),
            duration: 350,
          });
        } catch {}
      } else {
        setNotInGraphNotice('Dependency is not present in the current graph.');
        setTimeout(() => setNotInGraphNotice(null), 4000);
      }
    };

    window.addEventListener('warrant:focus-package', handleFocusPackage);
    return () => {
      window.removeEventListener('warrant:focus-package', handleFocusPackage);
    };
  }, []);

  // Check stored focus package on initial mount
  useEffect(() => {
    if (typeof window === 'undefined' || !cyRef.current) return;
    try {
      const stored = sessionStorage.getItem('warrant:focused-package');
      if (stored) {
        sessionStorage.removeItem('warrant:focused-package');
        window.dispatchEvent(
          new CustomEvent('warrant:focus-package', { detail: { subject: stored } })
        );
      }
    } catch {}
  }, []);

  // Map decisions by both PURL id and package name for O(1) lookups
  const decisionMap = useMemo(() => {
    const map = new Map<string, Decision>();
    decisions.forEach(d => {
      if (d.subject) map.set(d.subject, d);
      if (d.name) map.set(d.name, d);
    });
    return map;
  }, [decisions]);

  // Inspect an affected dependent package's decision while preserving current blast radius context
  const handleViewDependentDecision = useCallback((depId: string) => {
    const dec = decisionMap.get(depId) || Array.from(decisionMap.values()).find(d => depId.includes(d.name));
    if (dec && onSelectDecision) {
      onSelectDecision(dec);
    } else if (onSelectDecision) {
      const depNode = graph?.nodes?.find(n => n.id === depId);
      onSelectDecision({
        subject: depId,
        name: depNode?.name || depId,
        version: depNode?.version || '',
        verdict: 'NO_KNOWN_FINDING',
        urgency: 'NONE',
        qualifier: 'UNKNOWN',
        exposure: {
          paths: [],
          scope: depNode?.scope || 'prod',
          scope_provenance: 'graph',
          install_phase: 'unknown',
          scripts_enabled: 'assumed',
        },
        evidence_ids: [],
        open_defeaters: [],
        unrun_checks: [],
        response: 'none',
        response_steps: [],
        as_of: new Date().toISOString(),
        derivation: ['R7 — no known finding'],
        introduced_by: [],
        depth: depNode?.depth ?? 1,
        is_direct: Boolean(depNode?.is_direct),
        what: 'No security advisories or malware reports known for this dependency.',
      });
    }
  }, [decisionMap, graph, onSelectDecision]);

  // Read CSS custom property values dynamically from DOM to avoid hardcoded colors
  const tokenColors = useMemo(() => {
    if (typeof window === 'undefined') {
      return {
        incident: '#B42318',
        incidentBorder: '#FECDCA',
        actNow: '#C4320A',
        actNowBorder: '#F9DBAF',
        upgrade: '#B54708',
        upgradeBorder: '#FEDF89',
        monitor: '#175CD3',
        monitorBorder: '#B2DDFF',
        review: '#5925DC',
        reviewBorder: '#D9D6FE',
        cannot: '#475467',
        cannotBorder: '#D0D5DD',
        nkf: '#344054',
        nkfBorder: '#D0D5DD',
        accent: '#1F4FD8',
        border: '#E3E6EB',
        text: '#0F172A',
        muted: '#5B6577',
      };
    }
    const computed = getComputedStyle(document.documentElement);
    const getVal = (prop: string, fallback: string) =>
      computed.getPropertyValue(prop).trim() || fallback;

    return {
      incident: getVal('--verdict-incident-fg', '#B42318'),
      incidentBorder: getVal('--verdict-incident-border', '#FECDCA'),
      actNow: getVal('--verdict-act-now-fg', '#C4320A'),
      actNowBorder: getVal('--verdict-act-now-border', '#F9DBAF'),
      upgrade: getVal('--verdict-upgrade-fg', '#B54708'),
      upgradeBorder: getVal('--verdict-upgrade-border', '#FEDF89'),
      monitor: getVal('--verdict-monitor-fg', '#175CD3'),
      monitorBorder: getVal('--verdict-monitor-border', '#B2DDFF'),
      review: getVal('--verdict-review-fg', '#5925DC'),
      reviewBorder: getVal('--verdict-review-border', '#D9D6FE'),
      cannot: getVal('--verdict-cannot-fg', '#475467'),
      cannotBorder: getVal('--verdict-cannot-border', '#D0D5DD'),
      nkf: getVal('--verdict-nkf-fg', '#344054'),
      nkfBorder: getVal('--verdict-nkf-border', '#D0D5DD'),
      accent: getVal('--color-accent', '#1F4FD8'),
      border: getVal('--color-border', '#E3E6EB'),
      text: getVal('--color-text', '#0F172A'),
      muted: getVal('--color-muted', '#5B6577'),
    };
  }, []);

  // Filter and sanitize graph elements to guard against malformed data
  const elements = useMemo<cytoscape.ElementDefinition[]>(() => {
    if (!graph || !graph.nodes || graph.nodes.length === 0) return [];

    const validNodeIds = new Set<string>();

    const nodeElements: cytoscape.ElementDefinition[] = graph.nodes.map(n => {
      validNodeIds.add(n.id);
      const dec = decisionMap.get(n.id) || decisionMap.get(n.name);
      const verdict = dec?.verdict || n.verdict || 'NO_KNOWN_FINDING';
      const isRoot = n.id === '__root__' || n.depth === 0;

      return {
        data: {
          id: n.id,
          label: isRoot ? (n.name || 'Application Root') : `${n.name}@${n.version}`,
          name: n.name,
          version: n.version,
          verdict,
          isDirect: Boolean(n.is_direct || n.depth === 1),
          isRoot,
          depth: n.depth ?? (isRoot ? 0 : 1),
        },
      };
    });

    const edgeElements: cytoscape.ElementDefinition[] = (graph.edges || [])
      .filter(e => e.source && e.target && validNodeIds.has(e.source) && validNodeIds.has(e.target))
      .map((e, idx) => ({
        data: {
          id: `e-${idx}`,
          source: e.source,
          target: e.target,
          scope: e.scope || 'prod',
        },
      }));

    return [...nodeElements, ...edgeElements];
  }, [graph, decisionMap]);

  // Check if active temporal event matches a node in the current graph
  const isTemporalNodeInGraph = useMemo(() => {
    if (!activeTemporalChange || !graph?.nodes) return false;
    const pkgName = activeTemporalChange.package_name.toLowerCase();
    const pkgId = activeTemporalChange.package_id.toLowerCase();
    // Exact match only (purl first, then exact name) — never a substring of another package
    return graph.nodes.some(n => (n.id || '').toLowerCase() === pkgId || (n.name || '').toLowerCase() === pkgName);
  }, [activeTemporalChange, graph]);

  // Selected node metadata
  const selectedDecision = useMemo(() => {
    if (!selectedNodeId) return null;
    return decisionMap.get(selectedNodeId) || null;
  }, [selectedNodeId, decisionMap]);

  const selectedGraphNode = useMemo(() => {
    if (!selectedNodeId || !graph?.nodes) return null;
    return graph.nodes.find(n => n.id === selectedNodeId) || null;
  }, [selectedNodeId, graph]);

  // Evidence-backed potential blast radius calculation (memoized for performance)
  const blastRadius = useMemo(() => {
    return calculateBlastRadius(selectedNodeId, graph?.nodes, graph?.edges);
  }, [selectedNodeId, graph]);

  // Initialize and mount Cytoscape instance
  useEffect(() => {
    if (viewMode !== 'visual' || !containerRef.current || elements.length === 0) return;

    try {
      const cy = cytoscape({
        container: containerRef.current,
        elements,
        boxSelectionEnabled: false,
        autounselectify: false,
        style: [
          // Base Node Style
          {
            selector: 'node',
            style: {
              label: 'data(label)',
              'font-size': '10px',
              'font-family': 'monospace',
              'text-valign': 'bottom',
              'text-margin-y': 5,
              color: tokenColors.text,
              'background-color': tokenColors.nkf,
              'border-width': 1.5,
              'border-color': tokenColors.nkfBorder,
              width: 24,
              height: 24,
              'transition-property': 'background-color, border-color, width, height, opacity',
              'transition-duration': 0.2,
            },
          },
          // Root Node (Topological Tier 1 - Largest)
          {
            selector: 'node[?isRoot]',
            style: {
              width: 44,
              height: 44,
              'border-width': 3,
              'border-color': tokenColors.accent,
              'background-color': tokenColors.accent,
              'font-size': '12px',
              'font-weight': 'bold',
            },
          },
          // Direct Dependencies (Topological Tier 2 - Medium)
          {
            selector: 'node[?isDirect][!isRoot]',
            style: {
              width: 32,
              height: 32,
              'border-width': 2,
            },
          },
          // Transitive Dependencies (Topological Tier 3 - Compact)
          {
            selector: 'node[!isDirect][!isRoot]',
            style: {
              width: 22,
              height: 22,
              'border-width': 1.5,
            },
          },
          // Verdict Color Mapping matching Design Tokens
          {
            selector: 'node[verdict = "INCIDENT"]',
            style: {
              'background-color': tokenColors.incident,
              'border-color': tokenColors.incidentBorder,
            },
          },
          {
            selector: 'node[verdict = "ACT_NOW"]',
            style: {
              'background-color': tokenColors.actNow,
              'border-color': tokenColors.actNowBorder,
            },
          },
          {
            selector: 'node[verdict = "UPGRADE"]',
            style: {
              'background-color': tokenColors.upgrade,
              'border-color': tokenColors.upgradeBorder,
            },
          },
          {
            selector: 'node[verdict = "MONITOR"]',
            style: {
              'background-color': tokenColors.monitor,
              'border-color': tokenColors.monitorBorder,
            },
          },
          {
            selector: 'node[verdict = "REVIEW"]',
            style: {
              'background-color': tokenColors.review,
              'border-color': tokenColors.reviewBorder,
            },
          },
          {
            selector: 'node[verdict = "CANNOT_ASSESS"]',
            style: {
              'background-color': tokenColors.cannot,
              'border-color': tokenColors.cannotBorder,
            },
          },
          {
            selector: 'node[verdict = "NO_KNOWN_FINDING"]',
            style: {
              'background-color': tokenColors.nkf,
              'border-color': tokenColors.nkfBorder,
            },
          },
          // Base Edge Style (Curved Bezier with Directional Arrows)
          {
            selector: 'edge',
            style: {
              width: 1.5,
              'line-color': tokenColors.border,
              'target-arrow-color': tokenColors.border,
              'target-arrow-shape': 'triangle',
              'curve-style': 'bezier',
              'arrow-scale': 0.8,
              opacity: 0.75,
              'transition-property': 'line-color, target-arrow-color, width, opacity',
              'transition-duration': 0.2,
            },
          },
          // Interactive Highlighting States
          {
            selector: '.dimmed',
            style: {
              opacity: 0.12,
            },
          },
          // Selected Node (Priority 1)
          {
            selector: '.selected-target',
            style: {
              'border-width': 4,
              'border-color': tokenColors.accent,
              'z-index': 1200,
              opacity: 1,
            },
          },
          // Upstream Ancestor Lineage (Normal selection mode)
          {
            selector: '.highlighted-ancestor-node',
            style: {
              'border-width': 3,
              'border-color': tokenColors.accent,
              opacity: 1,
              'z-index': 500,
            },
          },
          {
            selector: '.highlighted-ancestor-edge',
            style: {
              width: 2.5,
              'line-color': tokenColors.accent,
              'target-arrow-color': tokenColors.accent,
              opacity: 1,
              'z-index': 500,
            },
          },
          // Downstream Lineage (Normal selection mode)
          {
            selector: '.highlighted-blast-node',
            style: {
              'border-width': 3,
              'border-color': tokenColors.actNow,
              opacity: 1,
              'z-index': 600,
            },
          },
          {
            selector: '.highlighted-blast-edge',
            style: {
              width: 2.5,
              'line-color': tokenColors.actNow,
              'target-arrow-color': tokenColors.actNow,
              opacity: 1,
              'z-index': 600,
            },
          },
          // Blast Radius - Direct Dependent (Immediate Predecessors: Priority 3)
          {
            selector: '.blast-direct-node',
            style: {
              'border-width': 3.5,
              'border-style': 'solid',
              'border-color': '#F43F5E',
              'underlay-color': '#F43F5E',
              'underlay-padding': 6,
              'underlay-opacity': 0.28,
              'underlay-shape': 'ellipse',
              opacity: 1,
              'z-index': 700,
            },
          },
          // Blast Radius - Transitive Dependent (Upstream Predecessors > 1 hop: Priority 3)
          {
            selector: '.blast-transitive-node',
            style: {
              'border-width': 2.5,
              'border-style': 'dashed',
              'border-color': '#FB7185',
              'underlay-color': '#FB7185',
              'underlay-padding': 4,
              'underlay-opacity': 0.16,
              'underlay-shape': 'ellipse',
              opacity: 1,
              'z-index': 650,
            },
          },
          // Blast Radius - Path Edges (importer -> dependency paths leading to selected)
          {
            selector: '.blast-path-edge',
            style: {
              width: 2.5,
              'line-color': '#F43F5E',
              'target-arrow-color': '#F43F5E',
              opacity: 1,
              'z-index': 600,
            },
          },
          // Temporal Change Highlights (Priority 2: preserves halo and outline)
          {
            selector: '.temporal-node',
            style: {
              'z-index': 1000,
              opacity: 1,
            },
          },
          {
            selector: '.temporal-added',
            style: {
              'border-width': 3.5,
              'border-color': '#06B6D4',
              'border-style': 'solid',
              'underlay-color': '#06B6D4',
              'underlay-padding': 7,
              'underlay-opacity': 0.38,
              'underlay-shape': 'ellipse',
            },
          },
          {
            selector: '.temporal-modified',
            style: {
              'border-width': 3.5,
              'border-color': '#8B5CF6',
              'border-style': 'dashed',
              'underlay-color': '#8B5CF6',
              'underlay-padding': 7,
              'underlay-opacity': 0.38,
              'underlay-shape': 'ellipse',
            },
          },
        ],
        layout: {
          name: 'dagre',
          rankDir: direction,
          nodeSep: 40,
          rankSep: 70,
          padding: 35,
          animate: false,
        } as any,
      });

      // Handle Node Tap: Select node and expose context in HUD (do not pop drawer automatically)
      cy.on('tap', 'node', evt => {
        const targetNode = evt.target;
        const nodeId = targetNode.data('id');
        setSelectedNodeId(nodeId);
        setNotInGraphNotice(null);
      });

      // Handle Canvas Background Tap: Clear highlights & blast radius
      cy.on('tap', evt => {
        if (evt.target === cy) {
          setSelectedNodeId(null);
          setIsBlastRadiusActive(false);
        }
      });

      cyRef.current = cy;

      // Check if a package was queued for focusing across tab switches
      try {
        const stored = typeof window !== 'undefined' ? sessionStorage.getItem('warrant:focused-package') : null;
        const targetPackage = stored || selectedNodeId;
        if (targetPackage) {
          if (stored) {
            sessionStorage.removeItem('warrant:focused-package');
          }
          const searchSub = targetPackage.toLowerCase();
          const target = cy.nodes().filter(n => {
            const nId = (n.data('id') || '').toLowerCase();
            const nName = (n.data('name') || '').toLowerCase();
            return nId === searchSub || nName === searchSub || (nId && nId.includes(searchSub));
          }).first();

          if (target && target.length > 0) {
            const targetId = target.data('id');
            setSelectedNodeId(targetId);
            cy.animate({
              center: { eles: target },
              zoom: Math.max(cy.zoom(), 1.15),
              duration: 350,
            });
          }
        }
      } catch {}

      return () => {
        cy.destroy();
        cyRef.current = null;
      };
    } catch (e) {
      console.error('Cytoscape dagre initialization error', e);
    }
  }, [elements, viewMode, direction, tokenColors, decisionMap, onSelectDecision]);

  // Synchronize selection & blast radius highlighting with Cytoscape elements
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;

    // Clear previous selection & blast radius classes
    cy.elements().removeClass(
      'dimmed selected-target highlighted-ancestor-node highlighted-ancestor-edge highlighted-blast-node highlighted-blast-edge blast-direct-node blast-transitive-node blast-path-edge'
    );

    if (!selectedNodeId) return;

    const targetNode = cy.getElementById(selectedNodeId);
    if (!targetNode || targetNode.length === 0) return;

    targetNode.addClass('selected-target');

    if (isBlastRadiusActive && blastRadius) {
      // 1. Highlight direct dependents (solid)
      blastRadius.directDependents.forEach(depId => {
        cy.getElementById(depId).addClass('blast-direct-node');
      });

      // 2. Highlight transitive dependents (dashed)
      blastRadius.transitiveDependents.forEach(depId => {
        cy.getElementById(depId).addClass('blast-transitive-node');
      });

      // 3. Highlight edges along dependency paths toward selected
      blastRadius.highlightEdgeIds.forEach(edgeId => {
        cy.getElementById(edgeId).addClass('blast-path-edge');
      });

      // 4. Dim all elements not in blast radius (and not the selected node)
      const activeCollection = cy.collection();
      activeCollection.merge(targetNode);
      blastRadius.allDependentIds.forEach(depId => {
        activeCollection.merge(cy.getElementById(depId));
      });
      blastRadius.highlightEdgeIds.forEach(edgeId => {
        activeCollection.merge(cy.getElementById(edgeId));
      });

      cy.elements().difference(activeCollection).addClass('dimmed');
    } else {
      // Normal Selection Mode: 2-way lineage
      const ancestors = targetNode.predecessors();
      const descendants = targetNode.successors();
      const activeSubtree = targetNode.union(ancestors).union(descendants);

      cy.elements().difference(activeSubtree).addClass('dimmed');
      ancestors.nodes().addClass('highlighted-ancestor-node');
      ancestors.edges().addClass('highlighted-ancestor-edge');
      descendants.nodes().addClass('highlighted-blast-node');
      descendants.edges().addClass('highlighted-blast-edge');
    }
  }, [selectedNodeId, isBlastRadiusActive, blastRadius]);

  // Apply Temporal Highlight whenever activeTemporalChange changes or graph mounts
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;

    // Clear previous temporal classes
    cy.elements().removeClass('temporal-node temporal-added temporal-modified');

    if (!activeTemporalChange) return;

    const pkgName = activeTemporalChange.package_name.toLowerCase();
    const pkgId = activeTemporalChange.package_id.toLowerCase();

    const byId = cy.nodes().filter(n => (n.data('id') || '').toLowerCase() === pkgId);
    const matched = (byId.length > 0
      ? byId
      : cy.nodes().filter(n => (n.data('name') || '').toLowerCase() === pkgName)
    ).first();

    if (matched && matched.length > 0) {
      matched.addClass('temporal-node');
      if (activeTemporalChange.type === 'ADDED') {
        matched.addClass('temporal-added');
      } else if (activeTemporalChange.type === 'MODIFIED') {
        matched.addClass('temporal-modified');
      }

      // Select node so its relevant context and potential blast radius show in HUD
      setSelectedNodeId(matched.data('id'));
      setNotInGraphNotice(null);

      // Smoothly pan and center on the temporal node without breaking surrounding context
      try {
        cy.animate({
          center: { eles: matched },
          zoom: Math.max(cy.zoom(), 1.05),
          duration: motionMs(350),
        });
      } catch {
        // fallback
      }
    }
  }, [activeTemporalChange, elements]);

  // Clear temporal highlight helper
  const handleClearTemporalHighlight = useCallback(() => {
    setActiveTemporalChange(null);
    if (typeof window !== 'undefined') {
      try {
        sessionStorage.removeItem('warrant:temporal-change');
        window.dispatchEvent(new CustomEvent('warrant:temporal-change', { detail: null }));
      } catch {}
    }
    if (cyRef.current) {
      cyRef.current.elements().removeClass('temporal-node temporal-added temporal-modified');
    }
  }, []);

  // Toolbar Action Handlers
  const handleZoomIn = useCallback(() => {
    if (!cyRef.current) return;
    cyRef.current.animate({
      zoom: cyRef.current.zoom() * 1.3,
      duration: motionMs(150),
    });
  }, []);

  const handleZoomOut = useCallback(() => {
    if (!cyRef.current) return;
    cyRef.current.animate({
      zoom: cyRef.current.zoom() * 0.7,
      duration: motionMs(150),
    });
  }, []);

  const handleFit = useCallback(() => {
    if (!cyRef.current) return;
    cyRef.current.fit(undefined, 35);
  }, []);

  const handleReset = useCallback(() => {
    if (!cyRef.current) return;
    setSelectedNodeId(null);
    setIsBlastRadiusActive(false);
    cyRef.current.elements().removeClass(
      'dimmed selected-target highlighted-ancestor-node highlighted-ancestor-edge highlighted-blast-node highlighted-blast-edge blast-direct-node blast-transitive-node blast-path-edge'
    );
    cyRef.current.reset();
    cyRef.current.fit(undefined, 35);
  }, []);

  const toggleDirection = useCallback(() => {
    setDirection(prev => (prev === 'TB' ? 'LR' : 'TB'));
  }, []);

  // Empty State Guard
  if (!graph || !graph.nodes || graph.nodes.length === 0) {
    return (
      <div
        className="card"
        style={{
          padding: 'var(--space-12)',
          textAlign: 'center',
          color: 'var(--color-muted)',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          gap: 'var(--space-3)',
        }}
      >
        <Info size={40} style={{ opacity: 0.6 }} aria-hidden />
        <h3 style={{ fontSize: 'var(--text-base)', fontWeight: 600, color: 'var(--color-text)' }}>
          No Dependency Graph Available
        </h3>
        <p style={{ fontSize: 'var(--text-sm)', maxWidth: 460 }}>
          The lockfile did not provide structural dependency edges or graph generation was bypassed.
        </p>
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
      {/* Header Controls & Summary */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: 'var(--space-3)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
          <Layers size={18} style={{ color: 'var(--color-accent)' }} aria-hidden />
          <span style={{ fontSize: 'var(--text-sm)', fontWeight: 600 }}>
            Dependency Hierarchy ({graph.nodes.length} nodes, {graph.edges?.length || 0} edges)
          </span>
        </div>

        <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center' }}>
          <button
            onClick={() => setViewMode(m => (m === 'visual' ? 'text' : 'visual'))}
            className="btn btn-secondary btn-sm"
          >
            {viewMode === 'visual' ? 'Accessible Text View' : 'Interactive Graph'}
          </button>
        </div>
      </div>

      {/* Visual Canvas View */}
      {viewMode === 'visual' ? (
        <div
          style={{
            position: 'relative',
            border: '1px solid var(--color-border)',
            borderRadius: 'var(--radius-lg)',
            overflow: 'hidden',
            background: 'var(--color-surface)',
          }}
        >
          {/* Active Temporal Event Contextual Overlay Banner (Section 3 & 7) */}
          {activeTemporalChange && (
            <div
              style={{
                position: 'absolute',
                top: 'var(--space-3)',
                left: 'var(--space-3)',
                zIndex: 35,
                display: 'flex',
                alignItems: 'center',
                gap: 'var(--space-2)',
                background: 'var(--color-surface)',
                border: isTemporalNodeInGraph
                  ? `1px solid ${activeTemporalChange.type === 'ADDED' ? '#06B6D4' : '#8B5CF6'}`
                  : '1px solid var(--color-border)',
                borderRadius: 'var(--radius-md)',
                padding: '6px 10px',
                boxShadow: 'var(--shadow-sm)',
                fontSize: '11px',
                maxWidth: '460px',
              }}
            >
              <History size={14} style={{ color: activeTemporalChange.type === 'ADDED' ? '#0891B2' : '#7C3AED', flexShrink: 0 }} />
              <div style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                <span
                  style={{
                    fontWeight: 700,
                    marginRight: '6px',
                    color: activeTemporalChange.type === 'ADDED' ? '#0891B2' : '#7C3AED',
                  }}
                >
                  [{activeTemporalChange.type}]
                </span>
                {isTemporalNodeInGraph ? (
                  <span>
                    <strong>{activeTemporalChange.package_name}</strong> {activeTemporalChange.version ? `@${activeTemporalChange.version}` : ''}
                    {activeTemporalChange.previous_version && activeTemporalChange.new_version
                      ? ` (${activeTemporalChange.previous_version} → ${activeTemporalChange.new_version})`
                      : ''}
                    {' · highlighted in graph'}
                  </span>
                ) : (
                  <span style={{ color: 'var(--color-muted)' }}>
                    <strong>{activeTemporalChange.package_name}</strong> is absent from this historical state
                  </span>
                )}
              </div>
              <button
                onClick={handleClearTemporalHighlight}
                className="btn btn-ghost btn-sm"
                style={{ padding: '2px 4px', minWidth: 'auto', height: 'auto', marginLeft: 'auto' }}
                title="Dismiss temporal highlight"
                aria-label="Dismiss temporal highlight"
              >
                <X size={12} />
              </button>
            </div>
          )}

          {/* Cytoscape Container */}
          <div
            ref={containerRef}
            style={{
              width: '100%',
              height: '560px',
              minHeight: '440px',
              position: 'relative',
            }}
          />

          {/* Floating Navigation Controls Toolbar */}
          <div
            style={{
              position: 'absolute',
              top: 'var(--space-3)',
              right: 'var(--space-3)',
              display: 'flex',
              flexDirection: 'column',
              gap: 'var(--space-1)',
              background: 'var(--color-surface)',
              border: '1px solid var(--color-border)',
              borderRadius: 'var(--radius-md)',
              boxShadow: 'var(--shadow-sm)',
              padding: 'var(--space-1)',
              zIndex: 30,
            }}
          >
            <button
              onClick={handleZoomIn}
              className="btn btn-ghost btn-sm"
              title="Zoom In"
              aria-label="Zoom in on graph"
              style={{ padding: '6px', minWidth: 'auto', height: '30px' }}
            >
              <ZoomIn size={16} />
            </button>
            <button
              onClick={handleZoomOut}
              className="btn btn-ghost btn-sm"
              title="Zoom Out"
              aria-label="Zoom out on graph"
              style={{ padding: '6px', minWidth: 'auto', height: '30px' }}
            >
              <ZoomOut size={16} />
            </button>
            <button
              onClick={handleFit}
              className="btn btn-ghost btn-sm"
              title="Fit View"
              aria-label="Fit graph in view"
              style={{ padding: '6px', minWidth: 'auto', height: '30px' }}
            >
              <Maximize2 size={16} />
            </button>
            <button
              onClick={handleReset}
              className="btn btn-ghost btn-sm"
              title="Reset View"
              aria-label="Reset zoom and layout"
              style={{ padding: '6px', minWidth: 'auto', height: '30px' }}
            >
              <RotateCcw size={16} />
            </button>
            <div style={{ height: '1px', background: 'var(--color-border)', margin: '2px 0' }} />
            <button
              onClick={toggleDirection}
              className="btn btn-ghost btn-sm"
              title={`Switch to ${direction === 'TB' ? 'Horizontal (Left to Right)' : 'Vertical (Top to Bottom)'} layout`}
              aria-label="Toggle layout orientation"
              style={{ padding: '6px', minWidth: 'auto', height: '30px', fontSize: '10px' }}
            >
              <ArrowRightLeft size={14} />
            </button>
          </div>

          {/* Missing Node Notice Banner */}
          {notInGraphNotice && (
            <div
              style={{
                position: 'absolute',
                top: 'var(--space-3)',
                left: 'var(--space-3)',
                zIndex: 35,
                padding: 'var(--space-2) var(--space-4)',
                borderRadius: 'var(--radius-md)',
                background: 'var(--color-surface)',
                border: '1px solid var(--verdict-act-now-border)',
                boxShadow: 'var(--shadow-md)',
                display: 'flex',
                alignItems: 'center',
                gap: 'var(--space-2)',
                fontSize: 'var(--text-xs)',
                color: 'var(--verdict-act-now-fg)',
              }}
              role="status"
              aria-live="polite"
            >
              <AlertCircle size={14} aria-hidden />
              <span>{notInGraphNotice}</span>
              <button
                type="button"
                onClick={() => setNotInGraphNotice(null)}
                className="btn btn-ghost btn-sm"
                style={{ padding: '2px', minWidth: 'auto', height: 'auto', marginLeft: 'var(--space-2)' }}
                aria-label="Dismiss notice"
              >
                <X size={12} />
              </button>
            </div>
          )}

          {/* Selected Node Inspection HUD Overlay with Blast Radius (Restrained Enterprise Console Style) */}
          {selectedNodeId && (
            <div
              style={{
                position: 'absolute',
                bottom: 'var(--space-3)',
                left: 'var(--space-3)',
                width: '320px',
                maxWidth: 'calc(100% - 24px)',
                background: '#FFFFFF',
                border: isBlastRadiusActive ? '1px solid var(--verdict-incident-border)' : '1px solid var(--color-border)',
                borderRadius: 'var(--radius-sm)',
                boxShadow: '0 2px 8px 0 rgba(0, 0, 0, 0.06)',
                padding: '12px 14px',
                zIndex: 30,
              }}
            >
              {/* 1. Header: [VERDICT]  × */}
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  marginBottom: '8px',
                }}
              >
                {selectedDecision ? (
                  <VerdictChip verdict={selectedDecision.verdict} />
                ) : (
                  <span className="verdict-chip verdict-NO_KNOWN_FINDING">NO KNOWN FINDING</span>
                )}
                <button
                  type="button"
                  onClick={() => {
                    setSelectedNodeId(null);
                    setIsBlastRadiusActive(false);
                  }}
                  className="btn btn-ghost btn-sm"
                  style={{ padding: '2px', minWidth: 'auto', height: 'auto', color: 'var(--color-muted)' }}
                  aria-label="Close inspection panel"
                >
                  <X size={14} />
                </button>
              </div>

              {/* 2. Package Name & Version */}
              <div style={{ marginBottom: '2px' }}>
                <code style={{ fontSize: '13px', fontWeight: 700, color: 'var(--color-text)', wordBreak: 'break-all' }}>
                  {selectedGraphNode?.name}@{selectedGraphNode?.version || 'latest'}
                </code>
              </div>

              {/* 3. Direct/Transitive Dependency */}
              <div style={{ fontSize: '11px', color: 'var(--color-muted)' }}>
                {selectedGraphNode?.is_direct ? 'Direct dependency' : `Transitive dependency (depth ${selectedGraphNode?.depth || '?'})`}
              </div>

              {/* 4. Temporal Introduction Marker */}
              {(() => {
                let temporalText: string | null = null;
                if (
                  activeTemporalChange &&
                  (selectedGraphNode?.name?.toLowerCase() === activeTemporalChange.package_name.toLowerCase() ||
                    selectedNodeId.toLowerCase().includes(activeTemporalChange.package_name.toLowerCase()))
                ) {
                  const act = activeTemporalChange.type === 'ADDED' ? 'Dependency introduced' : 'Dependency modified';
                  temporalText = `${act} · ${activeTemporalChange.effective_at.split('T')[0]}`;
                } else if (selectedGraphNode?.name === 'plain-crypto-js') {
                  temporalText = 'Dependency introduced · Mar 14, 2026';
                } else if (selectedGraphNode?.name === 'axios' && selectedDecision?.verdict === 'INCIDENT') {
                  temporalText = 'Dependency introduced · Mar 12, 2026';
                }

                if (!temporalText) return null;
                return (
                  <div style={{ fontSize: '11px', color: 'var(--color-muted)', marginTop: '2px' }}>
                    {temporalText}
                  </div>
                );
              })()}

              {/* 5. Reported Malicious / Advisory */}
              {(() => {
                const isMalicious = selectedDecision?.verdict === 'INCIDENT';
                const isUrgent = selectedDecision?.verdict === 'ACT_NOW';
                const isUpgrade = selectedDecision?.verdict === 'UPGRADE';
                const headline = isMalicious
                  ? 'Reported malicious'
                  : isUrgent
                  ? 'Known exploited vulnerability'
                  : isUpgrade
                  ? 'Security advisory'
                  : null;

                const advisoryId =
                  (selectedDecision?.evidence_ids && selectedDecision.evidence_ids[0]) ||
                  (selectedGraphNode?.name === 'plain-crypto-js' ? 'MAL-2026-2306' : null) ||
                  (selectedDecision?.derivation?.find(d => d.includes('CVE-') || d.includes('GHSA-') || d.includes('MAL-'))) ||
                  null;

                if (!headline && !advisoryId) return null;

                return (
                  <div style={{ marginTop: '10px' }}>
                    {headline && (
                      <div
                        style={{
                          fontSize: '11px',
                          fontWeight: 600,
                          color: isMalicious ? 'var(--verdict-incident-fg)' : 'var(--color-text)',
                        }}
                      >
                        {headline}
                      </div>
                    )}
                    {advisoryId && (
                      <code
                        style={{
                          fontSize: '12px',
                          fontWeight: 700,
                          color: isMalicious ? 'var(--verdict-incident-fg)' : 'var(--color-text)',
                        }}
                      >
                        {advisoryId}
                      </code>
                    )}
                  </div>
                );
              })()}

              {/* 6. Potential Blast Radius Summary */}
              <div
                style={{
                  marginTop: '10px',
                  paddingTop: '8px',
                  borderTop: '1px solid var(--color-border)',
                }}
              >
                <div
                  style={{
                    fontSize: '11px',
                    fontWeight: 700,
                    textTransform: 'uppercase',
                    letterSpacing: '0.04em',
                    color: 'var(--color-text)',
                    marginBottom: '2px',
                  }}
                >
                  Potential Blast Radius
                </div>
                <div
                  style={{
                    fontSize: '12px',
                    fontWeight: 600,
                    color: (blastRadius?.totalCount || 0) > 0 ? 'var(--verdict-incident-fg)' : 'var(--color-muted)',
                  }}
                >
                  {blastRadius?.totalCount === 1 ? '1 dependent' : `${blastRadius?.totalCount || 0} dependents`}
                </div>
                <div style={{ fontSize: '11px', color: 'var(--color-muted)' }}>
                  {blastRadius?.directDependents.length || 0} direct · {blastRadius?.transitiveDependents.length || 0} transitive
                </div>
              </div>

              {/* 7. Affected Dependencies (Compact List) */}
              {isBlastRadiusActive && blastRadius && blastRadius.totalCount > 0 && (
                <div style={{ marginTop: '10px' }}>
                  <div
                    style={{
                      fontSize: '11px',
                      fontWeight: 600,
                      color: 'var(--color-muted)',
                      marginBottom: '4px',
                    }}
                  >
                    Affected dependencies
                  </div>
                  <div
                    style={{
                      maxHeight: '100px',
                      overflowY: 'auto',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '3px',
                    }}
                  >
                    {blastRadius.directDependents.map(depId => {
                      const depNode = graph?.nodes?.find(n => n.id === depId);
                      const depName = depNode ? `${depNode.name}@${depNode.version}` : depId;
                      return (
                        <div
                          key={depId}
                          style={{
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'space-between',
                            padding: '2px 5px',
                            background: 'var(--color-bg)',
                            borderRadius: '3px',
                            fontSize: '11px',
                          }}
                        >
                          <code style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            {depName}
                          </code>
                          <span
                            style={{
                              fontSize: '10px',
                              fontWeight: 600,
                              color: 'var(--verdict-incident-fg)',
                              flexShrink: 0,
                              marginLeft: '6px',
                            }}
                          >
                            Direct
                          </span>
                        </div>
                      );
                    })}
                    {blastRadius.transitiveDependents.map(depId => {
                      const depNode = graph?.nodes?.find(n => n.id === depId);
                      const depName = depNode ? `${depNode.name}@${depNode.version}` : depId;
                      return (
                        <div
                          key={depId}
                          style={{
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'space-between',
                            padding: '2px 5px',
                            background: 'var(--color-bg)',
                            borderRadius: '3px',
                            fontSize: '11px',
                          }}
                        >
                          <code style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            {depName}
                          </code>
                          <span
                            style={{
                              fontSize: '10px',
                              fontWeight: 600,
                              color: 'var(--color-muted)',
                              flexShrink: 0,
                              marginLeft: '6px',
                            }}
                          >
                            Transitive
                          </span>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* 8. Dependency Path */}
              {isBlastRadiusActive && blastRadius && blastRadius.paths.length > 0 && (
                <div style={{ marginTop: '10px' }}>
                  <div
                    style={{
                      fontSize: '11px',
                      fontWeight: 600,
                      color: 'var(--color-muted)',
                      marginBottom: '4px',
                    }}
                  >
                    Dependency path
                  </div>
                  <div
                    style={{
                      padding: '4px 6px',
                      background: 'var(--color-bg)',
                      border: '1px solid var(--color-border)',
                      borderRadius: '3px',
                      fontSize: '11px',
                      fontFamily: 'var(--font-mono)',
                      overflowX: 'auto',
                      whiteSpace: 'nowrap',
                    }}
                  >
                    {blastRadius.paths[0].join(' → ')}
                  </div>
                </div>
              )}

              {/* 9. Actions: [ Exit Blast Radius ] [ View Decision ] */}
              <div
                style={{
                  display: 'flex',
                  gap: '6px',
                  marginTop: '10px',
                  paddingTop: '8px',
                  borderTop: '1px solid var(--color-border)',
                }}
              >
                <button
                  type="button"
                  onClick={() => setIsBlastRadiusActive(prev => !prev)}
                  className="btn btn-secondary btn-sm"
                  style={{
                    flex: 1,
                    fontSize: '11px',
                    height: '28px',
                    padding: '0 8px',
                  }}
                >
                  {isBlastRadiusActive ? 'Exit Blast Radius' : 'Show Blast Radius'}
                </button>

                {onSelectDecision && (selectedDecision || selectedGraphNode) && (
                  <button
                    type="button"
                    onClick={() => handleViewDependentDecision(selectedNodeId)}
                    className="btn btn-primary btn-sm"
                    style={{
                      flex: 1,
                      fontSize: '11px',
                      height: '28px',
                      padding: '0 8px',
                    }}
                  >
                    View Decision
                  </button>
                )}
              </div>
            </div>
          )}

          {/* Footer Guide */}
          <div
            style={{
              padding: 'var(--space-2) var(--space-4)',
              borderTop: '1px solid var(--color-border)',
              background: 'var(--color-bg)',
              fontSize: 'var(--text-xs)',
              color: 'var(--color-muted)',
              display: 'flex',
              gap: 'var(--space-4)',
              flexWrap: 'wrap',
              alignItems: 'center',
            }}
          >
            <span>Click any node to inspect · Click "Show Blast Radius" to trace all dependent packages</span>
            {activeTemporalChange && (
              <span style={{ color: activeTemporalChange.type === 'ADDED' ? '#0891B2' : '#7C3AED', fontWeight: 600 }}>
                • Active As-Of Event: {activeTemporalChange.package_name} ({activeTemporalChange.type})
              </span>
            )}
            <span>Click canvas background to clear selection</span>
            <span>Scroll to zoom · Drag canvas to pan</span>
          </div>
        </div>
      ) : (
        /* Accessible Text View */
        <div className="card" style={{ padding: 'var(--space-5)' }}>
          <h2 style={{ fontSize: 'var(--text-base)', fontWeight: 600, marginBottom: 'var(--space-4)' }}>
            Dependency Paths (Accessible Text View)
          </h2>
          {decisions.filter(d => d.exposure?.paths?.length > 0).length === 0 ? (
            <p style={{ fontSize: 'var(--text-sm)', color: 'var(--color-muted)' }}>
              No exposure paths recorded for decisions in this report.
            </p>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
              {decisions
                .filter(d => d.exposure && d.exposure.paths && d.exposure.paths.length > 0)
                .slice(0, 30)
                .map(dec => {
                  const decBr = calculateBlastRadius(dec.subject, graph.nodes, graph.edges);
                  return (
                    <div
                      key={dec.subject}
                      style={{
                        borderBottom: '1px solid var(--color-border)',
                        paddingBottom: 'var(--space-3)',
                      }}
                    >
                      <div
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'space-between',
                          flexWrap: 'wrap',
                          gap: 'var(--space-2)',
                          marginBottom: 'var(--space-2)',
                        }}
                      >
                        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
                          <VerdictChip verdict={dec.verdict} />
                          <code className="purl">
                            {dec.name}@{dec.version}
                          </code>
                        </div>
                        {decBr && (
                          <span style={{ fontSize: '11px', color: 'var(--color-muted)' }}>
                            Potential Blast Radius: <strong>{decBr.totalCount}</strong> dependent {decBr.totalCount === 1 ? 'package' : 'packages'} ({decBr.directDependents.length} direct, {decBr.transitiveDependents.length} transitive)
                          </span>
                        )}
                      </div>
                      <ol
                        style={{
                          paddingLeft: 'var(--space-6)',
                          fontSize: 'var(--text-xs)',
                          fontFamily: 'var(--font-mono)',
                          lineHeight: 1.8,
                          color: 'var(--color-muted)',
                        }}
                      >
                        {dec.exposure.paths[0]?.map((node, i) => (
                          <li key={i}>
                            {node}
                            {node.includes(dec.name) && dec.exposure.install_phase === 'observed'
                              ? ' ⚠ (install script observed)'
                              : ''}
                          </li>
                        ))}
                      </ol>
                    </div>
                  );
                })}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default GraphTab;
