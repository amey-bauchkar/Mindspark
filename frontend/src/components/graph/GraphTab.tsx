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
  History
} from 'lucide-react';

if (typeof cytoscape === 'function' && dagre) {
  try {
    cytoscape.use(dagre);
  } catch {
    // already registered
  }
}

interface GraphTabProps {
  graph: { nodes: GraphNode[]; edges: GraphEdge[] };
  decisions: Decision[];
  onSelectDecision?: (decision: Decision) => void;
  temporalChange?: DependencyChangeEvent | null;
}

export function GraphTab({ 
  graph, 
  decisions, 
  onSelectDecision,
  temporalChange,
}: GraphTabProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<cytoscape.Core | null>(null);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [viewMode, setViewMode] = useState<'visual' | 'text'>('visual');
  const [direction, setDirection] = useState<'TB' | 'LR'>('TB');

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

  // Map decisions by both PURL id and package name for O(1) lookups
  const decisionMap = useMemo(() => {
    const map = new Map<string, Decision>();
    decisions.forEach(d => {
      if (d.subject) map.set(d.subject, d);
      if (d.name) map.set(d.name, d);
    });
    return map;
  }, [decisions]);

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
    return graph.nodes.some(n => {
      const nId = (n.id || '').toLowerCase();
      const nName = (n.name || '').toLowerCase();
      return nId === pkgId || nName === pkgName || nId.includes(pkgName);
    });
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
          {
            selector: '.selected-target',
            style: {
              'border-width': 4,
              'border-color': tokenColors.accent,
              'z-index': 999,
              opacity: 1,
            },
          },
          // Upstream Ancestor Lineage (Root -> Selected Node)
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
          // Downstream Blast Radius (Packages depending on / pulled by Selected Node)
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
          // Temporal Change Highlights (Halo & Outline without overwriting verdict color)
          {
            selector: '.temporal-node',
            style: {
              'z-index': 1000,
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

      // Handle Node Click: 2-way lineage & blast-radius highlighting
      cy.on('tap', 'node', evt => {
        const targetNode = evt.target;
        const nodeId = targetNode.data('id');
        setSelectedNodeId(nodeId);

        // Clear all previous highlight classes
        cy.elements().removeClass(
          'dimmed selected-target highlighted-ancestor-node highlighted-ancestor-edge highlighted-blast-node highlighted-blast-edge'
        );

        // Predecessors = Upstream chain leading from Root into this node
        const ancestors = targetNode.predecessors();
        // Successors = Downstream chain / dependencies pulled by this node
        const descendants = targetNode.successors();

        const activeSubtree = targetNode.union(ancestors).union(descendants);

        // Dim everything outside active lineage
        cy.elements().difference(activeSubtree).addClass('dimmed');

        targetNode.addClass('selected-target');
        ancestors.nodes().addClass('highlighted-ancestor-node');
        ancestors.edges().addClass('highlighted-ancestor-edge');
        descendants.nodes().addClass('highlighted-blast-node');
        descendants.edges().addClass('highlighted-blast-edge');

        const dec = decisionMap.get(nodeId);
        if (dec && onSelectDecision) {
          onSelectDecision(dec);
        }
      });

      // Handle Canvas Background Tap: Clear highlights
      cy.on('tap', evt => {
        if (evt.target === cy) {
          setSelectedNodeId(null);
          cy.elements().removeClass(
            'dimmed selected-target highlighted-ancestor-node highlighted-ancestor-edge highlighted-blast-node highlighted-blast-edge'
          );
        }
      });

      cyRef.current = cy;

      return () => {
        cy.destroy();
        cyRef.current = null;
      };
    } catch (e) {
      console.error('Cytoscape dagre initialization error', e);
    }
  }, [elements, viewMode, direction, tokenColors, decisionMap, onSelectDecision]);

  // Apply Temporal Highlight whenever activeTemporalChange changes or graph mounts
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;

    // Clear previous temporal classes
    cy.elements().removeClass('temporal-node temporal-added temporal-modified');

    if (!activeTemporalChange) return;

    const pkgName = activeTemporalChange.package_name.toLowerCase();
    const pkgId = activeTemporalChange.package_id.toLowerCase();

    const matched = cy.nodes().filter(n => {
      const nId = (n.data('id') || '').toLowerCase();
      const nName = (n.data('name') || '').toLowerCase();
      return nId === pkgId || nName === pkgName || nId.includes(pkgName);
    }).first();

    if (matched && matched.length > 0) {
      matched.addClass('temporal-node');
      if (activeTemporalChange.type === 'ADDED') {
        matched.addClass('temporal-added');
      } else if (activeTemporalChange.type === 'MODIFIED') {
        matched.addClass('temporal-modified');
      }

      // Smoothly pan and center on the temporal node without breaking surrounding context
      try {
        cy.animate({
          center: { eles: matched },
          zoom: Math.max(cy.zoom(), 1.05),
          duration: 350,
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
      duration: 150,
    });
  }, []);

  const handleZoomOut = useCallback(() => {
    if (!cyRef.current) return;
    cyRef.current.animate({
      zoom: cyRef.current.zoom() * 0.7,
      duration: 150,
    });
  }, []);

  const handleFit = useCallback(() => {
    if (!cyRef.current) return;
    cyRef.current.fit(undefined, 35);
  }, []);

  const handleReset = useCallback(() => {
    if (!cyRef.current) return;
    setSelectedNodeId(null);
    cyRef.current.elements().removeClass(
      'dimmed selected-target highlighted-ancestor-node highlighted-ancestor-edge highlighted-blast-node highlighted-blast-edge'
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

          {/* Selected Node Inspection HUD Overlay */}
          {selectedNodeId && (
            <div
              style={{
                position: 'absolute',
                bottom: 'var(--space-3)',
                left: 'var(--space-3)',
                maxWidth: '380px',
                background: 'var(--color-surface)',
                border: '1px solid var(--color-border)',
                borderRadius: 'var(--radius-md)',
                boxShadow: 'var(--shadow-md)',
                padding: 'var(--space-3)',
                zIndex: 30,
              }}
            >
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'flex-start',
                  gap: 'var(--space-2)',
                  marginBottom: 'var(--space-2)',
                }}
              >
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginBottom: '4px' }}>
                    {selectedDecision ? (
                      <VerdictChip verdict={selectedDecision.verdict} />
                    ) : (
                      <span className="verdict-chip verdict-NO_KNOWN_FINDING">NO KNOWN FINDING</span>
                    )}
                    <span style={{ fontSize: 'var(--text-xs)', color: 'var(--color-muted)' }}>
                      {selectedGraphNode?.is_direct ? 'direct dependency' : `depth ${selectedGraphNode?.depth || 'transitive'}`}
                    </span>
                  </div>
                  <code style={{ fontSize: 'var(--text-xs)', fontWeight: 600, wordBreak: 'break-all' }}>
                    {selectedGraphNode?.name}@{selectedGraphNode?.version || 'latest'}
                  </code>
                </div>
                <button
                  onClick={() => {
                    setSelectedNodeId(null);
                    cyRef.current?.elements().removeClass(
                      'dimmed selected-target highlighted-ancestor-node highlighted-ancestor-edge highlighted-blast-node highlighted-blast-edge'
                    );
                  }}
                  className="btn btn-ghost btn-sm"
                  style={{ padding: '2px', minWidth: 'auto', height: 'auto' }}
                  aria-label="Dismiss inspector"
                >
                  <X size={14} />
                </button>
              </div>

              {selectedDecision?.what && (
                <p
                  style={{
                    fontSize: 'var(--text-xs)',
                    color: 'var(--color-text)',
                    lineHeight: 1.4,
                    marginBottom: 'var(--space-2)',
                  }}
                >
                  {selectedDecision.what}
                </p>
              )}

              <div
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  paddingTop: 'var(--space-2)',
                  borderTop: '1px solid var(--color-border)',
                }}
              >
                <div style={{ display: 'flex', gap: 'var(--space-3)', fontSize: '11px', color: 'var(--color-muted)' }}>
                  <span>🔵 Ancestor chain highlighted</span>
                  <span>🟠 Downstream tree highlighted</span>
                </div>
                {selectedDecision && onSelectDecision && (
                  <button
                    onClick={() => onSelectDecision(selectedDecision)}
                    className="btn btn-secondary btn-sm"
                    style={{ fontSize: '11px', padding: '2px 8px', height: '24px' }}
                  >
                    <span>Details</span>
                    <ExternalLink size={12} />
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
            <span>Click any node to trace upstream path & downstream blast radius</span>
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
                .map(dec => (
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
                        gap: 'var(--space-2)',
                        marginBottom: 'var(--space-2)',
                      }}
                    >
                      <VerdictChip verdict={dec.verdict} />
                      <code className="purl">
                        {dec.name}@{dec.version}
                      </code>
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
                ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default GraphTab;
