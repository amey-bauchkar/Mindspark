import React, { useEffect, useRef, useState } from 'react';
import type { Decision, GraphNode, GraphEdge, Verdict } from '../../lib/types';
import { VERDICT_LABELS } from '../../lib/types';
import cytoscape from 'cytoscape';
// @ts-ignore
import dagre from 'cytoscape-dagre';

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
}

export function GraphTab({ graph, decisions, onSelectDecision }: GraphTabProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<cytoscape.Core | null>(null);
  const [selectedNode, setSelectedNode] = useState<string | null>(null);
  const [viewMode, setViewMode] = useState<'visual' | 'text'>('visual');

  const decisionMap = new Map<string, Decision>();
  decisions.forEach(d => {
    decisionMap.set(d.subject, d);
    decisionMap.set(d.name, d);
  });

  useEffect(() => {
    if (viewMode !== 'visual' || !containerRef.current || !graph.nodes.length) return;

    try {
      // Build elements for cytoscape
      const elements: cytoscape.ElementDefinition[] = [
        ...graph.nodes.map((n: GraphNode) => {
          const dec = decisionMap.get(n.id) || decisionMap.get(n.name);
          const verdict = dec?.verdict || n.verdict || 'NO_KNOWN_FINDING';
          return {
            data: {
              id: n.id,
              label: `${n.name}@${n.version}`,
              verdict,
              isDirect: n.is_direct,
            },
          };
        }),
        ...graph.edges.map((e: GraphEdge, idx: number) => ({
          data: {
            id: `e-${idx}`,
            source: e.source,
            target: e.target,
          },
        })),
      ];

      const cy = cytoscape({
        container: containerRef.current,
        elements,
        style: [
          {
            selector: 'node',
            style: {
              label: 'data(label)',
              'font-size': '10px',
              'font-family': 'monospace',
              'text-valign': 'bottom',
              'text-margin-y': 4,
              color: '#344054',
              'background-color': '#9AA4B2',
              width: 24,
              height: 24,
              'border-width': 2,
              'border-color': '#475467',
            },
          },
          {
            selector: 'node[verdict = "INCIDENT"]',
            style: {
              'background-color': '#B42318',
              'border-color': '#FECDCA',
              width: 32,
              height: 32,
            },
          },
          {
            selector: 'node[verdict = "ACT_NOW"]',
            style: {
              'background-color': '#C4320A',
              'border-color': '#F9DBAF',
              width: 30,
              height: 30,
            },
          },
          {
            selector: 'node[verdict = "UPGRADE"]',
            style: {
              'background-color': '#B54708',
              'border-color': '#FEDF89',
              width: 28,
              height: 28,
            },
          },
          {
            selector: 'node[verdict = "REVIEW"]',
            style: {
              'background-color': '#5925DC',
              'border-color': '#D9D6FE',
            },
          },
          {
            selector: 'node[verdict = "MONITOR"]',
            style: {
              'background-color': '#175CD3',
              'border-color': '#B2DDFF',
            },
          },
          {
            selector: 'edge',
            style: {
              width: 1.5,
              'line-color': '#D0D5DD',
              'target-arrow-color': '#D0D5DD',
              'target-arrow-shape': 'triangle',
              'curve-style': 'bezier',
              'arrow-scale': 0.8,
            },
          },
          {
            selector: ':selected',
            style: {
              'border-width': 3,
              'border-color': '#aa3bff',
              'line-color': '#aa3bff',
              'target-arrow-color': '#aa3bff',
            },
          },
        ],
        layout: {
          name: 'cose',
          animate: false,
          padding: 30,
        },
      });

      cy.on('tap', 'node', evt => {
        const node = evt.target;
        const purl = node.data('id');
        setSelectedNode(purl);
        const dec = decisionMap.get(purl);
        if (dec && onSelectDecision) {
          onSelectDecision(dec);
        }
      });

      cyRef.current = cy;

      return () => {
        cy.destroy();
      };
    } catch (e) {
      console.error('Cytoscape init error', e);
    }
  }, [graph, viewMode]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
      {/* Controls & Summary */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: 'var(--space-2)',
        }}
      >
        <div className="callout callout-info" style={{ margin: 0, flex: 1 }}>
          <p style={{ fontSize: 'var(--text-sm)' }}>
            <strong>{graph.nodes.length}</strong> nodes and <strong>{graph.edges.length}</strong>{' '}
            edges in the dependency graph.
          </p>
        </div>
        <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
          <button
            onClick={() => setViewMode(m => (m === 'visual' ? 'text' : 'visual'))}
            className="btn btn-secondary btn-sm"
          >
            Switch to {viewMode === 'visual' ? 'Accessible Text View' : 'Interactive Graph'}
          </button>
          {viewMode === 'visual' && (
            <button
              onClick={() => cyRef.current?.fit(undefined, 30)}
              className="btn btn-ghost btn-sm"
            >
              Fit Graph
            </button>
          )}
        </div>
      </div>

      {/* Visual Canvas */}
      {viewMode === 'visual' ? (
        <div
          style={{
            border: '1px solid var(--color-border)',
            borderRadius: 'var(--radius-lg)',
            overflow: 'hidden',
            background: 'var(--color-surface)',
          }}
        >
          <div
            ref={containerRef}
            style={{
              width: '100%',
              height: '520px',
              minHeight: '400px',
              position: 'relative',
            }}
          />
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
            }}
          >
            <span>Click any node to inspect details</span>
            <span>Scroll to zoom</span>
            <span>Drag canvas to pan</span>
          </div>
        </div>
      ) : (
        /* Accessible Text View */
        <div>
          <h2 style={{ fontSize: 'var(--text-base)', fontWeight: 600, marginBottom: 'var(--space-4)' }}>
            Dependency paths (Accessible text view)
          </h2>
          {decisions
            .filter(d => d.exposure.paths.length > 0)
            .slice(0, 25)
            .map(dec => (
              <div key={dec.subject} style={{ marginBottom: 'var(--space-4)' }}>
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 'var(--space-2)',
                    marginBottom: 'var(--space-2)',
                  }}
                >
                  <span className={`verdict-chip verdict-${dec.verdict}`}>
                    {VERDICT_LABELS[dec.verdict as Verdict]}
                  </span>
                  <code className="purl">
                    {dec.name}@{dec.version}
                  </code>
                </div>
                <ol
                  style={{
                    paddingLeft: 'var(--space-6)',
                    fontSize: 'var(--text-xs)',
                    fontFamily: 'var(--font-mono)',
                    lineHeight: 2,
                    color: 'var(--color-muted)',
                  }}
                >
                  {dec.exposure.paths[0]?.map((node, i) => (
                    <li key={i}>
                      {node}
                      {node.includes(dec.name) && dec.exposure.install_phase === 'observed'
                        ? ' ⚠'
                        : ''}
                    </li>
                  ))}
                </ol>
              </div>
            ))}
        </div>
      )}
    </div>
  );
}

export default GraphTab;
