import React, { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { Shield, Download } from 'lucide-react';
import { getReport, exportUrl } from '../lib/api';
import { formatDate, saveRecentReport } from '../lib/format';
import { saveReportToCloud } from '../lib/supabaseClient';
import type { Decision, Verdict } from '../lib/types';
import { VERDICT_ORDER } from '../lib/types';

// Modular Feature Components
import { VerdictChip } from '../components/ui/VerdictChip';
import { DecisionDrawer } from '../components/drawer/DecisionDrawer';
import { DecisionCard } from '../components/decisions/DecisionCard';
import { ActionGroups } from '../components/decisions/ActionGroups';
import { GraphTab } from '../components/graph/GraphTab';
import { LicensesTab } from '../components/licenses/LicensesTab';
import { CoverageTab } from '../components/coverage/CoverageTab';
import { AsOfSlider } from '../components/asof/AsOfSlider';

export default function ReportPage() {
  const { id } = useParams<{ id: string }>();
  const [activeTab, setActiveTab] = useState<'decisions' | 'graph' | 'licenses' | 'coverage'>('decisions');
  const [openDecision, setOpenDecision] = useState<Decision | null>(null);
  const [activeVerdicts, setActiveVerdicts] = useState<Set<string>>(new Set());
  const [search, setSearch] = useState('');
  const [groupByPriority, setGroupByPriority] = useState(true);
  const [asOfFilter, setAsOfFilter] = useState<string | null>(null);

  const { data: report, isLoading, error } = useQuery({
    queryKey: ['report', id, asOfFilter],
    queryFn: () => getReport(id!, asOfFilter || undefined),
    enabled: !!id,
    refetchInterval: false,
  });

  // Save to recent reports & sync to Supabase Cloud
  useEffect(() => {
    if (report) {
      saveRecentReport({
        id: report.id,
        name: String(report.meta.filename || 'Report'),
        timestamp: report.created_at,
        summary: {
          incident: report.summary.incident,
          act_now: report.summary.act_now,
          total_packages: report.summary.total_packages,
        },
      });
      // Cloud backup
      saveReportToCloud(report).catch(() => {});
    }
  }, [report]);

  if (isLoading) {
    return (
      <div className="container" style={{ paddingTop: 'var(--space-12)' }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
          {[1, 2, 3].map(i => (
            <div key={i} className="skeleton" style={{ height: 100, borderRadius: 'var(--radius-lg)' }} />
          ))}
        </div>
      </div>
    );
  }

  if (error || !report) {
    return (
      <div className="container" style={{ paddingTop: 'var(--space-12)', textAlign: 'center' }}>
        <Shield size={48} style={{ color: 'var(--color-border)', margin: '0 auto var(--space-4)' }} aria-hidden />
        <h1 style={{ fontSize: 'var(--text-xl)', fontWeight: 700, marginBottom: 'var(--space-2)' }}>Report not found</h1>
        <p style={{ color: 'var(--color-muted)', marginBottom: 'var(--space-6)' }}>
          This report has expired or never existed. Reports are kept for 24 hours.
        </p>
        <Link to="/analyze" className="btn btn-primary">Analyze a new lockfile</Link>
      </div>
    );
  }

  const { summary, decisions, evidence, licenses, coverage, graph } = report;

  // Filter decisions
  const filtered = decisions
    .filter(d => {
      if (activeVerdicts.size > 0 && !activeVerdicts.has(d.verdict)) return false;
      if (
        search &&
        !d.name.toLowerCase().includes(search.toLowerCase()) &&
        !d.subject.toLowerCase().includes(search.toLowerCase())
      ) {
        return false;
      }
      return true;
    })
    .sort((a, b) => (VERDICT_ORDER[a.verdict as Verdict] ?? 99) - (VERDICT_ORDER[b.verdict as Verdict] ?? 99));

  const verdictGroups = [
    { verdict: 'INCIDENT', label: 'Incident', count: summary.incident },
    { verdict: 'ACT_NOW', label: 'Act Now', count: summary.act_now },
    { verdict: 'UPGRADE', label: 'Upgrade', count: summary.upgrade },
    { verdict: 'MONITOR', label: 'Monitor', count: summary.monitor },
    { verdict: 'REVIEW', label: 'Review', count: summary.review },
    { verdict: 'CANNOT_ASSESS', label: 'Cannot Assess', count: summary.cannot_assess },
    { verdict: 'NO_KNOWN_FINDING', label: 'No Known Finding', count: summary.no_known_finding },
  ];

  function toggleVerdict(v: string) {
    setActiveVerdicts(prev => {
      const next = new Set(prev);
      next.has(v) ? next.delete(v) : next.add(v);
      return next;
    });
  }

  return (
    <div>
      {/* Header */}
      <div style={{ background: 'var(--color-surface)', borderBottom: '1px solid var(--color-border)', padding: 'var(--space-6) 0' }}>
        <div className="container">
          <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 'var(--space-4)', flexWrap: 'wrap' }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)', marginBottom: 'var(--space-2)', flexWrap: 'wrap' }}>
                <h1 style={{ fontSize: 'var(--text-lg)', fontWeight: 700 }}>
                  {String(report.meta.filename || 'Report')}
                </h1>
                <span className={`nav-badge ${summary.data_badge === 'LIVE' ? 'live' : 'recorded'}`}>
                  {summary.data_badge}
                </span>
                <span style={{ fontSize: 'var(--text-xs)', color: 'var(--color-muted)' }}>
                  {summary.ecosystem}
                </span>
              </div>
              <p style={{ fontSize: 'var(--text-xs)', color: 'var(--color-muted)' }}>
                {summary.total_packages} packages ({summary.direct_packages} direct) · As of {formatDate(summary.as_of)}
              </p>
            </div>
            <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center', flexWrap: 'wrap' }}>
              <AsOfSlider currentAsOf={summary.as_of} onApplyAsOf={setAsOfFilter} isLoading={isLoading} />
              <a href={exportUrl(report.id, 'json')} download className="btn btn-secondary btn-sm">
                <Download size={14} aria-hidden /> JSON
              </a>
              <a href={exportUrl(report.id, 'md')} download className="btn btn-secondary btn-sm">
                <Download size={14} aria-hidden /> Markdown
              </a>
              <Link to="/analyze" className="btn btn-ghost btn-sm">New analysis</Link>
            </div>
          </div>

          {/* Summary sentence */}
          <div
            style={{
              marginTop: 'var(--space-4)',
              padding: 'var(--space-4)',
              background: 'var(--color-bg)',
              borderRadius: 'var(--radius-md)',
              border: '1px solid var(--color-border)',
            }}
            aria-live="polite"
          >
            <p style={{ fontSize: 'var(--text-lg)', fontWeight: 600, lineHeight: 1.5 }}>
              {summary.incident > 0 && <span style={{ color: 'var(--verdict-incident-fg)' }}>{summary.incident} incident · </span>}
              {summary.act_now > 0 && <span style={{ color: 'var(--verdict-act-now-fg)' }}>{summary.act_now} act now · </span>}
              {summary.upgrade > 0 && <span style={{ color: 'var(--verdict-upgrade-fg)' }}>{summary.upgrade} upgrade · </span>}
              {summary.monitor > 0 && <span style={{ color: 'var(--verdict-monitor-fg)' }}>{summary.monitor} monitor · </span>}
              {summary.review > 0 && <span style={{ color: 'var(--verdict-review-fg)' }}>{summary.review} review · </span>}
              {summary.cannot_assess > 0 && <span>{summary.cannot_assess} cannot assess · </span>}
              <span style={{ color: 'var(--color-muted)' }}>across {summary.total_packages} packages</span>
            </p>
            <p style={{ fontSize: 'var(--text-xs)', color: 'var(--color-muted)', marginTop: 'var(--space-1)' }}>
              Counts are unique package versions. Cannot-assess items are not safe items.
            </p>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div style={{ background: 'var(--color-surface)', borderBottom: '1px solid var(--color-border)', position: 'sticky', top: 'var(--nav-height)', zIndex: 40 }}>
        <div className="container">
          <div className="tabs" role="tablist" aria-label="Report tabs">
            {[
              { id: 'decisions', label: 'Decisions', count: decisions.length },
              { id: 'graph', label: 'Graph', count: null },
              { id: 'licenses', label: 'Licenses', count: licenses.length },
              { id: 'coverage', label: 'Coverage', count: coverage.length },
            ].map(tab => (
              <button
                key={tab.id}
                role="tab"
                aria-selected={activeTab === tab.id}
                aria-controls={`tab-panel-${tab.id}`}
                id={`tab-${tab.id}`}
                className={`tab-btn${activeTab === tab.id ? ' active' : ''}`}
                onClick={() => setActiveTab(tab.id as typeof activeTab)}
              >
                {tab.label}
                {tab.count !== null && <span className="tab-count">{tab.count}</span>}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Tab content */}
      <div className="container" style={{ paddingTop: 'var(--space-6)', paddingBottom: 'var(--space-16)' }}>
        {/* Decisions tab */}
        {activeTab === 'decisions' && (
          <div role="tabpanel" id="tab-panel-decisions" aria-labelledby="tab-decisions">
            {/* Filter chips & search */}
            <div style={{ display: 'flex', gap: 'var(--space-2)', flexWrap: 'wrap', marginBottom: 'var(--space-4)', alignItems: 'center' }}>
              {verdictGroups.filter(g => g.count > 0).map(g => (
                <button
                  key={g.verdict}
                  onClick={() => toggleVerdict(g.verdict)}
                  className={`verdict-chip verdict-${g.verdict}`}
                  style={{
                    cursor: 'pointer',
                    opacity: activeVerdicts.size === 0 || activeVerdicts.has(g.verdict) ? 1 : 0.4,
                    border: '1px solid',
                    fontWeight: 600,
                    minHeight: 32,
                  }}
                  aria-pressed={activeVerdicts.has(g.verdict)}
                >
                  {g.label} {g.count}
                </button>
              ))}

              <div style={{ marginLeft: 'auto', display: 'flex', gap: 'var(--space-2)', alignItems: 'center' }}>
                <button
                  onClick={() => setGroupByPriority(x => !x)}
                  className="btn btn-ghost btn-sm"
                  style={{ fontSize: 'var(--text-xs)' }}
                >
                  View: {groupByPriority ? 'Priority Groups' : 'Flat List'}
                </button>
                <input
                  type="search"
                  placeholder="Filter by name…"
                  value={search}
                  onChange={e => setSearch(e.target.value)}
                  className="input"
                  style={{ maxWidth: 200 }}
                  aria-label="Filter decisions by package name"
                />
              </div>
            </div>

            {filtered.length === 0 ? (
              <div style={{ textAlign: 'center', paddingTop: 'var(--space-12)', color: 'var(--color-muted)' }}>
                <Shield size={48} style={{ margin: '0 auto var(--space-4)', color: 'var(--color-border)' }} aria-hidden />
                <p>No decisions match your filter.</p>
              </div>
            ) : groupByPriority && activeVerdicts.size === 0 && !search ? (
              /* "Do This First" priority groupings (Tanmay's component) */
              <ActionGroups decisions={filtered} onOpenDecision={setOpenDecision} />
            ) : (
              /* Flat list */
              <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
                {filtered.map(dec => (
                  <DecisionCard key={dec.subject} decision={dec} onOpen={setOpenDecision} />
                ))}
              </div>
            )}
          </div>
        )}

        {/* Graph tab (Tanmay's component) */}
        {activeTab === 'graph' && (
          <div role="tabpanel" id="tab-panel-graph" aria-labelledby="tab-graph">
            <GraphTab graph={graph} decisions={decisions} onSelectDecision={setOpenDecision} />
          </div>
        )}

        {/* Licenses tab (Janhavi's component) */}
        {activeTab === 'licenses' && (
          <div role="tabpanel" id="tab-panel-licenses" aria-labelledby="tab-licenses">
            <LicensesTab licenses={licenses} context={report.context} />
          </div>
        )}

        {/* Coverage tab */}
        {activeTab === 'coverage' && (
          <div role="tabpanel" id="tab-panel-coverage" aria-labelledby="tab-coverage">
            <CoverageTab coverage={coverage} />
          </div>
        )}
      </div>

      {/* Decision Drawer (Janhavi's component) */}
      {openDecision && (
        <DecisionDrawer
          decision={openDecision}
          evidence={evidence}
          reportId={report.id}
          onClose={() => setOpenDecision(null)}
        />
      )}
    </div>
  );
}
