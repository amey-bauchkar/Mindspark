import React, { useState, useEffect, useMemo } from 'react';
import { useParams, Link } from 'react-router-dom';
import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { Shield, ShieldAlert, Share2, Scale, CheckCircle2, FileCode2, Layers, Search, Download, Printer } from 'lucide-react';
import { getReport, exportUrl, ReportRequestError } from '../lib/api';
import { formatDate, saveRecentReport } from '../lib/format';
import { evidenceTimeline } from '../lib/timeline';
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
import { PrintReportModal } from '../components/print/PrintReportModal';
import { PrintReportDocument } from '../components/print/PrintReportDocument';
import { WatchPanel } from '../components/watch/WatchPanel';
import { DownloadReportModal } from '../components/report/DownloadReportModal';

export default function ReportPage() {
  const { id } = useParams<{ id: string }>();
  const [activeTab, setActiveTab] = useState<'decisions' | 'graph' | 'licenses' | 'coverage'>('decisions');
  const [openDecision, setOpenDecision] = useState<Decision | null>(null);
  const [activeVerdicts, setActiveVerdicts] = useState<Set<string>>(new Set());
  const [search, setSearch] = useState('');
  const [groupByPriority, setGroupByPriority] = useState(true);
  const [asOfFilter, setAsOfFilter] = useState<string | null>(null);
  const [printModalOpen, setPrintModalOpen] = useState(false);
  const [pendingStage, setPendingStage] = useState<{ stage: string; progress: number } | null>(null);

  const { data: report, isLoading, error, refetch, isPlaceholderData } = useQuery({
    queryKey: ['report', id, asOfFilter],
    queryFn: () => getReport(id!, asOfFilter || undefined),
    enabled: !!id,
    refetchInterval: false,
    // Keep showing the current report while an as-of view loads (or fails)
    placeholderData: keepPreviousData,
    retry: (count, err) =>
      !(err instanceof ReportRequestError && err.status !== null && err.status < 500) && count < 2,
  });

  // A direct link to an analysis that is still running: show its progress, then load it.
  const notFound = error instanceof ReportRequestError && (error.status === 404 || error.status === null) && !report;
  useEffect(() => {
    if (!notFound || !id) return;
    let stop = false;
    const poll = async () => {
      try {
        const res = await fetch(`/api/reports/${encodeURIComponent(id)}/status`);
        if (!res.ok) return setPendingStage(null);
        const st = await res.json();
        if (stop) return;
        if (st.stage === 'done') {
          setPendingStage(null);
          refetch();
        } else if (!st.error) {
          setPendingStage({ stage: st.stage, progress: st.progress || 0 });
          setTimeout(poll, 1500);
        } else {
          setPendingStage(null);
        }
      } catch {
        setPendingStage(null);
      }
    };
    poll();
    return () => {
      stop = true;
    };
  }, [notFound, id, refetch]);

  const timelineEvents = useMemo(() => (report ? evidenceTimeline(report) : []), [report]);

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
      // Cloud backup of the canonical report only (never an as-of view, never a cloud copy over
      // itself); the remembered Corporate Privacy Mode choice is applied by saveReportToCloud.
      if (!asOfFilter && !isPlaceholderData) {
        saveReportToCloud(report).catch(() => {});
      }
    }
  }, [report, asOfFilter, isPlaceholderData]);

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

  if (!report && pendingStage) {
    return (
      <div className="container" style={{ paddingTop: 'var(--space-12)', textAlign: 'center' }} aria-live="polite">
        <h1 style={{ fontSize: 'var(--text-xl)', fontWeight: 700, marginBottom: 'var(--space-2)' }}>Analysis in progress</h1>
        <p style={{ color: 'var(--color-muted)' }}>
          {pendingStage.stage} · {pendingStage.progress}%
        </p>
      </div>
    );
  }

  if (!report) {
    const status = error instanceof ReportRequestError ? error.status : null;
    const expired = status === 404 || status === null;
    return (
      <div className="container" style={{ paddingTop: 'var(--space-12)', textAlign: 'center' }}>
        <Shield size={48} style={{ color: 'var(--color-border)', margin: '0 auto var(--space-4)' }} aria-hidden />
        <h1 style={{ fontSize: 'var(--text-xl)', fontWeight: 700, marginBottom: 'var(--space-2)' }}>
          {expired ? 'Report not found' : 'Report could not be loaded'}
        </h1>
        <p style={{ color: 'var(--color-muted)', marginBottom: 'var(--space-6)' }}>
          {expired
            ? 'This report has expired or never existed. Reports are kept for 24 hours unless they are monitored by Warrant Watch.'
            : (error as Error | null)?.message || 'The server did not return this report.'}
        </p>
        <div style={{ display: 'flex', gap: 'var(--space-2)', justifyContent: 'center' }}>
          {!expired && (
            <button className="btn btn-secondary" onClick={() => refetch()}>Retry</button>
          )}
          <Link to="/analyze" className="btn btn-primary">Analyze a new lockfile</Link>
        </div>
      </div>
    );
  }

  const { summary, decisions, evidence, licenses, coverage, graph } = report;
  const watchMeta = report.meta.watch as
    | { evidence_as_of: string; detected_at: string; previous_report_id: string; check_status: string; label?: string | null }
    | undefined;
  const replayMeta = report.meta.replay as { label: string; title: string; simulated_clock: string } | undefined;
  const asOfView = report.meta.as_of_view as
    | { rederived: boolean; note: string; applied: string; excluded_evidence_count?: number }
    | undefined;
  const importedMeta = report.meta.imported as { note: string } | undefined;
  const isCloudCopy = Boolean(report.meta.cloud_copy);
  const asOfError = asOfFilter && error ? (error as Error).message : null;

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
      {/* Corporate Report Header */}
      <div className="report-header-section">
        <div className="container">
          <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 'var(--space-4)', flexWrap: 'wrap' }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)', marginBottom: 'var(--space-2)', flexWrap: 'wrap' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <FileCode2 size={22} style={{ color: 'var(--color-accent)' }} aria-hidden />
                  <h1 style={{ fontSize: 'var(--text-xl)', fontWeight: 800, color: 'var(--color-text)', letterSpacing: '-0.02em', margin: 0 }}>
                    {String(report.meta.filename || 'Report')}
                  </h1>
                </div>
                <span className="corporate-ecosystem-tag">
                  {summary.ecosystem}
                </span>
              </div>
              <p style={{ fontSize: 'var(--text-xs)', color: 'var(--color-muted)', display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap' }}>
                <span>{summary.total_packages} packages ({summary.direct_packages} direct)</span>
                <span>·</span>
                <span>As of {formatDate(summary.as_of)}</span>
                <span>·</span>
                <span>Warrant Policy Engine v2.4</span>
              </p>
              {replayMeta && (
                <p className="watch-meta">
                  <span className="watch-sim-badge">{replayMeta.label}</span> {replayMeta.title} · simulated clock{' '}
                  {formatDate(replayMeta.simulated_clock)}
                </p>
              )}
              {watchMeta && (
                <p className="watch-meta">
                  Re-analysis by Warrant Watch · evidence as of {formatDate(watchMeta.evidence_as_of)} · detected{' '}
                  {formatDate(watchMeta.detected_at)} · generated {formatDate(report.created_at)} ·{' '}
                  <Link to={`/report/${watchMeta.previous_report_id}`}>previous analysis</Link>
                </p>
              )}
              {importedMeta && (
                <p className="watch-meta">
                  <span className="nav-badge recorded">IMPORTED</span> {importedMeta.note}
                </p>
              )}
              {isCloudCopy && (
                <p className="watch-meta">
                  <span className="nav-badge recorded">CLOUD COPY</span> Loaded from cloud storage because this server no
                  longer has the report. Time-travel and monitoring need the original analysis.
                </p>
              )}
              {asOfView && (
                <p className={asOfView.rederived ? 'watch-newer' : 'watch-meta'} style={{ marginTop: 'var(--space-2)' }}>
                  <strong>As-of view {formatDate(asOfView.applied)}.</strong> {asOfView.note}
                  {asOfView.rederived && typeof asOfView.excluded_evidence_count === 'number' &&
                    ` ${asOfView.excluded_evidence_count} evidence record(s) were not yet published or already withdrawn at this time.`}
                </p>
              )}
              {asOfError && (
                <p className="watch-check watch-check-failed" role="alert">
                  As-of view unavailable: {asOfError}{' '}
                  <button className="btn btn-ghost btn-sm" onClick={() => setAsOfFilter(null)}>Show latest analysis</button>
                </p>
              )}
            </div>
            <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center', flexWrap: 'wrap' }}>
              {!isCloudCopy && (
                <AsOfSlider
                  currentAsOf={summary.as_of}
                  onApplyAsOf={setAsOfFilter}
                  isLoading={isLoading || isPlaceholderData}
                  events={timelineEvents}
                />
              )}
              <DownloadReportModal report={report} />
              <Link to="/analyze" className="btn btn-ghost btn-sm">New analysis</Link>
            </div>
          </div>

          {/* Executive Security Posture Banner */}
          <div className="executive-posture-card" aria-live="polite">
            <div className="posture-card-header">
              <div className="posture-badge-row">
                <span className="posture-kicker">EXECUTIVE SECURITY POSTURE</span>
                <span className="posture-badge-engine">Engine: Warrant Enterprise v2.4</span>
              </div>
              <div className="posture-headline-row">
                <div className="posture-headline">
                  {summary.incident > 0 ? (
                    <span className="status-indicator status-critical">
                      <span className="status-dot"></span>
                      <strong>{summary.incident} Critical Incident{summary.incident > 1 ? 's' : ''}</strong> Requiring Immediate Isolation
                    </span>
                  ) : summary.act_now > 0 ? (
                    <span className="status-indicator status-high">
                      <span className="status-dot"></span>
                      <strong>{summary.act_now} Urgent Remediation{summary.act_now > 1 ? 's' : ''}</strong> Required
                    </span>
                  ) : summary.upgrade > 0 ? (
                    <span className="status-indicator status-advisory">
                      <span className="status-dot"></span>
                      <strong>{summary.upgrade} Dependency Upgrade{summary.upgrade > 1 ? 's' : ''}</strong> Recommended
                    </span>
                  ) : summary.review > 0 ? (
                    <span className="status-indicator status-review">
                      <span className="status-dot"></span>
                      <strong>{summary.review} Package{summary.review > 1 ? 's' : ''}</strong> Pending Policy Review
                    </span>
                  ) : (
                    <span className="status-indicator status-stable">
                      <span className="status-dot"></span>
                      <strong>Zero Known Vulnerabilities</strong> in Monitored Dependencies
                    </span>
                  )}
                </div>
                <div className="posture-scope-pill">
                  <strong>{summary.total_packages}</strong> packages ({summary.direct_packages} direct)
                </div>
              </div>
            </div>

            <div className="posture-metric-grid">
              {verdictGroups.filter(g => g.count > 0).map(g => {
                const isSelected = activeVerdicts.has(g.verdict);
                return (
                  <button
                    key={g.verdict}
                    type="button"
                    onClick={() => toggleVerdict(g.verdict)}
                    className={`posture-pill posture-pill-${g.verdict.toLowerCase().replace(/_/g, '-')} ${isSelected ? 'selected' : ''}`}
                    title={`Click to filter by ${g.label}`}
                  >
                    <span className="posture-pill-count">{g.count}</span>
                    <span className="posture-pill-label">{g.label}</span>
                  </button>
                );
              })}
            </div>

            <div className="posture-footer">
              <p className="posture-disclaimer">
                Counts reflect unique dependency versions. Cannot-assess items indicate missing policy coverage, not confirmed safety.
              </p>
            </div>
          </div>

          <WatchPanel reportId={report.id} />
        </div>
      </div>

      {/* Tabs: Spreading 100% Horizontally Across the Page Line */}
      <div className="report-tabs-wrapper">
        <div className="container" style={{ paddingLeft: 0, paddingRight: 0 }}>
          <div className="report-tabs" role="tablist" aria-label="Report tabs">
            {[
              { id: 'decisions', label: 'Decisions', count: decisions.length, icon: ShieldAlert },
              { id: 'graph', label: 'Graph', count: null, icon: Share2 },
              { id: 'licenses', label: 'Licenses', count: licenses.length, icon: Scale },
              { id: 'coverage', label: 'Coverage', count: coverage.length, icon: CheckCircle2 },
            ].map(tab => {
              const Icon = tab.icon;
              return (
                <button
                  key={tab.id}
                  role="tab"
                  aria-selected={activeTab === tab.id}
                  aria-controls={`tab-panel-${tab.id}`}
                  id={`tab-${tab.id}`}
                  className={`report-tab-btn${activeTab === tab.id ? ' active' : ''}`}
                  onClick={() => setActiveTab(tab.id as typeof activeTab)}
                >
                  <Icon size={16} className="report-tab-icon" aria-hidden />
                  <span className="report-tab-label">{tab.label}</span>
                  {tab.count !== null && <span className="tab-count">{tab.count}</span>}
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {/* Tab content */}
      <div className="container" style={{ paddingTop: 'var(--space-6)', paddingBottom: 'var(--space-16)' }}>
        {/* Decisions tab */}
        {activeTab === 'decisions' && (
          <div role="tabpanel" id="tab-panel-decisions" aria-labelledby="tab-decisions">
            {/* Filter chips & search */}
            <div className="report-filter-bar">
              <div className="report-filter-chips">
                <span className="filter-bar-label">FILTER FINDINGS:</span>
                {verdictGroups.filter(g => g.count > 0).map(g => (
                  <button
                    key={g.verdict}
                    onClick={() => toggleVerdict(g.verdict)}
                    className={`verdict-chip verdict-${g.verdict} ${activeVerdicts.has(g.verdict) ? 'chip-active' : ''}`}
                    style={{
                      cursor: 'pointer',
                      opacity: activeVerdicts.size === 0 || activeVerdicts.has(g.verdict) ? 1 : 0.45,
                      border: '1px solid',
                      fontWeight: 600,
                      minHeight: 32,
                    }}
                    aria-pressed={activeVerdicts.has(g.verdict)}
                  >
                    {g.label} <span className="chip-count">{g.count}</span>
                  </button>
                ))}
                {activeVerdicts.size > 0 && (
                  <button
                    onClick={() => setActiveVerdicts(new Set())}
                    className="btn btn-ghost btn-sm"
                    style={{ fontSize: '11px', color: 'var(--color-muted)' }}
                  >
                    Reset filters
                  </button>
                )}
              </div>

              <div className="report-filter-controls">
                <button
                  onClick={() => setGroupByPriority(x => !x)}
                  className="btn btn-secondary btn-sm"
                  style={{ fontSize: 'var(--text-xs)', display: 'inline-flex', alignItems: 'center', gap: '6px' }}
                >
                  <Layers size={13} aria-hidden />
                  View: <strong>{groupByPriority ? 'Priority Groups' : 'Flat List'}</strong>
                </button>
                <div className="search-input-wrapper">
                  <Search size={14} className="search-icon" aria-hidden />
                  <input
                    type="search"
                    placeholder="Filter by name…"
                    value={search}
                    onChange={e => setSearch(e.target.value)}
                    className="corporate-search-input"
                    aria-label="Filter decisions by package name"
                  />
                </div>
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

      {/* Print Preview & Configuration Modal */}
      <PrintReportModal
        report={report}
        isOpen={printModalOpen}
        onClose={() => setPrintModalOpen(false)}
      />

      {/* Fallback for direct browser Ctrl+P without modal */}
      <div className="print-only" aria-hidden="true">
        <PrintReportDocument report={report} />
      </div>
    </div>
  );
}
