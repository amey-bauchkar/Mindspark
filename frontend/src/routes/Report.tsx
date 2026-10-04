import React, { useState, useEffect, useMemo } from 'react';
import { useParams, Link } from 'react-router-dom';
import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { Shield, ShieldAlert, AlertTriangle, Share2, Scale, CheckCircle2, FileCode2, Layers, Search, Download, Printer, AlertOctagon, X, RefreshCw } from 'lucide-react';
import { getReport, exportUrl, ReportRequestError, getReportStatusUrl } from '../lib/api';
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
        const res = await fetch(getReportStatusUrl(id));
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
    { verdict: 'INCIDENT', label: 'Malware & Exploits', count: summary.incident },
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

          {/* Executive Security Posture Card */}
          <div className={`executive-posture-card ${summary.incident > 0 ? 'has-incident' : summary.act_now > 0 ? 'has-urgent' : ''}`} aria-live="polite">
            <div className="posture-card-header">
              <div className="posture-header-left">
                <div className="posture-kicker-line">
                  {summary.incident > 0 ? (
                    <span className="posture-status-tag status-incident">
                      <AlertOctagon size={11} aria-hidden /> Critical Threat Detected
                    </span>
                  ) : summary.act_now > 0 ? (
                    <span className="posture-status-tag status-urgent">
                      <ShieldAlert size={11} aria-hidden /> Remediation Required
                    </span>
                  ) : summary.upgrade > 0 ? (
                    <span className="posture-status-tag status-upgrade">
                      <AlertTriangle size={11} aria-hidden /> Upgrades Recommended
                    </span>
                  ) : summary.review > 0 ? (
                    <span className="posture-status-tag status-review">
                      <Shield size={11} aria-hidden /> Policy Review Pending
                    </span>
                  ) : (
                    <span className="posture-status-tag status-clean">
                      <CheckCircle2 size={11} aria-hidden /> All Checks Passed
                    </span>
                  )}
                  <span className="posture-kicker-sep">·</span>
                  <span className="posture-kicker-meta">
                    {summary.ecosystem} Dependencies · {summary.direct_packages} Direct · {summary.total_packages - summary.direct_packages} Transitive · Warrant v2.4
                  </span>
                </div>

                <h2 className="posture-headline">
                  {summary.incident > 0 ? (
                    <>{summary.incident} Critical Incident{summary.incident > 1 ? 's' : ''} Requiring Immediate Isolation</>
                  ) : summary.act_now > 0 ? (
                    <>{summary.act_now} Urgent Remediation{summary.act_now > 1 ? 's' : ''} Required</>
                  ) : summary.upgrade > 0 ? (
                    <>{summary.upgrade} Dependency Upgrade{summary.upgrade > 1 ? 's' : ''} Recommended</>
                  ) : summary.review > 0 ? (
                    <>{summary.review} Package{summary.review > 1 ? 's' : ''} Pending Policy Review</>
                  ) : (
                    <>Zero Known Vulnerabilities in Monitored Dependencies</>
                  )}
                </h2>

                <p className="posture-subtitle">
                  {summary.incident > 0
                    ? `Active backdoors or credential stealers identified in dependencies. Quarantined from deployment pipeline.`
                    : `${summary.total_packages} packages evaluated against Warrant Policy Rules R1–R7 across Code, Build, Deploy & Run.`}
                </p>
              </div>

              {summary.incident > 0 && (
                <div className="posture-header-right">
                  <button
                    type="button"
                    className="posture-threat-action-btn"
                    onClick={() => {
                      setActiveTab('decisions');
                      setActiveVerdicts(new Set(['INCIDENT']));
                    }}
                  >
                    <ShieldAlert size={14} aria-hidden />
                    <span>View {summary.incident} Quarantined Threat{summary.incident > 1 ? 's' : ''} →</span>
                  </button>
                </div>
              )}
            </div>

            {/* Interactive KPI Filter Strip */}
            <div className="posture-kpi-container">
              <div className="posture-kpi-grid">
                {verdictGroups.filter(g => g.count > 0).map(g => {
                  const isSelected = activeVerdicts.has(g.verdict);
                  return (
                    <button
                      key={g.verdict}
                      type="button"
                      onClick={() => toggleVerdict(g.verdict)}
                      className={`posture-kpi-tile tile-${g.verdict.toLowerCase().replace(/_/g, '-')} ${isSelected ? 'selected' : ''}`}
                      aria-pressed={isSelected}
                      title={`Filter findings by ${g.label}`}
                    >
                      <span className="tile-accent-bar" />
                      <div className="tile-body">
                        <span className="tile-count">{g.count}</span>
                        <span className="tile-label">{g.label}</span>
                      </div>
                    </button>
                  );
                })}
              </div>

              {activeVerdicts.size > 0 && (
                <button
                  type="button"
                  onClick={() => setActiveVerdicts(new Set())}
                  className="kpi-reset-btn"
                  title="Clear verdict filters"
                >
                  <X size={12} aria-hidden />
                  Clear filter ({activeVerdicts.size})
                </button>
              )}
            </div>

            <div className="posture-card-footer">
              <span className="posture-footer-text">
                Counts reflect unique dependency versions · Missing policy coverage evaluated as cannot-assess, not confirmed safe.
              </span>
            </div>
          </div>

          <WatchPanel reportId={report.id} />
        </div>
      </div>

      {/* Tabs Sub-Navigation Header: Clean, sticky, flush with top nav (zero gap bleed-through) */}
      <div className="report-tabs-wrapper">
        <div className="container">
          <div className="report-tabs-bar">
            <div className="report-tabs" role="tablist" aria-label="Report tabs">
              {[
                { id: 'decisions', label: 'Findings', count: decisions.length, icon: ShieldAlert },
                { id: 'graph', label: 'Dependency Graph', count: null, icon: Share2 },
                { id: 'licenses', label: 'Licenses', count: licenses.length, icon: Scale },
                { id: 'coverage', label: 'Policy Coverage', count: coverage.length, icon: CheckCircle2 },
              ].map(tab => {
                const Icon = tab.icon;
                const isActive = activeTab === tab.id;
                return (
                  <button
                    key={tab.id}
                    role="tab"
                    aria-selected={isActive}
                    aria-controls={`tab-panel-${tab.id}`}
                    id={`tab-${tab.id}`}
                    className={`report-tab-btn${isActive ? ' active' : ''}`}
                    onClick={() => setActiveTab(tab.id as typeof activeTab)}
                  >
                    <Icon size={14} className="report-tab-icon" aria-hidden />
                    <span className="report-tab-label">{tab.label}</span>
                    {tab.count !== null && <span className="tab-count">{tab.count}</span>}
                  </button>
                );
              })}
            </div>

            {activeTab === 'decisions' && (
              <div className="subnav-controls hide-mobile">
                <div className="subnav-view-toggle">
                  <button
                    type="button"
                    className={`view-toggle-btn ${groupByPriority ? 'active' : ''}`}
                    onClick={() => setGroupByPriority(true)}
                    title="Group findings by urgency"
                  >
                    <Layers size={13} aria-hidden />
                    <span>Priority</span>
                  </button>
                  <button
                    type="button"
                    className={`view-toggle-btn ${!groupByPriority ? 'active' : ''}`}
                    onClick={() => setGroupByPriority(false)}
                    title="Flat list of findings"
                  >
                    <span>Flat</span>
                  </button>
                </div>

                <div className="search-input-wrapper">
                  <Search size={14} className="search-icon" aria-hidden />
                  <input
                    type="search"
                    placeholder="Search package or CVE..."
                    value={search}
                    onChange={e => setSearch(e.target.value)}
                    className="corporate-search-input"
                    aria-label="Filter decisions by package name"
                  />
                  {search && (
                    <button
                      type="button"
                      className="search-clear-btn"
                      onClick={() => setSearch('')}
                      aria-label="Clear search"
                    >
                      <X size={12} aria-hidden />
                    </button>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Tab content */}
      <div className="container" style={{ paddingTop: 'var(--space-6)', paddingBottom: 'var(--space-16)' }}>
        {/* Decisions tab */}
        {activeTab === 'decisions' && (
          <div role="tabpanel" id="tab-panel-decisions" aria-labelledby="tab-decisions">
            {/* Active filter notification pill if any filters are set */}
            {(activeVerdicts.size > 0 || search) && (
              <div className="report-active-filters-banner">
                <div className="active-filters-info">
                  <span className="filters-count-text">
                    Showing <strong>{filtered.length}</strong> of {decisions.length} findings
                  </span>
                  {activeVerdicts.size > 0 && (
                    <span className="filters-tag-list">
                      Filtered by:{' '}
                      {Array.from(activeVerdicts).map(v => (
                        <span key={v} className="filter-active-pill">
                          {v.replace(/_/g, ' ')}
                        </span>
                      ))}
                    </span>
                  )}
                  {search && (
                    <span className="filter-search-tag">
                      Keyword: &ldquo;{search}&rdquo;
                    </span>
                  )}
                </div>
                <button
                  type="button"
                  className="btn btn-ghost btn-sm"
                  onClick={() => {
                    setActiveVerdicts(new Set());
                    setSearch('');
                  }}
                  style={{ fontSize: '11px', color: 'var(--color-muted)' }}
                >
                  Reset all filters
                </button>
              </div>
            )}

            {filtered.length === 0 ? (
              <div style={{ textAlign: 'center', paddingTop: 'var(--space-12)', color: 'var(--color-muted)' }}>
                <Shield size={48} style={{ margin: '0 auto var(--space-4)', color: 'var(--color-border)' }} aria-hidden />
                <p>No decisions match your filter.</p>
              </div>
            ) : groupByPriority && activeVerdicts.size === 0 && !search ? (
              /* "Do This First" priority groupings */
              <ActionGroups decisions={filtered} onOpenDecision={setOpenDecision} />
            ) : (
              /* Flat list */
              <div className="decisions-flat-container">
                <div className="table-header-row hide-mobile">
                  <span className="th-cell">PACKAGE &amp; FINDING</span>
                  <span className="th-cell">SEVERITY</span>
                  <span className="th-cell">INTRODUCED PATH</span>
                  <span className="th-cell">CHECKS &amp; EVIDENCE</span>
                  <span className="th-cell text-right">ACTIONS</span>
                </div>
                <div className="action-group-rows">
                  {filtered.map(dec => (
                    <DecisionCard key={dec.subject} decision={dec} onOpen={setOpenDecision} />
                  ))}
                </div>
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
