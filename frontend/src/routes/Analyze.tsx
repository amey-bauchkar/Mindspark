import React, { useState, useCallback, useRef, useMemo, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Upload,
  FileText,
  AlertCircle,
  Clock,
  Zap,
  ChevronDown,
  ChevronUp,
  FileCode,
  ArrowRight,
  RefreshCw,
  Trash2,
  FolderGit2,
  Cloud,
  FileCheck2,
  Check,
} from 'lucide-react';
import { analyzeFile, analyzeSample, getSamples } from '../lib/api';
import { useQuery } from '@tanstack/react-query';
import { getRecentReports, formatDateShort } from '../lib/format';
import { ReportReimport } from '../components/analyze/ReportReimport';
import { GitHubRepoAnalyzer } from '../components/analyze/GitHubRepoAnalyzer';
import { getRecentCloudReports, isSupabaseConfigured, setCloudPrivacyPrefs } from '../lib/supabaseClient';

type DistMode = 'SaaS' | 'Distributed' | 'Internal' | 'OpenSource' | '';
type ProjLic = 'Proprietary' | 'MIT' | 'Apache-2.0' | 'GPL-3.0-or-later' | '';

interface ContextForm {
  distribution_mode: DistMode;
  project_license: ProjLic;
  install_scripts_run: boolean | null;
  company_policy: string;
  banned_dependencies: string;
}

const STAGES = [
  'Parsing lockfile',
  'Rebuilding graph',
  'Querying OSV',
  'Fetching EPSS and CISA KEV',
  'Checking licenses',
  'Fetching registry metadata',
  'Running signals',
  'Deriving decisions',
  'Classifying licenses',
  'Building graph',
];

function ProgressView({ stage, progress, error }: { stage: string; progress: number; error?: string }) {
  return (
    <div
      className="card"
      style={{
        maxWidth: 580,
        margin: '0 auto',
        padding: 'var(--space-8)',
        borderRadius: 'var(--radius-xl)',
        boxShadow: 'var(--shadow-card-hover)',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)', marginBottom: 'var(--space-4)' }}>
        <div
          style={{
            width: 36,
            height: 36,
            borderRadius: 'var(--radius-full)',
            backgroundColor: 'var(--color-accent-bg)',
            color: 'var(--color-accent)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
          }}
        >
          <RefreshCw size={18} className="spin" />
        </div>
        <div>
          <h2 style={{ fontSize: 'var(--text-lg)', fontWeight: 700, margin: 0 }}>
            Analyzing Supply Chain…
          </h2>
          <p style={{ fontSize: 'var(--text-xs)', color: 'var(--color-muted)', margin: 0 }}>
            Deterministic rule engine execution in progress
          </p>
        </div>
      </div>

      {error ? (
        <div className="callout callout-error" style={{ marginTop: 'var(--space-4)' }}>
          <p style={{ fontWeight: 600 }}>Analysis failed</p>
          <p style={{ marginTop: 'var(--space-1)', fontSize: 'var(--text-sm)' }}>{error}</p>
        </div>
      ) : (
        <>
          <div
            style={{
              height: 6,
              background: 'var(--color-bg-subtle)',
              borderRadius: 3,
              overflow: 'hidden',
              margin: 'var(--space-5) 0 var(--space-6)',
            }}
          >
            <div
              style={{
                height: '100%',
                width: `${progress}%`,
                background: 'linear-gradient(90deg, #0284C7 0%, #0369A1 100%)',
                borderRadius: 3,
                transition: 'width 0.3s ease',
              }}
            />
          </div>

          <ul className="progress-list" aria-live="polite" aria-label="Analysis progress">
            {STAGES.map(s => {
              const idx = STAGES.findIndex(x => stage.includes(x.split(' ')[0]));
              const thisIdx = STAGES.indexOf(s);
              const status = thisIdx < idx ? 'done' : thisIdx === idx ? 'current' : 'pending';
              return (
                <li key={s} className={`progress-item ${status}`}>
                  <span className={`progress-icon ${status}`} aria-hidden>
                    {status === 'done' ? <Check size={12} strokeWidth={2.5} /> : status === 'current' ? <span className="progress-dot" /> : null}
                  </span>
                  <span>{s}</span>
                </li>
              );
            })}
          </ul>

          <div
            style={{
              marginTop: 'var(--space-6)',
              padding: 'var(--space-3) var(--space-4)',
              background: 'var(--color-bg-subtle)',
              borderRadius: 'var(--radius-md)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              fontSize: 'var(--text-xs)',
            }}
          >
            <span style={{ color: 'var(--color-muted)' }}>Current Operation:</span>
            <span style={{ fontWeight: 600, color: 'var(--color-accent)' }}>{stage || 'Initializing…'}</span>
          </div>
        </>
      )}
    </div>
  );
}

export default function Analyze() {
  const navigate = useNavigate();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [dragOver, setDragOver] = useState(false);
  const [file, setFile] = useState<File | null>(null);
  const [filename, setFilename] = useState('');
  const [fileSize, setFileSize] = useState<string>('');
  const [error, setError] = useState('');
  const [analysisId, setAnalysisId] = useState<string | null>(null);
  const [analysisStage, setAnalysisStage] = useState('');
  const [analysisProgress, setAnalysisProgress] = useState(0);
  const [analysisError, setAnalysisError] = useState('');
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [corporatePrivacyMode, setCorporatePrivacyMode] = useState(false);
  const [privateScopeInput, setPrivateScopeInput] = useState('');
  const [tabMode, setTabMode] = useState<'upload' | 'github' | 'samples' | 'import'>('upload');

  const [context, setContext] = useState<ContextForm>({
    distribution_mode: '',
    project_license: '',
    install_scripts_run: null,
    company_policy: '',
    banned_dependencies: '',
  });

  const { data: samplesData } = useQuery({
    queryKey: ['samples'],
    queryFn: getSamples,
  });

  const { data: cloudRecent } = useQuery({
    queryKey: ['cloud-recent-reports'],
    queryFn: () => getRecentCloudReports(10),
    refetchInterval: 30_000,
    enabled: isSupabaseConfigured,
  });

  const localRecent = getRecentReports();
  const recentReports = useMemo(() => {
    if (cloudRecent && cloudRecent.length > 0) {
      const cloudIds = new Set(cloudRecent.map(r => r.id));
      const extraLocal = localRecent.filter(r => !cloudIds.has(r.id));
      return [...cloudRecent, ...extraLocal].slice(0, 10);
    }
    return localRecent;
  }, [cloudRecent, localRecent]);

  const isCloudConnected = Boolean(isSupabaseConfigured);

  // Poll analysis status
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  useEffect(() => () => {
    if (pollRef.current) clearInterval(pollRef.current);
  }, []);

  function startPolling(id: string) {
    setAnalysisId(id);
    setCloudPrivacyPrefs({
      corporatePrivacyMode,
      internalScopePrefixes: privateScopeInput.split(',').map(s => s.trim()).filter(Boolean),
    });
    if (pollRef.current) clearInterval(pollRef.current);
    let misses = 0;
    pollRef.current = setInterval(async () => {
      try {
        const res = await fetch(`/api/reports/${id}/status`);
        if (res.status === 404 || res.status === 429) {
          if (++misses > 40) {
            setAnalysisError('The analysis did not start. Please try again.');
            clearInterval(pollRef.current!);
          }
          return;
        }
        if (!res.ok) {
          setAnalysisError(`Status check failed (${res.status}).`);
          clearInterval(pollRef.current!);
          return;
        }
        const data = await res.json();
        setAnalysisStage(data.stage || '');
        setAnalysisProgress(data.progress || 0);
        if (data.error) {
          setAnalysisError(data.error);
          clearInterval(pollRef.current!);
        } else if (data.stage === 'done') {
          clearInterval(pollRef.current!);
          navigate(`/report/${id}`);
        }
      } catch {
        setAnalysisError('Could not reach the backend — is it running?');
        clearInterval(pollRef.current!);
      }
    }, 700);
  }

  function formatBytes(bytes: number): string {
    if (bytes < 1024) return bytes + ' B';
    else if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / 1048576).toFixed(1) + ' MB';
  }

  function validateFile(f: File): string {
    if (f.size > 5 * 1024 * 1024) return 'File too large (max 5 MB)';
    const name = f.name.toLowerCase();
    if (!name.endsWith('.json') && !name.endsWith('.txt') && !name.endsWith('.lock') && !name.endsWith('.yaml') && !name.endsWith('.yml')) {
      return 'Please upload a lockfile: package-lock.json, yarn.lock, pnpm-lock.yaml, or requirements.txt.';
    }
    return '';
  }

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    const dropped = e.dataTransfer.files[0];
    if (!dropped) return;
    const err = validateFile(dropped);
    if (err) {
      setError(err);
      return;
    }
    setError('');
    setFile(dropped);
    setFilename(dropped.name);
    setFileSize(formatBytes(dropped.size));
  }, []);

  const handleFileInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    const picked = e.target.files?.[0];
    if (!picked) return;
    const err = validateFile(picked);
    if (err) {
      setError(err);
      return;
    }
    setError('');
    setFile(picked);
    setFilename(picked.name);
    setFileSize(formatBytes(picked.size));
  };

  const removeFile = (e: React.MouseEvent) => {
    e.stopPropagation();
    setFile(null);
    setFilename('');
    setFileSize('');
    setError('');
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  async function submit() {
    if (!file) return;
    setError('');
    setAnalysisError('');
    try {
      const ctx: Record<string, unknown> = {};
      if (context.distribution_mode) ctx.distribution_mode = context.distribution_mode;
      if (context.project_license) ctx.project_license = context.project_license;
      if (context.install_scripts_run !== null) ctx.install_scripts_run = context.install_scripts_run;
      if (context.company_policy) ctx.company_policy = context.company_policy;
      if (context.banned_dependencies) {
        ctx.banned_dependencies = context.banned_dependencies.split(',').map(s => s.trim()).filter(Boolean);
      }
      const { report_id } = await analyzeFile(file, ctx);
      startPolling(report_id);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Submit failed');
    }
  }

  async function handleSample(sampleId: string) {
    setError('');
    setAnalysisError('');
    setFile(null);
    setFilename('');
    setFileSize('');
    try {
      const ctx: Record<string, unknown> = {};
      if (context.distribution_mode) ctx.distribution_mode = context.distribution_mode;
      if (context.project_license) ctx.project_license = context.project_license;
      if (context.install_scripts_run !== null) ctx.install_scripts_run = context.install_scripts_run;
      if (context.company_policy) ctx.company_policy = context.company_policy;
      if (context.banned_dependencies) {
        ctx.banned_dependencies = context.banned_dependencies.split(',').map(s => s.trim()).filter(Boolean);
      }
      const { report_id } = await analyzeSample(sampleId, ctx);
      startPolling(report_id);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Could not load sample');
    }
  }

  async function handleGitHubFile(fetchedFile: File, displayPath: string) {
    setError('');
    setAnalysisError('');
    setFile(fetchedFile);
    setFilename(displayPath);
    try {
      const ctx: Record<string, unknown> = {};
      if (context.distribution_mode) ctx.distribution_mode = context.distribution_mode;
      if (context.project_license) ctx.project_license = context.project_license;
      if (context.install_scripts_run !== null) ctx.install_scripts_run = context.install_scripts_run;
      if (context.company_policy) ctx.company_policy = context.company_policy;
      if (context.banned_dependencies) {
        ctx.banned_dependencies = context.banned_dependencies.split(',').map(s => s.trim()).filter(Boolean);
      }
      const { report_id } = await analyzeFile(fetchedFile, ctx);
      startPolling(report_id);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Submit failed');
    }
  }

  if (analysisId && !analysisError) {
    return (
      <div className="analyze-page container" style={{ paddingTop: 'var(--space-16)', paddingBottom: 'var(--space-24)' }}>
        <ProgressView stage={analysisStage} progress={analysisProgress} error={analysisError} />
      </div>
    );
  }

  return (
    <div className="analyze-page container">
      {/* ─── Hero Header (Simple, Authoritative, Focused) ─────────────── */}
      <div className="analyze-hero">
        <div className="analyze-tag-pill">
          <span>DETERMINISTIC SUPPLY CHAIN AUDIT</span>
        </div>
        <h1 className="analyze-title">
          Analyze Software Manifest
        </h1>
        <p className="analyze-desc">
          Drop a lockfile or run a real-world incident replay to evaluate transitive packages against OSV malware records, CISA KEV exploits, and EPSS scores in real time.
        </p>
      </div>

      {/* ─── Central Stage: The Unified Security Studio Card ──────────── */}
      <div className="analyze-studio-card">
        {/* Navigation Tabs Bar */}
        <div className="analyze-tabs-bar" role="tablist">
          <button
            type="button"
            role="tab"
            aria-selected={tabMode === 'upload'}
            className={`analyze-tab-btn ${tabMode === 'upload' ? 'active' : ''}`}
            onClick={() => setTabMode('upload')}
          >
            <Upload size={15} />
            <span>Upload Lockfile</span>
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={tabMode === 'samples'}
            className={`analyze-tab-btn ${tabMode === 'samples' ? 'active' : ''}`}
            onClick={() => setTabMode('samples')}
          >
            <Zap size={15} />
            <span>Attack Replays & Presets</span>
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={tabMode === 'github'}
            className={`analyze-tab-btn ${tabMode === 'github' ? 'active' : ''}`}
            onClick={() => setTabMode('github')}
          >
            <FolderGit2 size={15} />
            <span>GitHub Repository</span>
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={tabMode === 'import'}
            className={`analyze-tab-btn ${tabMode === 'import' ? 'active' : ''}`}
            onClick={() => setTabMode('import')}
          >
            <FileCheck2 size={15} />
            <span>Import Report</span>
          </button>
        </div>

        {/* Tab 1: Upload Lockfile Studio */}
        {tabMode === 'upload' && (
          <div className="analyze-studio-body">
            <div
              className={`dropzone-clean${dragOver ? ' drag-over' : ''}${file ? ' has-file' : ''}`}
              onDragOver={e => {
                e.preventDefault();
                setDragOver(true);
              }}
              onDragLeave={() => setDragOver(false)}
              onDrop={handleDrop}
              onClick={() => !file && fileInputRef.current?.click()}
              tabIndex={0}
              role="button"
              aria-label="Drop lockfile here or click to browse"
            >
              <input
                ref={fileInputRef}
                type="file"
                accept=".json,.txt,.lock,.yaml,.yml"
                style={{ display: 'none' }}
                onChange={handleFileInput}
                aria-hidden
              />

              {!file ? (
                <div className="dropzone-empty-state">
                  <div className="dropzone-icon-box">
                    <Upload size={28} />
                  </div>
                  <h3 className="dropzone-heading">
                    Drag and drop your lockfile here
                  </h3>
                  <p className="dropzone-sub">
                    or click anywhere to browse from your device
                  </p>

                  <div className="dropzone-format-tags">
                    <span className="format-tag">package-lock.json</span>
                    <span className="format-tag">yarn.lock</span>
                    <span className="format-tag">pnpm-lock.yaml</span>
                    <span className="format-tag">requirements.txt</span>
                  </div>

                  <span className="btn btn-secondary btn-sm" style={{ marginTop: 'var(--space-4)' }}>
                    <FileCode size={14} />
                    <span>Browse Files</span>
                  </span>
                </div>
              ) : (
                <div className="file-active-card" onClick={e => e.stopPropagation()}>
                  <div className="file-active-left">
                    <div className="file-success-icon">
                      <Check size={20} strokeWidth={3} />
                    </div>
                    <div>
                      <h4 className="file-active-name">{filename}</h4>
                      <p className="file-active-meta">{fileSize} · Validated Lockfile</p>
                    </div>
                  </div>

                  <div className="file-active-actions">
                    <button
                      type="button"
                      onClick={() => fileInputRef.current?.click()}
                      className="btn btn-ghost btn-sm"
                    >
                      Change
                    </button>
                    <button
                      type="button"
                      onClick={removeFile}
                      className="btn btn-ghost btn-sm file-remove-btn"
                      title="Remove file"
                    >
                      <Trash2 size={14} />
                    </button>
                    <button
                      type="button"
                      onClick={submit}
                      className="btn btn-primary btn-md file-submit-btn"
                    >
                      <Zap size={16} />
                      <span>Run Security Audit →</span>
                    </button>
                  </div>
                </div>
              )}
            </div>

            {/* Quick Sample Presets (For Instant 1-Click Judging & Demos) */}
            <div className="quick-presets-section">
              <span className="quick-presets-label">
                <Zap size={13} style={{ color: 'var(--color-accent)' }} />
                <span>Instant attack replay presets:</span>
              </span>
              <div className="quick-presets-chips">
                <button
                  type="button"
                  className="preset-chip chip-malware"
                  onClick={() => handleSample('axios-replay')}
                  title="Reconstruct the 2026-03-31 Axios supply-chain attack (12 pkgs)"
                >
                  <span className="chip-indicator red" />
                  <span>Axios 2026 Compromise (Replay)</span>
                </button>
                <button
                  type="button"
                  className="preset-chip"
                  onClick={() => handleSample('slack-action')}
                  title="Authentic lockfile from slackapi/slack-github-action (94 pkgs)"
                >
                  <span className="chip-indicator green" />
                  <span>Slack GitHub Action (Real)</span>
                </button>
                <button
                  type="button"
                  className="preset-chip"
                  onClick={() => handleSample('legacy-express')}
                  title="Old Express app with deep transitive dependencies (77 pkgs)"
                >
                  <span className="chip-indicator amber" />
                  <span>Legacy Express App</span>
                </button>
                <button
                  type="button"
                  className="preset-chip"
                  onClick={() => handleSample('python-limited')}
                  title="Python requirements.txt sample (7 pkgs)"
                >
                  <span className="chip-indicator slate" />
                  <span>Python Pip</span>
                </button>
              </div>
            </div>

            {error && (
              <div className="callout callout-error" style={{ marginTop: 'var(--space-4)' }}>
                <AlertCircle size={16} />
                <span>{error}</span>
              </div>
            )}
            {analysisError && (
              <div className="callout callout-error" style={{ marginTop: 'var(--space-4)' }}>
                <span>{analysisError}</span>
              </div>
            )}
          </div>
        )}

        {/* Tab 2: Attack Replays & Samples Grid */}
        {tabMode === 'samples' && (
          <div className="analyze-studio-body">
            <div className="samples-header-strip">
              <h3 className="section-title-sm">Instant Incident Replays & Verified Manifests</h3>
              <p className="section-desc-sm">
                Test the deterministic decision engine with real supply-chain CVEs, active KEV exploits, and authentic production lockfiles.
              </p>
            </div>

            <div className="sample-grid">
              {samplesData?.samples.map(s => {
                const isAxios = s.id === 'axios-replay';
                const isSlack = s.id === 'slack-action';
                const isExpress = s.id.includes('express');

                return (
                  <div
                    key={s.id}
                    onClick={() => handleSample(s.id)}
                    className="sample-card"
                    role="button"
                    tabIndex={0}
                    onKeyDown={e => e.key === 'Enter' && handleSample(s.id)}
                  >
                    <div>
                      <div className="sample-card-header">
                        <span
                          className="tier-badge"
                          style={{
                            fontSize: '10px',
                            fontWeight: 800,
                            padding: '3px 8px',
                            borderRadius: 'var(--radius-sm)',
                            backgroundColor: isAxios
                              ? 'var(--verdict-incident-bg)'
                              : isSlack
                              ? 'var(--license-ok-bg)'
                              : isExpress
                              ? 'var(--verdict-upgrade-bg)'
                              : 'var(--verdict-monitor-bg)',
                            color: isAxios
                              ? 'var(--verdict-incident-fg)'
                              : isSlack
                              ? 'var(--license-ok-fg)'
                              : isExpress
                              ? 'var(--verdict-upgrade-fg)'
                              : 'var(--verdict-monitor-fg)',
                            border: `1px solid ${
                              isAxios
                                ? 'var(--verdict-incident-border)'
                                : isSlack
                                ? 'var(--license-ok-border)'
                                : isExpress
                                ? 'var(--verdict-upgrade-border)'
                                : 'var(--verdict-monitor-border)'
                            }`,
                          }}
                        >
                          {s.badge || (isAxios ? 'MALWARE REPLAY' : isSlack ? '100% REAL' : isExpress ? 'DEEP GRAPH' : 'PYTHON PIP')}
                        </span>
                        <ArrowRight size={14} style={{ color: 'var(--color-muted)' }} />
                      </div>

                      <h3 className="sample-card-title">{s.name}</h3>
                      <p className="sample-card-desc">{s.description}</p>
                    </div>

                    <div className="sample-card-footer">
                      <span>
                        {isAxios
                          ? '12 Pkgs · 2 Incidents'
                          : isSlack
                          ? '94 Pkgs · Real Production'
                          : isExpress
                          ? '77 Pkgs · T1/T2 Risks'
                          : '7 Pkgs · Pip License'}
                      </span>
                      <span style={{ color: 'var(--color-accent)', fontWeight: 700 }}>Run Replay →</span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Tab 3: Public GitHub Repository */}
        {tabMode === 'github' && (
          <div className="analyze-studio-body">
            <GitHubRepoAnalyzer
              onSelectFile={handleGitHubFile}
              isAnalyzing={Boolean(analysisId && !analysisError)}
            />
          </div>
        )}

        {/* Tab 4: Import Saved JSON Report */}
        {tabMode === 'import' && (
          <div className="analyze-studio-body">
            <ReportReimport />
          </div>
        )}
      </div>

      {/* ─── Collapsible Advanced Policies & Corporate Blacklists ─────── */}
      <div className="policy-accordion-container">
        <button
          type="button"
          className="policy-accordion-toggle"
          aria-expanded={showAdvanced}
          onClick={() => setShowAdvanced(!showAdvanced)}
        >
          <div className="policy-toggle-left">
            <span className="policy-toggle-title">
              Corporate Policies & License Compliance (Optional)
            </span>
            <span className="policy-toggle-desc">
              Enforce Google, Apache, Meta, or Microsoft open-source bans and custom dependency blacklists.
            </span>
          </div>
          <div className="policy-toggle-icon">
            {showAdvanced ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
          </div>
        </button>

        {showAdvanced && (
          <div className="policy-accordion-content">
            {/* Distribution mode */}
            <div>
              <label className="policy-label">How is this project distributed?</label>
              <div className="context-pill-group">
                {[
                  { val: '', label: 'Auto (Assume Unknown)' },
                  { val: 'SaaS', label: 'SaaS / Web Service' },
                  { val: 'Distributed', label: 'Distributed Binary / App' },
                  { val: 'Internal', label: 'Internal Tool Only' },
                  { val: 'OpenSource', label: 'Open-Source Library' },
                ].map(item => (
                  <div
                    key={item.val}
                    onClick={() => setContext(c => ({ ...c, distribution_mode: item.val as DistMode }))}
                    className={`context-pill${context.distribution_mode === item.val ? ' active' : ''}`}
                  >
                    {item.label}
                  </div>
                ))}
              </div>
            </div>

            {/* Project License */}
            <div>
              <label className="policy-label">What is your target project license?</label>
              <div className="context-pill-group">
                {[
                  { val: '', label: 'Skip / Unknown' },
                  { val: 'Proprietary', label: 'Proprietary (Closed Source)' },
                  { val: 'MIT', label: 'MIT' },
                  { val: 'Apache-2.0', label: 'Apache 2.0' },
                  { val: 'GPL-3.0-or-later', label: 'GPL v3 or later' },
                ].map(item => (
                  <div
                    key={item.val}
                    onClick={() => setContext(c => ({ ...c, project_license: item.val as ProjLic }))}
                    className={`context-pill${context.project_license === item.val ? ' active' : ''}`}
                  >
                    {item.label}
                  </div>
                ))}
              </div>
            </div>

            {/* Corporate Policy Presets */}
            <div>
              <label className="policy-label">Enforce Corporate Policy Standard</label>
              <div className="policy-grid-presets">
                {[
                  { id: '', label: 'Standard Defaults', desc: 'Standard risk rules without strict corporate bans' },
                  { id: 'google', label: 'Google LLC', desc: 'Strictly bans AGPL, SSPL, JSON & Non-Commercial' },
                  { id: 'apache', label: 'Apache Foundation', desc: 'Category X (Bans GPL, AGPL, SSPL, BUSL)' },
                  { id: 'meta', label: 'Meta Platforms', desc: 'Bans AGPL, SSPL, Non-Commercial in production' },
                  { id: 'microsoft', label: 'Microsoft Corp', desc: 'Bans AGPL, SSPL, Commons Clause' },
                ].map(p => (
                  <div
                    key={p.id || 'none'}
                    onClick={() => setContext(c => ({ ...c, company_policy: p.id }))}
                    className={`policy-preset-box ${context.company_policy === p.id ? 'active' : ''}`}
                  >
                    <p className="policy-preset-title">{p.label}</p>
                    <p className="policy-preset-desc">{p.desc}</p>
                  </div>
                ))}
              </div>
            </div>

            {/* Organization Banned Dependencies */}
            <div>
              <label htmlFor="banned_dependencies" className="policy-label">
                Organization Banned Dependencies (Blacklist)
              </label>
              <input
                id="banned_dependencies"
                type="text"
                placeholder="e.g. plain-crypto-js, malicious-dep, untrusted-lib"
                value={context.banned_dependencies}
                onChange={e => setContext(c => ({ ...c, banned_dependencies: e.target.value }))}
                className="policy-input"
              />
            </div>

            {/* Corporate Privacy Mode (Supabase) */}
            {isSupabaseConfigured && (
              <div className={`corporate-privacy-box ${corporatePrivacyMode ? 'active' : ''}`}>
                <div
                  role="switch"
                  aria-checked={corporatePrivacyMode}
                  tabIndex={0}
                  className="privacy-switch-row"
                  onClick={() => setCorporatePrivacyMode(v => !v)}
                  onKeyDown={e => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault();
                      setCorporatePrivacyMode(v => !v);
                    }
                  }}
                >
                  <div className={`switch-knob ${corporatePrivacyMode ? 'on' : 'off'}`}>
                    <div className="knob-circle" />
                  </div>
                  <div>
                    <p className="privacy-title">Corporate Privacy Mode</p>
                    <p className="privacy-desc">
                      Anonymize proprietary enterprise package scopes (e.g. <code>@internal/*</code>) before cloud sync. Local analysis is unaffected.
                    </p>
                  </div>
                </div>
                {corporatePrivacyMode && (
                  <div style={{ marginTop: 'var(--space-3)' }}>
                    <input
                      type="text"
                      placeholder="e.g. @acme-corp, @internal, @mycompany"
                      value={privateScopeInput}
                      onChange={e => setPrivateScopeInput(e.target.value)}
                      className="policy-input"
                    />
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </div>

      {/* ─── Recent Audits (Clean Minimalist Enterprise History) ───────── */}
      <div className="recent-audits-section">
        <div className="recent-audits-header">
          <div className="recent-audits-title-group">
            <Clock size={16} style={{ color: 'var(--color-accent)' }} />
            <h2 className="recent-audits-title">Recent Audits</h2>
            <span className="recent-count-badge">
              {recentReports.length} {recentReports.length === 1 ? 'Audit' : 'Audits'}
            </span>
          </div>

          {isCloudConnected && (
            <span className="cloud-badge" title="Connected to Supabase Cloud">
              <Cloud size={11} />
              <span>Cloud Synced</span>
            </span>
          )}
        </div>

        {recentReports.length === 0 ? (
          <div className="recent-empty-box">
            <p>No recent reports yet. Drop a lockfile or run a preset attack replay above.</p>
          </div>
        ) : (
          <div className="recent-grid-layout">
            {recentReports.slice(0, 6).map(r => (
              <a key={r.id} href={`/report/${r.id}`} className="recent-audit-card">
                <div className="recent-audit-info">
                  <span className="recent-audit-name">{r.name}</span>
                  <span className="recent-audit-meta">
                    {formatDateShort(r.timestamp)} · {r.summary.total_packages} packages
                  </span>
                </div>
                <div className="recent-audit-status">
                  {r.summary.incident > 0 ? (
                    <span className="audit-tag incident">
                      {r.summary.incident} Incident{r.summary.incident !== 1 ? 's' : ''}
                    </span>
                  ) : (
                    <span className="audit-tag clean">Clean</span>
                  )}
                  <ArrowRight size={14} className="recent-audit-arrow" />
                </div>
              </a>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
