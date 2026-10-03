import React, { useState, useCallback, useRef, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Upload,
  FileText,
  AlertCircle,
  Clock,
  Shield,
  CheckCircle2,
  Lock,
  Zap,
  Layers,
  ChevronDown,
  ChevronUp,
  FileCode,
  ArrowRight,
  Sparkles,
  RefreshCw,
  Trash2,
  FolderGit2,
  Cloud,
} from 'lucide-react';
import { analyzeFile, analyzeSample, getSamples, getReport } from '../lib/api';
import { useQuery } from '@tanstack/react-query';
import { getRecentReports, formatDateShort } from '../lib/format';
import { ReportReimport } from '../components/analyze/ReportReimport';
import { GitHubRepoAnalyzer } from '../components/analyze/GitHubRepoAnalyzer';
import { getRecentCloudReports, isSupabaseConfigured, saveReportToCloud } from '../lib/supabaseClient';

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
                    {status === 'done' ? '✓' : status === 'current' ? '◉' : ''}
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
    refetchInterval: 5000,
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
  function startPolling(id: string) {
    setAnalysisId(id);
    pollRef.current = setInterval(async () => {
      try {
        const res = await fetch(`http://localhost:8000/api/reports/${id}/status`);
        const data = await res.json();
        setAnalysisStage(data.stage || '');
        setAnalysisProgress(data.progress || 0);
        if (data.error) {
          setAnalysisError(data.error);
          clearInterval(pollRef.current!);
        } else if (data.stage === 'done') {
          clearInterval(pollRef.current!);
          // Background cloud sync
          getReport(id).then(r => saveReportToCloud(r)).catch(() => {});
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
    if (!name.endsWith('.json') && !name.endsWith('.txt')) {
      return 'Unsupported file type. Please upload a .json (package-lock.json) or .txt (requirements.txt) file.';
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

  const [inputMode, setInputMode] = useState<'upload' | 'github'>('upload');

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
      {/* ─── Page Header ────────────────────────────────────────────── */}
      <div className="analyze-header">
        <h1
          style={{
            fontSize: 'clamp(1.75rem, 3vw, 2.5rem)',
            fontWeight: 800,
            letterSpacing: '-0.03em',
            color: 'var(--color-text)',
            marginBottom: 'var(--space-2)',
          }}
        >
          Analyze a lockfile
        </h1>
        <p style={{ fontSize: 'var(--text-base)', color: 'var(--color-muted)', margin: 0 }}>
          Drop your dependency manifest to generate an instant, evidence-backed supply chain decision tree. Files are parsed in memory and not stored.
        </p>
      </div>

      {/* ─── Main 2-Column Full-Screen Grid ─────────────────────────── */}
      <div className="analyze-layout">
        {/* Left Column: Upload Studio & Configurations */}
        <div>
          {/* Input Method Selector (Upload vs GitHub) */}
          <div
            style={{
              display: 'flex',
              gap: 'var(--space-2)',
              marginBottom: 'var(--space-4)',
              borderBottom: '1px solid var(--color-border)',
              paddingBottom: 'var(--space-3)',
            }}
            role="tablist"
            aria-label="Analysis input method"
          >
            <button
              type="button"
              role="tab"
              aria-selected={inputMode === 'upload'}
              className={`btn ${inputMode === 'upload' ? 'btn-primary' : 'btn-ghost'} btn-sm`}
              onClick={() => {
                setInputMode('upload');
                setError('');
              }}
              style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', fontSize: 'var(--text-xs)' }}
            >
              <Upload size={14} aria-hidden />
              <span>Upload Dependency File</span>
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={inputMode === 'github'}
              className={`btn ${inputMode === 'github' ? 'btn-primary' : 'btn-ghost'} btn-sm`}
              onClick={() => {
                setInputMode('github');
                setError('');
              }}
              style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', fontSize: 'var(--text-xs)' }}
            >
              <FolderGit2 size={14} aria-hidden />
              <span>Public GitHub Repository</span>
            </button>
          </div>

          {inputMode === 'upload' ? (
            /* Enhanced Dropzone Studio Card */
            <div
              className={`dropzone-enhanced${dragOver ? ' drag-over' : ''}`}
              onDragOver={e => {
                e.preventDefault();
                setDragOver(true);
              }}
              onDragLeave={() => setDragOver(false)}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
              tabIndex={0}
              role="button"
              aria-label="Drop lockfile here or click to browse"
              onKeyDown={e => e.key === 'Enter' && fileInputRef.current?.click()}
            >
              <input
                ref={fileInputRef}
                type="file"
                accept=".json,.txt"
                style={{ display: 'none' }}
                onChange={handleFileInput}
                aria-hidden
              />

              {!file ? (
                <>
                  <div className="dropzone-icon-circle" aria-hidden="true">
                    <Upload size={28} strokeWidth={2.2} />
                  </div>
                  <h3 style={{ fontSize: 'var(--text-lg)', fontWeight: 700, color: 'var(--color-text)', marginBottom: 'var(--space-1)' }}>
                    Drag & drop your lockfile here
                  </h3>
                  <p style={{ fontSize: 'var(--text-sm)', color: 'var(--color-muted)', marginBottom: 'var(--space-5)' }}>
                    or click anywhere to browse from your device
                  </p>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
                    <span className="btn btn-secondary btn-sm" style={{ pointerEvents: 'none' }}>
                      <FileCode size={14} />
                      <span>Select Manifest (.json / .txt)</span>
                    </span>
                  </div>
                  <p style={{ fontSize: 'var(--text-2xs)', color: 'var(--color-text-light)', marginTop: 'var(--space-4)' }}>
                    Maximum file size: 5 MB · Zero telemetry storage
                  </p>
                </>
              ) : (
                <div
                  style={{ width: '100%', display: 'flex', flexDirection: 'column', alignItems: 'center' }}
                  onClick={e => e.stopPropagation()}
                >
                  <div
                    style={{
                      width: 56,
                      height: 56,
                      borderRadius: 'var(--radius-full)',
                      backgroundColor: '#ECFDF5',
                      color: '#059669',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      marginBottom: 'var(--space-3)',
                    }}
                  >
                    <CheckCircle2 size={28} />
                  </div>
                  <h3 style={{ fontSize: 'var(--text-base)', fontWeight: 700, color: 'var(--color-text)', margin: 0 }}>
                    File Loaded & Validated
                  </h3>
                  <div className="file-selected-box">
                    <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)', minWidth: 0 }}>
                      <FileText size={22} style={{ color: 'var(--color-accent)', flexShrink: 0 }} />
                      <div style={{ textAlign: 'left', minWidth: 0 }}>
                        <p style={{ fontSize: 'var(--text-sm)', fontWeight: 700, margin: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {filename}
                        </p>
                        <p style={{ fontSize: 'var(--text-xs)', color: 'var(--color-muted)', margin: 0 }}>
                          {fileSize} · Ready for analysis
                        </p>
                      </div>
                    </div>
                    <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
                      <button
                        type="button"
                        onClick={() => fileInputRef.current?.click()}
                        className="btn btn-secondary btn-sm"
                      >
                        Change
                      </button>
                      <button
                        type="button"
                        onClick={removeFile}
                        className="btn btn-ghost btn-sm"
                        style={{ color: 'var(--verdict-incident-fg)' }}
                        title="Remove file"
                      >
                        <Trash2 size={15} />
                      </button>
                    </div>
                  </div>
                </div>
              )}
            </div>
          ) : (
            <GitHubRepoAnalyzer
              onSelectFile={handleGitHubFile}
              isAnalyzing={Boolean(analysisId && !analysisError)}
            />
          )}

          {error && (
            <div
              className="callout callout-error"
              style={{ marginTop: 'var(--space-4)', display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}
            >
              <AlertCircle size={18} aria-hidden />
              <span>{error}</span>
            </div>
          )}

          {analysisError && (
            <div className="callout callout-error" style={{ marginTop: 'var(--space-4)' }}>
              <p style={{ fontWeight: 600 }}>Analysis execution error</p>
              <p style={{ fontSize: 'var(--text-sm)', marginTop: 4 }}>{analysisError}</p>
            </div>
          )}

          {/* ─── Context & Corporate Policy Settings (Collapsible Panel) ────────── */}
          <div className="context-panel" style={{ marginTop: 'var(--space-5)' }}>
            <button
              type="button"
              onClick={() => setShowAdvanced(!showAdvanced)}
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                width: '100%',
                background: 'none',
                border: 'none',
                padding: 'var(--space-3)',
                cursor: 'pointer',
                textAlign: 'left',
                borderRadius: 'var(--radius-md)',
                backgroundColor: 'var(--color-surface)',
                borderWidth: 1,
                borderStyle: 'solid',
                borderColor: showAdvanced ? 'var(--color-accent)' : 'var(--color-border)',
              }}
            >
              <div>
                <p style={{ fontSize: 'var(--text-sm)', fontWeight: 700, color: 'var(--color-text)', margin: 0 }}>
                  Advanced Context, Corporate Policies & Banned Dependencies (Optional)
                </p>
                <p style={{ fontSize: 'var(--text-xs)', color: 'var(--color-muted)', margin: 0, marginTop: 2 }}>
                  Enforce Google, Apache, Meta, or Microsoft open-source policies and custom dependency blacklists.
                </p>
              </div>
              <div style={{ color: 'var(--color-muted)' }}>
                {showAdvanced ? <ChevronUp size={18} /> : <ChevronDown size={18} />}
              </div>
            </button>

            {showAdvanced && (
              <div style={{ marginTop: 'var(--space-4)', display: 'flex', flexDirection: 'column', gap: 'var(--space-5)', padding: 'var(--space-4)', backgroundColor: 'var(--color-surface)', borderRadius: 'var(--radius-md)', border: '1px solid var(--color-border)' }}>
                {/* Distribution mode */}
                <div>
                  <label style={{ fontSize: 'var(--text-xs)', fontWeight: 700, color: 'var(--color-text)', display: 'block', marginBottom: 'var(--space-2)' }}>
                    How is this project distributed?
                  </label>
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
                  <label style={{ fontSize: 'var(--text-xs)', fontWeight: 700, color: 'var(--color-text)', display: 'block', marginBottom: 'var(--space-2)' }}>
                    What is your target project license?
                  </label>
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

                {/* Install scripts */}
                <div>
                  <label style={{ fontSize: 'var(--text-xs)', fontWeight: 700, color: 'var(--color-text)', display: 'block', marginBottom: 'var(--space-2)' }}>
                    Do postinstall scripts execute during CI builds?
                  </label>
                  <div className="context-pill-group">
                    {[
                      { val: null, label: 'Not Sure / Default' },
                      { val: true, label: 'Yes (npm install allows scripts)' },
                      { val: false, label: 'No (--ignore-scripts enforced)' },
                    ].map(item => (
                      <div
                        key={String(item.val)}
                        onClick={() => setContext(c => ({ ...c, install_scripts_run: item.val }))}
                        className={`context-pill${context.install_scripts_run === item.val ? ' active' : ''}`}
                      >
                        {item.label}
                      </div>
                    ))}
                  </div>
                </div>

                {/* Corporate Policy */}
                <div>
                  <label style={{ fontSize: 'var(--text-xs)', fontWeight: 700, color: 'var(--color-text)', display: 'block', marginBottom: 'var(--space-2)' }}>
                    Enforce Corporate License Policy (Enterprise Whitelists & Prohibitions)
                  </label>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 'var(--space-2)' }}>
                    {[
                      { id: '', label: 'None / Generic Defaults', desc: 'Standard risk rules without strict corporate bans' },
                      { id: 'google', label: 'Google LLC', desc: 'Strictly bans AGPL, SSPL, JSON & Non-Commercial' },
                      { id: 'apache', label: 'Apache Software Foundation', desc: 'Category X (Bans GPL, AGPL, SSPL, BUSL)' },
                      { id: 'meta', label: 'Meta Platforms (Facebook)', desc: 'Bans AGPL, SSPL, Non-Commercial in production' },
                      { id: 'microsoft', label: 'Microsoft Corporation', desc: 'Bans AGPL, SSPL, Commons Clause in products' },
                    ].map(p => (
                      <div
                        key={p.id || 'none'}
                        onClick={() => setContext(c => ({ ...c, company_policy: p.id }))}
                        style={{
                          padding: 'var(--space-3)',
                          borderRadius: 'var(--radius-md)',
                          border: `1px solid ${context.company_policy === p.id ? 'var(--color-accent)' : 'var(--color-border)'}`,
                          backgroundColor: context.company_policy === p.id ? 'rgba(59, 130, 246, 0.08)' : 'var(--color-surface)',
                          cursor: 'pointer',
                          transition: 'all 0.15s ease',
                        }}
                      >
                        <p style={{ fontSize: 'var(--text-xs)', fontWeight: 700, color: context.company_policy === p.id ? 'var(--color-accent)' : 'var(--color-text)', margin: 0 }}>
                          {p.label}
                        </p>
                        <p style={{ fontSize: '11px', color: 'var(--color-muted)', margin: '2px 0 0', lineHeight: 1.3 }}>
                          {p.desc}
                        </p>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Organization Banned Dependencies */}
                <div>
                  <label htmlFor="banned_dependencies" style={{ fontSize: 'var(--text-xs)', fontWeight: 700, color: 'var(--color-text)', display: 'block', marginBottom: 'var(--space-1)' }}>
                    Organization Banned Dependencies (Optional Blacklist)
                  </label>
                  <p style={{ fontSize: '11px', color: 'var(--color-muted)', margin: '0 0 var(--space-2)' }}>
                    Comma-separated package names strictly prohibited by your security team (e.g. <code>plain-crypto-js, untrusted-lib</code>).
                  </p>
                  <input
                    id="banned_dependencies"
                    type="text"
                    placeholder="e.g. plain-crypto-js, malicious-dep, deprecated-module"
                    value={context.banned_dependencies}
                    onChange={e => setContext(c => ({ ...c, banned_dependencies: e.target.value }))}
                    style={{
                      padding: 'var(--space-2) var(--space-3)',
                      background: 'var(--color-surface)',
                      border: '1px solid var(--color-border)',
                      borderRadius: 'var(--radius-md)',
                      color: 'var(--color-text)',
                      fontSize: 'var(--text-sm)',
                      fontFamily: 'var(--font-mono)',
                      width: '100%',
                    }}
                  />
                </div>
              </div>
            )}
          </div>

          {/* Main Submit Action */}
          {inputMode === 'upload' && (
            <div style={{ marginTop: 'var(--space-6)', display: 'flex', alignItems: 'center', gap: 'var(--space-4)' }}>
              <button
                className="btn btn-primary"
                onClick={submit}
                disabled={!file}
                aria-disabled={!file}
                style={{
                  fontSize: 'var(--text-base)',
                  fontWeight: 700,
                  padding: '12px 28px',
                  borderRadius: 'var(--radius-md)',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '8px',
                  boxShadow: file ? 'var(--shadow-md)' : 'none',
                }}
              >
                <Zap size={18} />
                <span>Analyze Lockfile</span>
                <ArrowRight size={16} />
              </button>
              {!file && (
                <span style={{ fontSize: 'var(--text-xs)', color: 'var(--color-muted)' }}>
                  Select a file above or pick a sample replay below.
                </span>
              )}
            </div>
          )}

          {/* ─── Instant Sample Datasets (Interactive Grid) ────────────── */}
          <div style={{ marginTop: 'var(--space-10)' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 'var(--space-2)' }}>
              <div>
                <h2 style={{ fontSize: 'var(--text-base)', fontWeight: 700, color: 'var(--color-text)', margin: 0, display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <Sparkles size={16} style={{ color: 'var(--color-accent)' }} />
                  <span>Instant Incident Replays & Sample Manifests</span>
                </h2>
                <p style={{ fontSize: 'var(--text-xs)', color: 'var(--color-muted)', marginTop: 2 }}>
                  Test the deterministic decision engine with real-world CVEs, production ecosystems, and supply chain attacks.
                </p>
              </div>
            </div>

            <div className="sample-grid">
              {samplesData?.samples.map(s => {
                const isAxios = s.id === 'axios-replay';
                const isSlack = s.id === 'slack-action';
                const isExpress = s.id.includes('express');
                const isPython = s.id.includes('python');

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
                              ? '#ECFDF5'
                              : isExpress
                              ? 'var(--verdict-upgrade-bg)'
                              : 'var(--verdict-monitor-bg)',
                            color: isAxios
                              ? 'var(--verdict-incident-fg)'
                              : isSlack
                              ? '#059669'
                              : isExpress
                              ? 'var(--verdict-upgrade-fg)'
                              : 'var(--verdict-monitor-fg)',
                            border: `1px solid ${
                              isAxios
                                ? 'var(--verdict-incident-border)'
                                : isSlack
                                ? '#A7F3D0'
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
                          ? '94 Pkgs · Real Production Action'
                          : isExpress
                          ? '77 Pkgs · T1/T2 Risks'
                          : '7 Pkgs · License Engine'}
                      </span>
                      <span style={{ color: 'var(--color-accent)', fontWeight: 700 }}>Run Replay →</span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Re-import Saved Report */}
          <div style={{ marginTop: 'var(--space-6)' }}>
            <ReportReimport />
          </div>
        </div>

        {/* Right Column: Recent Reports History & Security Guarantees */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
          {/* Recent Reports Card */}
          <div className="card" style={{ padding: 'var(--space-5)', borderRadius: 'var(--radius-lg)' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 'var(--space-3)' }}>
              <h2 style={{ fontSize: 'var(--text-sm)', fontWeight: 700, display: 'flex', alignItems: 'center', gap: 'var(--space-2)', margin: 0 }}>
                <Clock size={16} style={{ color: 'var(--color-accent)' }} />
                <span>Recent Analyses</span>
              </h2>
              <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
                {isCloudConnected && (
                  <span
                    style={{
                      fontSize: '10px',
                      fontWeight: 700,
                      padding: '2px 7px',
                      borderRadius: 'var(--radius-full)',
                      backgroundColor: 'var(--color-accent-bg)',
                      color: 'var(--color-accent)',
                      border: '1px solid var(--color-accent-border)',
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '4px',
                    }}
                    title="Live connected to Supabase Cloud database"
                  >
                    <Cloud size={10} />
                    <span>Cloud Synced</span>
                  </span>
                )}
                <span
                  style={{
                    fontSize: 'var(--text-2xs)',
                    fontWeight: 700,
                    padding: '2px 8px',
                    borderRadius: 'var(--radius-full)',
                    backgroundColor: 'var(--color-bg-subtle)',
                    color: 'var(--color-muted)',
                  }}
                >
                  {recentReports.length} {recentReports.length === 1 ? 'Report' : 'Reports'}
                </span>
              </div>
            </div>

            {recentReports.length === 0 ? (
              <div style={{ textAlign: 'center', padding: 'var(--space-5) var(--space-2)' }}>
                <FileText size={24} style={{ color: 'var(--color-border-strong)', margin: '0 auto var(--space-2)' }} />
                <p style={{ fontSize: 'var(--text-xs)', color: 'var(--color-muted)', margin: 0 }}>
                  No recent reports yet.
                  <br />
                  Analyze a lockfile or click a sample to get started.
                </p>
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}>
                {recentReports.map(r => (
                  <a key={r.id} href={`/report/${r.id}`} className="recent-item">
                    <div style={{ minWidth: 0 }}>
                      <p style={{ fontSize: 'var(--text-xs)', fontWeight: 700, margin: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {r.name}
                      </p>
                      <p style={{ fontSize: '11px', color: 'var(--color-muted)', margin: 0, marginTop: 2 }}>
                        {formatDateShort(r.timestamp)} · {r.summary.total_packages} pkgs
                      </p>
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', flexShrink: 0 }}>
                      {r.summary.incident > 0 ? (
                        <span
                          style={{
                            fontSize: '10px',
                            fontWeight: 700,
                            padding: '2px 6px',
                            borderRadius: 'var(--radius-xs)',
                            backgroundColor: 'var(--verdict-incident-bg)',
                            color: 'var(--verdict-incident-fg)',
                            border: '1px solid var(--verdict-incident-border)',
                          }}
                        >
                          {r.summary.incident} Incident{r.summary.incident !== 1 ? 's' : ''}
                        </span>
                      ) : (
                        <span
                          style={{
                            fontSize: '10px',
                            fontWeight: 600,
                            padding: '2px 6px',
                            borderRadius: 'var(--radius-xs)',
                            backgroundColor: 'var(--color-bg-subtle)',
                            color: 'var(--color-muted)',
                          }}
                        >
                          Clean
                        </span>
                      )}
                      <ArrowRight size={13} style={{ color: 'var(--color-muted)' }} />
                    </div>
                  </a>
                ))}
              </div>
            )}
          </div>

          {/* Engine Guarantees & Security Standards */}
          <div
            style={{
              padding: 'var(--space-5)',
              borderRadius: 'var(--radius-lg)',
              backgroundColor: 'var(--color-surface)',
              border: '1px solid var(--color-border)',
              boxShadow: 'var(--shadow-xs)',
            }}
          >
            <h3 style={{ fontSize: 'var(--text-xs)', fontWeight: 800, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--color-text)', marginBottom: 'var(--space-3)' }}>
              Deterministic Engine Guarantees
            </h3>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: 'var(--space-3)' }}>
                <div style={{ width: 22, height: 22, borderRadius: '50%', backgroundColor: 'var(--color-accent-bg)', color: 'var(--color-accent)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0, marginTop: 1 }}>
                  <Lock size={12} />
                </div>
                <div>
                  <p style={{ fontSize: 'var(--text-xs)', fontWeight: 700, color: 'var(--color-text)', margin: 0 }}>
                    100% In-Memory Parsing
                  </p>
                  <p style={{ fontSize: '11px', color: 'var(--color-muted)', margin: 0, marginTop: 1, lineHeight: 1.4 }}>
                    Manifests evaluated purely in volatile RAM. No source code or tokens stored.
                  </p>
                </div>
              </div>

              <div style={{ display: 'flex', alignItems: 'flex-start', gap: 'var(--space-3)' }}>
                <div style={{ width: 22, height: 22, borderRadius: '50%', backgroundColor: 'var(--color-accent-bg)', color: 'var(--color-accent)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0, marginTop: 1 }}>
                  <Shield size={12} />
                </div>
                <div>
                  <p style={{ fontSize: 'var(--text-xs)', fontWeight: 700, color: 'var(--color-text)', margin: 0 }}>
                    Zero Code Execution
                  </p>
                  <p style={{ fontSize: '11px', color: 'var(--color-muted)', margin: 0, marginTop: 1, lineHeight: 1.4 }}>
                    Never runs postinstall hooks or installs npm binaries during graph derivation.
                  </p>
                </div>
              </div>

              <div style={{ display: 'flex', alignItems: 'flex-start', gap: 'var(--space-3)' }}>
                <div style={{ width: 22, height: 22, borderRadius: '50%', backgroundColor: 'var(--color-accent-bg)', color: 'var(--color-accent)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0, marginTop: 1 }}>
                  <Layers size={12} />
                </div>
                <div>
                  <p style={{ fontSize: 'var(--text-xs)', fontWeight: 700, color: 'var(--color-text)', margin: 0 }}>
                    Top-Down Rule Determinism
                  </p>
                  <p style={{ fontSize: '11px', color: 'var(--color-muted)', margin: 0, marginTop: 1, lineHeight: 1.4 }}>
                    Decisions computed from strict priority table (R1–R7) — not black-box scores.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
