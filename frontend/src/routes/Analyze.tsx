import React, { useState, useCallback, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { Upload, FileText, AlertCircle, Clock, ExternalLink } from 'lucide-react';
import { analyzeFile, analyzeSample, getSamples } from '../lib/api';
import { useQuery } from '@tanstack/react-query';
import { getRecentReports, formatDate, formatDateShort } from '../lib/format';
import { ReportReimport } from '../components/analyze/ReportReimport';




type DistMode = 'SaaS' | 'Distributed' | 'Internal' | 'OpenSource' | 'Unknown';
type ProjLic = 'Proprietary' | 'MIT' | 'Apache-2.0' | 'GPL-3.0-or-later' | 'Unknown';

interface ContextForm {
  distribution_mode: DistMode | '';
  project_license: ProjLic | '';
  install_scripts_run: boolean | null;
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
    <div className="card" style={{ maxWidth: 480, margin: '0 auto', marginTop: 'var(--space-8)' }}>
      <h2 style={{ fontSize: 'var(--text-base)', fontWeight: 600, marginBottom: 'var(--space-4)' }}>
        Analyzing…
      </h2>
      {error ? (
        <div className="callout callout-error">
          <p style={{ fontWeight: 500 }}>Analysis failed</p>
          <p style={{ marginTop: 'var(--space-1)', fontSize: 'var(--text-sm)' }}>{error}</p>
        </div>
      ) : (
        <>
          <div
            style={{
              height: 4,
              background: 'var(--color-border)',
              borderRadius: 2,
              overflow: 'hidden',
              marginBottom: 'var(--space-4)',
            }}
          >
            <div
              style={{
                height: '100%',
                width: `${progress}%`,
                background: 'var(--color-accent)',
                borderRadius: 2,
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
                  {s}
                </li>
              );
            })}
          </ul>
          <p style={{ marginTop: 'var(--space-4)', fontSize: 'var(--text-xs)', color: 'var(--color-muted)' }}>
            Current: {stage}
          </p>
        </>
      )}
    </div>
  );
}

export default function Analyze() {
  const navigate = useNavigate();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [dragOver, setDragOver] = useState(false);
  const [file, setFile] = useState<File | string | null>(null);
  const [filename, setFilename] = useState('');
  const [error, setError] = useState('');
  const [analysisId, setAnalysisId] = useState<string | null>(null);
  const [analysisStage, setAnalysisStage] = useState('');
  const [analysisProgress, setAnalysisProgress] = useState(0);
  const [analysisError, setAnalysisError] = useState('');
  const [context, setContext] = useState<ContextForm>({
    distribution_mode: '',
    project_license: '',
    install_scripts_run: null,
  });

  const { data: samplesData } = useQuery({
    queryKey: ['samples'],
    queryFn: getSamples,
  });

  const recentReports = getRecentReports();

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
          navigate(`/report/${id}`);
        }
      } catch {
        setAnalysisError('Could not reach the backend — is it running?');
        clearInterval(pollRef.current!);
      }
    }, 700);
  }

  function validateFile(f: File): string {
    if (f.size > 5 * 1024 * 1024) return 'File too large (max 5 MB)';
    const name = f.name.toLowerCase();
    if (!name.endsWith('.json') && !name.endsWith('.txt')) return 'Unsupported file type (accept .json, .txt)';
    return '';
  }

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    const dropped = e.dataTransfer.files[0];
    if (!dropped) return;
    const err = validateFile(dropped);
    if (err) { setError(err); return; }
    setError('');
    setFile(dropped);
    setFilename(dropped.name);
  }, []);

  const handleFileInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    const picked = e.target.files?.[0];
    if (!picked) return;
    const err = validateFile(picked);
    if (err) { setError(err); return; }
    setError('');
    setFile(picked);
    setFilename(picked.name);
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
    try {
      const { report_id } = await analyzeSample(sampleId, {});
      startPolling(report_id);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Could not load sample');
    }
  }

  if (analysisId && !analysisError) {
    return (
      <div className="container" style={{ paddingTop: 'var(--space-12)', paddingBottom: 'var(--space-16)' }}>
        <ProgressView stage={analysisStage} progress={analysisProgress} error={analysisError} />
      </div>
    );
  }

  return (
    <div className="container" style={{ paddingTop: 'var(--space-10)', paddingBottom: 'var(--space-16)' }}>
      <h1 style={{ fontSize: 'var(--text-xl)', fontWeight: 700, letterSpacing: '-0.02em', marginBottom: 'var(--space-2)' }}>
        Analyze a lockfile
      </h1>
      <p style={{ fontSize: 'var(--text-sm)', color: 'var(--color-muted)', marginBottom: 'var(--space-8)' }}>
        Upload a <code className="purl" style={{ fontSize: 'inherit' }}>package-lock.json</code> (npm v2/v3) or pinned{' '}
        <code className="purl" style={{ fontSize: 'inherit' }}>requirements.txt</code>.
        Files are parsed in memory and not stored.
      </p>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr minmax(260px, 300px)', gap: 'var(--space-8)', alignItems: 'start' }}>
        {/* Main column */}
        <div>
          {/* Dropzone */}
          <div
            className={`dropzone${dragOver ? ' drag-over' : ''}`}
            onDragOver={e => { e.preventDefault(); setDragOver(true); }}
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
            <Upload size={32} style={{ color: 'var(--color-accent)', marginBottom: 'var(--space-4)' }} aria-hidden />
            {file ? (
              <>
                <p style={{ fontWeight: 600, color: 'var(--color-text)' }}>
                  {typeof file === 'string' ? 'Pasted text' : (file as File).name}
                </p>
                <p style={{ fontSize: 'var(--text-sm)', color: 'var(--color-muted)', marginTop: 'var(--space-1)' }}>
                  Click to change
                </p>
              </>
            ) : (
              <>
                <p style={{ fontWeight: 500, color: 'var(--color-text)' }}>
                  Drop your lockfile here
                </p>
                <p style={{ fontSize: 'var(--text-sm)', color: 'var(--color-muted)', marginTop: 'var(--space-1)' }}>
                  or click to browse — .json, .txt — max 5 MB
                </p>
              </>
            )}
          </div>

          {error && (
            <div className="callout callout-error" style={{ marginTop: 'var(--space-3)', display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
              <AlertCircle size={16} aria-hidden />
              {error}
            </div>
          )}

          {analysisError && (
            <div className="callout callout-error" style={{ marginTop: 'var(--space-4)' }}>
              <p style={{ fontWeight: 500 }}>Analysis error</p>
              <p>{analysisError}</p>
            </div>
          )}

          {/* Samples */}
          <div style={{ marginTop: 'var(--space-6)' }}>
            <p style={{ fontSize: 'var(--text-xs)', fontWeight: 600, color: 'var(--color-muted)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 'var(--space-3)' }}>
              Or try a sample
            </p>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}>
              {samplesData?.samples.map(s => (
                <button
                  key={s.id}
                  onClick={() => handleSample(s.id)}
                  className="btn btn-secondary"
                  style={{ justifyContent: 'flex-start', textAlign: 'left' }}
                >
                  <FileText size={16} aria-hidden style={{ flexShrink: 0 }} />
                  <span style={{ flex: 1 }}>
                    <span style={{ fontWeight: 500 }}>{s.name}</span>
                    {s.badge && (
                      <span className="tier-badge tier-T3" style={{ marginLeft: 'var(--space-2)' }}>
                        {s.badge}
                      </span>
                    )}
                    <br />
                    <span style={{ fontSize: 'var(--text-xs)', color: 'var(--color-muted)' }}>{s.description}</span>
                  </span>
                </button>
              ))}
            </div>
          </div>

          {/* Re-import saved report */}
          <ReportReimport />

          {/* Context form */}

          <div style={{ marginTop: 'var(--space-8)' }}>
            <h2 style={{ fontSize: 'var(--text-base)', fontWeight: 600, marginBottom: 'var(--space-1)' }}>
              Context questions
            </h2>
            <p style={{ fontSize: 'var(--text-xs)', color: 'var(--color-muted)', marginBottom: 'var(--space-4)' }}>
              Answers affect license classification. Skipping is fine — we'll note what was assumed.
            </p>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-6)' }}>
              {/* Distribution mode */}
              <fieldset style={{ border: 'none', padding: 0 }}>
                <legend style={{ fontSize: 'var(--text-sm)', fontWeight: 500, marginBottom: 'var(--space-3)' }}>
                  How is this project distributed?
                </legend>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}>
                  {(['SaaS', 'Distributed', 'Internal', 'OpenSource', ''] as const).map((v) => (
                    <label key={v || 'skip'} style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', fontSize: 'var(--text-sm)', cursor: 'pointer' }}>
                      <input
                        type="radio"
                        name="distribution_mode"
                        value={v}
                        checked={context.distribution_mode === v}
                        onChange={() => setContext(c => ({ ...c, distribution_mode: v as DistMode | '' }))}
                        style={{ accentColor: 'var(--color-accent)' }}
                      />
                      {v === '' ? 'Not sure / skip → we\'ll assume Unknown' :
                       v === 'SaaS' ? 'SaaS / network service' :
                       v === 'Distributed' ? 'Distributed app or binary' :
                       v === 'Internal' ? 'Internal tool only' : 'Open-source library'}
                    </label>
                  ))}
                </div>
              </fieldset>

              {/* Project license */}
              <fieldset style={{ border: 'none', padding: 0 }}>
                <legend style={{ fontSize: 'var(--text-sm)', fontWeight: 500, marginBottom: 'var(--space-3)' }}>
                  What is your project's license?
                </legend>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}>
                  {(['Proprietary', 'MIT', 'Apache-2.0', 'GPL-3.0-or-later', ''] as const).map((v) => (
                    <label key={v || 'skip'} style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', fontSize: 'var(--text-sm)', cursor: 'pointer' }}>
                      <input
                        type="radio"
                        name="project_license"
                        value={v}
                        checked={context.project_license === v}
                        onChange={() => setContext(c => ({ ...c, project_license: v as ProjLic | '' }))}
                        style={{ accentColor: 'var(--color-accent)' }}
                      />
                      {v === '' ? 'Not sure / skip' : v}
                    </label>
                  ))}
                </div>
              </fieldset>

              {/* Install scripts */}
              <fieldset style={{ border: 'none', padding: 0 }}>
                <legend style={{ fontSize: 'var(--text-sm)', fontWeight: 500, marginBottom: 'var(--space-3)' }}>
                  Do install scripts run in your CI/dev machines?
                </legend>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}>
                  {[true, false, null].map(v => (
                    <label key={String(v)} style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', fontSize: 'var(--text-sm)', cursor: 'pointer' }}>
                      <input
                        type="radio"
                        name="install_scripts"
                        checked={context.install_scripts_run === v}
                        onChange={() => setContext(c => ({ ...c, install_scripts_run: v }))}
                        style={{ accentColor: 'var(--color-accent)' }}
                      />
                      {v === true ? 'Yes — npm install runs without --ignore-scripts' :
                       v === false ? 'No — scripts are ignored in CI' :
                       'Not sure / skip'}
                    </label>
                  ))}
                </div>
              </fieldset>
            </div>
          </div>

          {/* Submit */}
          <div style={{ marginTop: 'var(--space-8)' }}>
            <button
              className="btn btn-primary"
              onClick={submit}
              disabled={!file}
              aria-disabled={!file}
              style={{ fontSize: 'var(--text-base)', padding: 'var(--space-3) var(--space-6)' }}
            >
              Analyze
            </button>
            {!file && (
              <p style={{ marginTop: 'var(--space-2)', fontSize: 'var(--text-xs)', color: 'var(--color-muted)' }}>
                Drop or select a lockfile to enable analysis.
              </p>
            )}
          </div>
        </div>

        {/* Sidebar — recent reports */}
        <div>
          <div className="card">
            <h2 style={{ fontSize: 'var(--text-sm)', fontWeight: 600, marginBottom: 'var(--space-4)', display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
              <Clock size={16} aria-hidden /> Recent reports
            </h2>
            {recentReports.length === 0 ? (
              <p style={{ fontSize: 'var(--text-sm)', color: 'var(--color-muted)' }}>
                No recent reports — analyze a lockfile to get started.
              </p>
            ) : (
              <ul style={{ listStyle: 'none', display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
                {recentReports.map(r => (
                  <li key={r.id}>
                    <a
                      href={`/report/${r.id}`}
                      style={{ display: 'block', textDecoration: 'none', color: 'inherit' }}
                    >
                      <p style={{ fontSize: 'var(--text-sm)', fontWeight: 500 }}>{r.name}</p>
                      <p style={{ fontSize: 'var(--text-xs)', color: 'var(--color-muted)' }}>
                        {formatDateShort(r.timestamp)} · {r.summary.total_packages} pkgs
                        {r.summary.incident > 0 && (
                          <span style={{ color: 'var(--verdict-incident-fg)', marginLeft: 'var(--space-1)' }}>
                            · {r.summary.incident} incident{r.summary.incident !== 1 ? 's' : ''}
                          </span>
                        )}
                      </p>
                    </a>
                  </li>
                ))}
              </ul>
            )}
          </div>

          <div className="callout callout-info" style={{ marginTop: 'var(--space-4)' }}>
            <p style={{ fontSize: 'var(--text-xs)', fontWeight: 500, marginBottom: 'var(--space-1)' }}>
              Privacy note
            </p>
            <p style={{ fontSize: 'var(--text-xs)', color: 'var(--color-muted)' }}>
              Uploaded files are parsed in memory and not stored. Only the derived report is kept for 24 hours. No account required.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
