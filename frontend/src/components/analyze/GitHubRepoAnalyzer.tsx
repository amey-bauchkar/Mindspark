import React, { useState } from 'react';
import { 
  scanPublicGitHubRepo, 
  fetchRawFileContent, 
  GitHubScanResult, 
  DetectedDependencyFile, 
  GitHubScanError,
  getStoredGitHubToken,
  setStoredGitHubToken
} from './githubClient';
import { 
  FolderGit2, 
  Search, 
  Loader2, 
  AlertCircle, 
  FileCode, 
  GitBranch, 
  ArrowRight, 
  ShieldCheck,
  RotateCcw,
  KeyRound,
  ExternalLink,
  Check
} from 'lucide-react';

interface GitHubRepoAnalyzerProps {
  onSelectFile: (file: File, displayPath: string, repoUrl: string) => void;
  isAnalyzing?: boolean;
}

export function GitHubRepoAnalyzer({ onSelectFile, isAnalyzing = false }: GitHubRepoAnalyzerProps) {
  const [urlInput, setUrlInput] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [scanStage, setScanStage] = useState('');
  const [scanResult, setScanResult] = useState<GitHubScanResult | null>(null);
  const [selectedFilePath, setSelectedFilePath] = useState<string>('');
  const [isFetchingFile, setIsFetchingFile] = useState(false);
  const [error, setError] = useState<string>('');

  const [tokenInput, setTokenInput] = useState(() => getStoredGitHubToken());
  const [showTokenConfig, setShowTokenConfig] = useState(false);
  const [tokenSavedNotice, setTokenSavedNotice] = useState(false);

  const handleSaveToken = (val: string) => {
    setTokenInput(val);
    setStoredGitHubToken(val);
    setTokenSavedNotice(true);
    setTimeout(() => setTokenSavedNotice(false), 2000);
  };

  const handleClearToken = () => {
    setTokenInput('');
    setStoredGitHubToken('');
  };

  const handleScan = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!urlInput.trim()) return;

    setError('');
    setScanResult(null);
    setSelectedFilePath('');
    setIsScanning(true);
    setScanStage('Connecting to GitHub…');

    try {
      const result = await scanPublicGitHubRepo(
        urlInput, 
        stage => setScanStage(stage),
        tokenInput.trim() || undefined
      );

      setScanResult(result);
      if (result.files.length > 0) {
        // Auto-select the first file (usually root file)
        setSelectedFilePath(result.files[0].path);
      }
    } catch (err) {
      if (err instanceof GitHubScanError) {
        setError(err.message);
        if (err.code === 'RATE_LIMITED' || err.code === 'INVALID_TOKEN') {
          setShowTokenConfig(true);
        }
      } else if (err instanceof Error) {
        setError(err.message);
      } else {
        setError('An unexpected error occurred while scanning the repository.');
      }
    } finally {
      setIsScanning(false);
      setScanStage('');
    }
  };

  const handleAnalyzeSelected = async () => {
    if (!scanResult || !selectedFilePath) return;

    const fileMeta = scanResult.files.find(f => f.path === selectedFilePath);
    if (!fileMeta) return;

    setError('');
    setIsFetchingFile(true);

    try {
      // Step: Fetch static raw content via GitHub REST API (Zero Code Execution)
      const rawContent = await fetchRawFileContent(
        scanResult.owner,
        scanResult.repo,
        fileMeta.path,
        fileMeta.branch,
        tokenInput.trim() || undefined
      );

      // Construct standard browser File object representing the fetched dependency file
      // Include owner, repo, and relative path in filename for full audit provenance
      const cleanPath = fileMeta.path.replace(/\//g, '_');
      const safeFileName = `github_${scanResult.owner}_${scanResult.repo}_${cleanPath}`;
      
      const file = new File([rawContent], safeFileName, {
        type: fileMeta.fileName.endsWith('.json') ? 'application/json' : 'text/plain',
      });

      // Save complete audit provenance to sessionStorage for traceability
      try {
        const provenance = {
          source: 'GitHub Repository',
          repository: `${scanResult.owner}/${scanResult.repo}`,
          branch: fileMeta.branch,
          file_path: fileMeta.path,
          fetched_at: new Date().toISOString(),
        };
        sessionStorage.setItem('warrant:provenance', JSON.stringify(provenance));
      } catch {}

      // Hand off to existing Warrant analyzer pipeline
      onSelectFile(file, `${scanResult.owner}/${scanResult.repo}/${fileMeta.path}`, urlInput);
    } catch (err) {
      if (err instanceof GitHubScanError) {
        setError(err.message);
      } else if (err instanceof Error) {
        setError(err.message);
      } else {
        setError(`Failed to retrieve file "${fileMeta.path}".`);
      }
    } finally {
      setIsFetchingFile(false);
    }
  };

  const handleResetScan = () => {
    setScanResult(null);
    setSelectedFilePath('');
    setError('');
  };

  const isLoading = isScanning || isFetchingFile || isAnalyzing;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
      {/* URL Input Form */}
      <form onSubmit={handleScan} style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
        <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
          <div style={{ position: 'relative', flex: 1 }}>
            <div
              style={{
                position: 'absolute',
                left: '12px',
                top: '50%',
                transform: 'translateY(-50%)',
                color: 'var(--color-muted)',
                display: 'flex',
                alignItems: 'center',
              }}
            >
              <FolderGit2 size={16} aria-hidden />
            </div>
            <input
              type="text"
              className="input"
              value={urlInput}
              onChange={e => setUrlInput(e.target.value)}
              placeholder="https://github.com/owner/repository"
              disabled={isLoading}
              style={{
                width: '100%',
                paddingLeft: '36px',
                fontSize: 'var(--text-sm)',
              }}
              aria-label="Public GitHub repository URL"
            />
          </div>
          <button
            type="submit"
            className="btn btn-primary"
            disabled={isLoading || !urlInput.trim()}
            style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', minWidth: '150px', justifyContent: 'center' }}
          >
            {isScanning ? (
              <>
                <Loader2 size={16} className="spinner" aria-hidden />
                <span>Scanning…</span>
              </>
            ) : (
              <>
                <Search size={16} aria-hidden />
                <span>Scan Repository</span>
              </>
            )}
          </button>
        </div>

        {/* Token Configuration Toggle & Panel */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}>
          <div style={{ display: 'flex', justifyContent: 'flex-start', alignItems: 'center' }}>
            <button
              type="button"
              onClick={() => setShowTokenConfig(!showTokenConfig)}
              style={{
                background: 'none',
                border: 'none',
                padding: '2px 4px',
                fontSize: '11px',
                color: tokenInput ? 'var(--color-accent)' : 'var(--color-muted)',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                textDecoration: 'none',
              }}
            >
              <KeyRound size={12} />
              <span>
                {tokenInput
                  ? 'GitHub Token Active (5,000 req/hr unlocked)'
                  : 'Add GitHub Token (Optional — unlocks 5,000 req/hr)'}
              </span>
            </button>
          </div>

          {showTokenConfig && (
            <div
              style={{
                padding: 'var(--space-3) var(--space-4)',
                borderRadius: 'var(--radius-md)',
                background: 'var(--color-bg)',
                border: '1px solid var(--color-border)',
                display: 'flex',
                flexDirection: 'column',
                gap: 'var(--space-2)',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: '11px', fontWeight: 600, color: 'var(--color-text)' }}>
                  GitHub Personal Access Token
                </span>
                <a
                  href="https://github.com/settings/tokens/new?description=Warrant+Analyzer&scopes="
                  target="_blank"
                  rel="noopener noreferrer"
                  style={{
                    fontSize: '11px',
                    color: 'var(--color-accent)',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '4px',
                    textDecoration: 'none',
                  }}
                >
                  Generate Free Token <ExternalLink size={10} />
                </a>
              </div>

              <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
                <input
                  type="password"
                  className="input"
                  value={tokenInput}
                  onChange={e => handleSaveToken(e.target.value)}
                  placeholder="Paste GitHub Personal Access Token (classic or fine-grained)..."
                  disabled={isLoading}
                  style={{
                    flex: 1,
                    fontSize: 'var(--text-xs)',
                    fontFamily: 'monospace',
                  }}
                  aria-label="GitHub Personal Access Token"
                />
                {tokenInput && (
                  <button
                    type="button"
                    onClick={handleClearToken}
                    className="btn btn-ghost btn-sm"
                    style={{ fontSize: '11px' }}
                  >
                    Clear
                  </button>
                )}
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <p style={{ margin: 0, fontSize: '10px', color: 'var(--color-muted)' }}>
                  Unauthenticated scans are limited by GitHub to 60 req/hr per IP. A token increases your limit to 5,000 req/hr (no special permissions required for public repos). Token is stored locally in your browser.
                </p>
                {tokenSavedNotice && (
                  <span style={{ fontSize: '10px', color: 'var(--color-success, #10B981)', display: 'flex', alignItems: 'center', gap: '3px', flexShrink: 0 }}>
                    <Check size={10} /> Saved
                  </span>
                )}
              </div>
            </div>
          )}
        </div>

        {/* Real Loading State Steps */}
        {isScanning && scanStage && (
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 'var(--space-2)',
              fontSize: 'var(--text-xs)',
              color: 'var(--color-accent)',
              padding: '6px 12px',
              borderRadius: 'var(--radius-md)',
              background: 'var(--color-bg)',
              border: '1px solid var(--color-border)',
            }}
          >
            <Loader2 size={14} className="spinner" aria-hidden />
            <span>{scanStage}</span>
          </div>
        )}

        {/* Error Callout */}
        {error && (
          <div
            className="callout callout-error"
            style={{
              display: 'flex',
              alignItems: 'flex-start',
              gap: 'var(--space-2)',
              margin: 0,
            }}
            role="alert"
          >
            <AlertCircle size={16} style={{ flexShrink: 0, marginTop: '2px' }} aria-hidden />
            <div style={{ fontSize: 'var(--text-xs)', lineHeight: 1.5 }}>
              <strong style={{ display: 'block', marginBottom: '2px' }}>Discovery Error</strong>
              {error}
            </div>
          </div>
        )}
      </form>

      {/* Discovery Results & File Selection */}
      {scanResult && (
        <div
          className="card"
          style={{
            padding: 'var(--space-5)',
            border: '1px solid var(--color-border)',
            borderRadius: 'var(--radius-lg)',
            background: 'var(--color-surface)',
          }}
        >
          {/* Repository Header */}
          <div
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'flex-start',
              paddingBottom: 'var(--space-3)',
              marginBottom: 'var(--space-4)',
              borderBottom: '1px solid var(--color-border)',
            }}
          >
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginBottom: '4px' }}>
                <FolderGit2 size={16} style={{ color: 'var(--color-accent)' }} />
                <h3 style={{ fontSize: 'var(--text-base)', fontWeight: 700, margin: 0 }}>
                  {scanResult.owner}/{scanResult.repo}
                </h3>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', fontSize: 'var(--text-xs)', color: 'var(--color-muted)' }}>
                <GitBranch size={13} aria-hidden />
                <span>Branch: <code>{scanResult.activeBranch}</code></span>
                <span>•</span>
                <span>{scanResult.files.length} supported {scanResult.files.length === 1 ? 'file' : 'files'} detected</span>
              </div>
            </div>

            <button
              onClick={handleResetScan}
              className="btn btn-ghost btn-sm"
              title="Scan another repository"
              style={{ fontSize: 'var(--text-xs)', display: 'flex', alignItems: 'center', gap: '4px' }}
            >
              <RotateCcw size={12} />
              <span>Change</span>
            </button>
          </div>

          {/* Multiple files guidance note */}
          {scanResult.files.length > 1 && (
            <div
              style={{
                fontSize: '11px',
                color: 'var(--color-muted)',
                marginBottom: 'var(--space-3)',
                padding: '6px 10px',
                borderRadius: 'var(--radius-sm)',
                background: 'var(--color-bg)',
                border: '1px solid var(--color-border)',
              }}
            >
              Warrant analyzes one dependency file at a time. Select the file you wish to assess:
            </div>
          )}

          {/* File Selection List */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)', marginBottom: 'var(--space-5)' }}>
            {scanResult.files.map(f => {
              const isSelected = selectedFilePath === f.path;
              const formattedSize = f.size ? `${(f.size / 1024).toFixed(1)} KB` : null;

              return (
                <label
                  key={f.path}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    padding: 'var(--space-3) var(--space-4)',
                    borderRadius: 'var(--radius-md)',
                    border: isSelected ? '1px solid var(--color-accent)' : '1px solid var(--color-border)',
                    background: isSelected ? 'var(--color-accent-bg)' : 'var(--color-bg)',
                    cursor: 'pointer',
                    transition: 'border-color 0.15s ease',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)', minWidth: 0 }}>
                    <input
                      type="radio"
                      name="selected_dependency_file"
                      checked={isSelected}
                      onChange={() => setSelectedFilePath(f.path)}
                      style={{ accentColor: 'var(--color-accent)' }}
                      aria-label={`Select ${f.path}`}
                    />
                    <FileCode size={16} style={{ color: isSelected ? 'var(--color-accent)' : 'var(--color-muted)', flexShrink: 0 }} />
                    <div style={{ minWidth: 0 }}>
                      <code style={{ fontSize: 'var(--text-xs)', fontWeight: 600, display: 'block', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {f.path}
                      </code>
                    </div>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', flexShrink: 0 }}>
                    {formattedSize && (
                      <span style={{ fontSize: '11px', color: 'var(--color-muted)' }}>
                        {formattedSize}
                      </span>
                    )}
                    <span
                      style={{
                        fontSize: '10px',
                        fontWeight: 700,
                        padding: '1px 6px',
                        borderRadius: 'var(--radius-sm)',
                        background: f.ecosystem === 'npm' ? 'rgba(239, 68, 68, 0.12)' : 'rgba(59, 130, 246, 0.12)',
                        color: f.ecosystem === 'npm' ? '#DC2626' : '#2563EB',
                        textTransform: 'uppercase',
                      }}
                    >
                      {f.ecosystem}
                    </span>
                  </div>
                </label>
              );
            })}
          </div>

          {/* Action Button */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 'var(--space-3)', flexWrap: 'wrap' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px', color: 'var(--color-muted)' }}>
              <ShieldCheck size={14} style={{ color: 'var(--color-accent)' }} />
              <span>Zero Code Execution: Static dependency file retrieved in memory.</span>
            </div>

            <button
              onClick={handleAnalyzeSelected}
              className="btn btn-primary"
              disabled={isLoading || !selectedFilePath}
              style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', fontSize: 'var(--text-sm)', minWidth: '160px', justifyContent: 'center' }}
            >
              {isFetchingFile ? (
                <>
                  <Loader2 size={14} className="spinner" aria-hidden />
                  <span>Fetching file…</span>
                </>
              ) : isAnalyzing ? (
                <>
                  <Loader2 size={14} className="spinner" aria-hidden />
                  <span>Analyzing…</span>
                </>
              ) : (
                <>
                  <span>Analyze {scanResult.files.length === 1 ? scanResult.files[0].fileName : 'Selected File'}</span>
                  <ArrowRight size={14} aria-hidden />
                </>
              )}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

export default GitHubRepoAnalyzer;
