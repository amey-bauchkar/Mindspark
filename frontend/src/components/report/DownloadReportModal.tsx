import React, { useState } from 'react';
import { Download, FileText, Globe, Table, Code, X, Check, ExternalLink } from 'lucide-react';
import type { Report } from '../../lib/types';
import { downloadReportFile, type ExportFormat, getReportBaseFilename } from '../../lib/exportReport';

interface DownloadReportModalProps {
  report: Report;
}

export function DownloadReportModal({ report }: DownloadReportModalProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [downloadedFormat, setDownloadedFormat] = useState<ExportFormat | null>(null);

  const handleDownload = (format: ExportFormat) => {
    downloadReportFile(report, format);
    setDownloadedFormat(format);
    setTimeout(() => {
      setDownloadedFormat(null);
    }, 2500);
  };

  const options: {
    format: ExportFormat;
    title: string;
    extension: string;
    icon: React.ReactNode;
    badge?: string;
    badgeClass?: string;
    description: string;
    details: string;
  }[] = [
    {
      format: 'html',
      title: 'Executive HTML Report',
      extension: '.html',
      icon: <Globe size={20} style={{ color: 'var(--color-accent)' }} />,
      badge: 'Recommended · PDF Ready',
      badgeClass: 'nav-badge live',
      description: 'Fully self-contained, styled executive report. Open in any browser or click Print to save as a professional PDF audit document.',
      details: 'Includes executive KPI summaries, risk badges, evidence quotes, dependency paths, and print styling.',
    },
    {
      format: 'md',
      title: 'Detailed Markdown Report',
      extension: '.md',
      icon: <FileText size={20} style={{ color: '#0284C7' }} />,
      badge: 'GitHub / GitLab / PRs',
      badgeClass: 'nav-badge',
      description: 'Comprehensive markdown report with complete rule derivations, authoritative evidence quotes, dependency chains, and shell fix commands.',
      details: 'Formatted with markdown tables, callout blocks, and bash code snippets.',
    },
    {
      format: 'csv',
      title: 'Security Audit Spreadsheet',
      extension: '.csv',
      icon: <Table size={20} style={{ color: '#16A34A' }} />,
      badge: 'Excel / Sheets / JIRA',
      badgeClass: 'nav-badge',
      description: 'Tabular RFC 4180 audit spreadsheet of all dependencies, versions, verdicts, urgencies, CVEs, and remediation steps.',
      details: 'Ideal for security team reviews, compliance tracking, and ticketing systems.',
    },
    {
      format: 'json',
      title: 'Complete Machine JSON',
      extension: '.json',
      icon: <Code size={20} style={{ color: '#9333EA' }} />,
      badge: 'CI / CD & Tooling',
      badgeClass: 'nav-badge',
      description: 'Full structured JSON schema payload containing all graph nodes, edges, evidence records, and decision derivations.',
      details: 'Can be re-imported into Warrant or used in automation pipelines.',
    },
  ];

  return (
    <>
      {/* Trigger Button in Header */}
      <div style={{ display: 'inline-flex', alignItems: 'center', gap: 'var(--space-1)' }}>
        <button
          type="button"
          onClick={() => setIsOpen(true)}
          className="btn btn-primary btn-sm"
          style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontWeight: 600 }}
          title="Download comprehensive detail report"
        >
          <Download size={14} aria-hidden />
          <span>Download Detail Report</span>
        </button>

        {/* Quick instant HTML download shortcut */}
        <button
          type="button"
          onClick={() => handleDownload('html')}
          className="btn btn-secondary btn-sm"
          title="Quick download as standalone HTML / PDF"
          style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}
        >
          <Globe size={13} aria-hidden />
          <span>HTML</span>
        </button>

        {/* Quick instant Markdown shortcut */}
        <button
          type="button"
          onClick={() => handleDownload('md')}
          className="btn btn-secondary btn-sm"
          title="Quick download as Detailed Markdown"
          style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}
        >
          <FileText size={13} aria-hidden />
          <span>Markdown</span>
        </button>
      </div>

      {/* Modal Dialog */}
      {isOpen && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="download-modal-title"
          style={{
            position: 'fixed',
            inset: 0,
            backgroundColor: 'rgba(15, 23, 42, 0.65)',
            backdropFilter: 'blur(4px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1000,
            padding: 'var(--space-4)',
          }}
          onClick={e => {
            if (e.target === e.currentTarget) setIsOpen(false);
          }}
        >
          <div
            style={{
              background: 'var(--color-surface)',
              border: '1px solid var(--color-border)',
              borderRadius: 'var(--radius-xl, 16px)',
              maxWidth: 720,
              width: '100%',
              maxHeight: '90vh',
              overflowY: 'auto',
              boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.2), 0 10px 10px -5px rgba(0, 0, 0, 0.1)',
              padding: 'var(--space-6)',
              position: 'relative',
              animation: 'fadeIn 0.15s ease-out',
            }}
          >
            {/* Modal Header */}
            <div
              style={{
                display: 'flex',
                alignItems: 'flex-start',
                justifyContent: 'space-between',
                marginBottom: 'var(--space-4)',
                paddingBottom: 'var(--space-4)',
                borderBottom: '1px solid var(--color-border)',
              }}
            >
              <div>
                <h2
                  id="download-modal-title"
                  style={{
                    fontSize: 'var(--text-lg)',
                    fontWeight: 700,
                    color: 'var(--color-text)',
                    margin: 0,
                    display: 'flex',
                    alignItems: 'center',
                    gap: 8,
                  }}
                >
                  <Download size={20} style={{ color: 'var(--color-accent)' }} />
                  Download Detailed Report
                </h2>
                <p style={{ fontSize: 'var(--text-xs)', color: 'var(--color-muted)', margin: '4px 0 0 0' }}>
                  Target: <strong>{String(report.meta.filename || report.meta.sample_name || 'manifest.json')}</strong> · {report.summary.total_packages} packages · Rule-backed deterministic analysis
                </p>
              </div>
              <button
                type="button"
                onClick={() => setIsOpen(false)}
                className="btn btn-ghost btn-sm"
                style={{ padding: 6, borderRadius: '50%' }}
                aria-label="Close dialog"
              >
                <X size={18} />
              </button>
            </div>

            {/* Notification when downloaded */}
            {downloadedFormat && (
              <div
                style={{
                  background: '#F0FDF4',
                  border: '1px solid #BBF7D0',
                  color: '#166534',
                  borderRadius: 'var(--radius-md)',
                  padding: 'var(--space-3) var(--space-4)',
                  fontSize: 'var(--text-xs)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 8,
                  marginBottom: 'var(--space-4)',
                  fontWeight: 600,
                }}
              >
                <Check size={16} />
                Downloaded {getReportBaseFilename(report)}.{downloadedFormat}
              </div>
            )}

            {/* Format Cards */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
              {options.map(opt => {
                const isDownloaded = downloadedFormat === opt.format;

                return (
                  <div
                    key={opt.format}
                    style={{
                      border: '1px solid var(--color-border)',
                      borderRadius: 'var(--radius-lg)',
                      padding: 'var(--space-4)',
                      background: 'var(--color-bg)',
                      display: 'flex',
                      alignItems: 'flex-start',
                      justifyContent: 'space-between',
                      gap: 'var(--space-4)',
                      transition: 'all 0.2s ease',
                    }}
                  >
                    <div style={{ display: 'flex', gap: 'var(--space-3)', alignItems: 'flex-start' }}>
                      <div
                        style={{
                          background: 'var(--color-surface)',
                          border: '1px solid var(--color-border)',
                          borderRadius: 'var(--radius-md)',
                          padding: 10,
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                        }}
                      >
                        {opt.icon}
                      </div>

                      <div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4, flexWrap: 'wrap' }}>
                          <span style={{ fontSize: 'var(--text-sm)', fontWeight: 700, color: 'var(--color-text)' }}>
                            {opt.title}
                          </span>
                          <code style={{ fontSize: '11px', padding: '1px 5px' }}>{opt.extension}</code>
                          {opt.badge && (
                            <span className={opt.badgeClass || 'nav-badge'} style={{ fontSize: '10px' }}>
                              {opt.badge}
                            </span>
                          )}
                        </div>
                        <p style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-secondary)', margin: '0 0 4px 0', lineHeight: 1.4 }}>
                          {opt.description}
                        </p>
                        <p style={{ fontSize: '11px', color: 'var(--color-muted)', margin: 0 }}>
                          {opt.details}
                        </p>
                      </div>
                    </div>

                    <button
                      type="button"
                      onClick={() => handleDownload(opt.format)}
                      className={`btn ${opt.format === 'html' ? 'btn-primary' : 'btn-secondary'} btn-sm`}
                      style={{ whiteSpace: 'nowrap', minWidth: 105, display: 'inline-flex', alignItems: 'center', justifyContent: 'center', gap: 6 }}
                    >
                      {isDownloaded ? (
                        <>
                          <Check size={14} /> Saved
                        </>
                      ) : (
                        <>
                          <Download size={14} /> Download
                        </>
                      )}
                    </button>
                  </div>
                );
              })}
            </div>

            {/* Footer */}
            <div
              style={{
                marginTop: 'var(--space-5)',
                paddingTop: 'var(--space-4)',
                borderTop: '1px solid var(--color-border)',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                flexWrap: 'wrap',
                gap: 8,
              }}
            >
              <span style={{ fontSize: '11px', color: 'var(--color-muted)' }}>
                Deterministic evidence-backed export · As of {new Date(report.summary.as_of).toLocaleDateString()}
              </span>
              <button
                type="button"
                onClick={() => setIsOpen(false)}
                className="btn btn-ghost btn-sm"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}

export default DownloadReportModal;
