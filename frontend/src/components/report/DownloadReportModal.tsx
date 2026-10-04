import React, { useState, useMemo } from 'react';
import { Download, FileText, Globe, Table, Code, X, Check, Eye, Printer, Copy } from 'lucide-react';
import type { Report } from '../../lib/types';
import {
  downloadReportFile,
  printReportAsPdf,
  generateDetailedHtml,
  generateDetailedMarkdown,
  generateDetailedCsv,
  type ExportFormat,
  getReportBaseFilename,
} from '../../lib/exportReport';

interface DownloadReportModalProps {
  report: Report;
}

export function DownloadReportModal({ report }: DownloadReportModalProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [modalTab, setModalTab] = useState<'formats' | 'preview'>('formats');
  const [previewFormat, setPreviewFormat] = useState<'document' | 'markdown' | 'csv'>('document');
  const [downloadedFormat, setDownloadedFormat] = useState<ExportFormat | null>(null);
  const [copied, setCopied] = useState(false);

  const handleDownload = (format: ExportFormat) => {
    downloadReportFile(report, format);
    setDownloadedFormat(format);
    setTimeout(() => {
      setDownloadedFormat(null);
    }, 2500);
  };

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // Pre-generate report views
  const htmlContent = useMemo(() => generateDetailedHtml(report), [report]);
  const markdownContent = useMemo(() => generateDetailedMarkdown(report), [report]);
  const csvContent = useMemo(() => generateDetailedCsv(report), [report]);

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
      format: 'pdf',
      title: 'Executive PDF Audit Report',
      extension: '.pdf',
      icon: <FileText size={20} style={{ color: '#DC2626' }} />,
      badge: 'Print / Save as PDF',
      badgeClass: 'corporate-ecosystem-tag',
      description: 'High-resolution corporate PDF report with executive summary, CVSS scoring breakdown, remediation commands, and license audit.',
      details: 'Pre-formatted for corporate compliance, board decks, and security sign-offs. Triggers browser print-to-PDF.',
    },
    {
      format: 'html',
      title: 'Executive HTML Report',
      extension: '.html',
      icon: <Globe size={20} style={{ color: '#0284C7' }} />,
      badge: 'Standalone Web Document',
      badgeClass: 'corporate-ecosystem-tag',
      description: 'Fully self-contained, interactive executive report. Open in any browser without server dependencies.',
      details: 'Includes executive KPI summaries, risk badges, evidence quotes, dependency paths, and print styling.',
    },
    {
      format: 'md',
      title: 'Detailed Markdown Report',
      extension: '.md',
      icon: <FileText size={20} style={{ color: '#0F172A' }} />,
      badge: 'GitHub / GitLab / PRs',
      badgeClass: 'corporate-ecosystem-tag',
      description: 'Comprehensive markdown report with complete rule derivations, authoritative evidence quotes, dependency chains, and shell fix commands.',
      details: 'Formatted with markdown tables, callout blocks, and bash code snippets.',
    },
    {
      format: 'csv',
      title: 'Security Audit Spreadsheet',
      extension: '.csv',
      icon: <Table size={20} style={{ color: '#16A34A' }} />,
      badge: 'Excel / Sheets / JIRA',
      badgeClass: 'corporate-ecosystem-tag',
      description: 'Tabular RFC 4180 audit spreadsheet of all dependencies, versions, verdicts, urgencies, CVEs, and remediation steps.',
      details: 'Ideal for security team reviews, compliance tracking, and ticketing systems.',
    },
    {
      format: 'json',
      title: 'Complete Machine JSON',
      extension: '.json',
      icon: <Code size={20} style={{ color: '#9333EA' }} />,
      badge: 'CI / CD & Tooling',
      badgeClass: 'corporate-ecosystem-tag',
      description: 'Full structured JSON schema payload containing all graph nodes, edges, evidence records, and decision derivations.',
      details: 'Can be re-imported into Warrant or used in automation pipelines.',
    },
  ];

  return (
    <>
      {/* Trigger Button in Header */}
      <button
        type="button"
        onClick={() => {
          setModalTab('formats');
          setIsOpen(true);
        }}
        className="btn btn-primary btn-sm"
        style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontWeight: 600 }}
        title="Download or preview comprehensive detail report"
      >
        <Download size={14} aria-hidden />
        <span>Download Detail Report</span>
      </button>

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
              maxWidth: modalTab === 'preview' ? 1040 : 720,
              width: '100%',
              maxHeight: '92vh',
              overflowY: 'auto',
              boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.2), 0 10px 10px -5px rgba(0, 0, 0, 0.1)',
              padding: 'var(--space-6)',
              position: 'relative',
              animation: 'fadeIn 0.15s ease-out',
              display: 'flex',
              flexDirection: 'column',
            }}
          >
            {/* Modal Header */}
            <div
              style={{
                display: 'flex',
                alignItems: 'flex-start',
                justifyContent: 'space-between',
                marginBottom: 'var(--space-4)',
                paddingBottom: 'var(--space-3)',
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
                  {modalTab === 'preview' ? (
                    <>
                      <Eye size={20} style={{ color: 'var(--color-accent)' }} />
                      Report Preview &amp; Export
                    </>
                  ) : (
                    <>
                      <Download size={20} style={{ color: 'var(--color-accent)' }} />
                      Download Detailed Report
                    </>
                  )}
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

            {/* Navigation Tabs inside Modal: Formats vs Live Preview */}
            <div
              style={{
                display: 'flex',
                gap: 'var(--space-2)',
                borderBottom: '1px solid var(--color-border)',
                marginBottom: 'var(--space-4)',
              }}
            >
              <button
                type="button"
                onClick={() => setModalTab('formats')}
                style={{
                  padding: '8px 16px',
                  fontSize: 'var(--text-sm)',
                  fontWeight: modalTab === 'formats' ? 700 : 600,
                  color: modalTab === 'formats' ? '#0284C7' : 'var(--color-muted)',
                  border: 'none',
                  background: 'transparent',
                  borderBottom: modalTab === 'formats' ? '3px solid #0284C7' : '3px solid transparent',
                  cursor: 'pointer',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: 6,
                  marginBottom: -1,
                  transition: 'all 0.15s ease',
                }}
              >
                <Download size={15} />
                <span>Export Formats (PDF, HTML, MD, CSV, JSON)</span>
              </button>

              <button
                type="button"
                onClick={() => setModalTab('preview')}
                style={{
                  padding: '8px 16px',
                  fontSize: 'var(--text-sm)',
                  fontWeight: modalTab === 'preview' ? 700 : 600,
                  color: modalTab === 'preview' ? '#0284C7' : 'var(--color-muted)',
                  border: 'none',
                  background: 'transparent',
                  borderBottom: modalTab === 'preview' ? '3px solid #0284C7' : '3px solid transparent',
                  cursor: 'pointer',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: 6,
                  marginBottom: -1,
                  transition: 'all 0.15s ease',
                }}
              >
                <Eye size={15} />
                <span>Live Report Preview</span>
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
                {downloadedFormat === 'pdf' ? (
                  <span>Opening PDF print document for {getReportBaseFilename(report)}.pdf</span>
                ) : (
                  <span>Downloaded {getReportBaseFilename(report)}.{downloadedFormat}</span>
                )}
              </div>
            )}

            {/* TAB 1: FORMATS SELECTION */}
            {modalTab === 'formats' && (
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
                              <span className={opt.badgeClass || 'corporate-ecosystem-tag'} style={{ fontSize: '10px' }}>
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

                      <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)', flexShrink: 0 }}>
                        <button
                          type="button"
                          onClick={() => handleDownload(opt.format)}
                          className={`btn ${opt.format === 'pdf' || opt.format === 'html' ? 'btn-primary' : 'btn-secondary'} btn-sm`}
                          style={{ whiteSpace: 'nowrap', minWidth: 110, display: 'inline-flex', alignItems: 'center', justifyContent: 'center', gap: 6 }}
                        >
                          {isDownloaded ? (
                            <>
                              <Check size={14} /> Ready
                            </>
                          ) : opt.format === 'pdf' ? (
                            <>
                              <Printer size={14} /> Save as PDF
                            </>
                          ) : (
                            <>
                              <Download size={14} /> Download
                            </>
                          )}
                        </button>

                        {(opt.format === 'html' || opt.format === 'pdf' || opt.format === 'md') && (
                          <button
                            type="button"
                            onClick={() => {
                              setModalTab('preview');
                              setPreviewFormat(opt.format === 'md' ? 'markdown' : 'document');
                            }}
                            className="btn btn-ghost btn-sm"
                            style={{ fontSize: '11px', padding: '3px 8px' }}
                          >
                            <Eye size={12} /> Preview
                          </button>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}

            {/* TAB 2: LIVE REPORT PREVIEW */}
            {modalTab === 'preview' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)', flex: 1 }}>
                {/* Preview Toolbar */}
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    flexWrap: 'wrap',
                    gap: 'var(--space-2)',
                    padding: '8px 12px',
                    background: 'var(--color-bg)',
                    borderRadius: 'var(--radius-md)',
                    border: '1px solid var(--color-border)',
                  }}
                >
                  {/* Format switcher */}
                  <div style={{ display: 'inline-flex', alignItems: 'center', gap: 'var(--space-1)' }}>
                    <span style={{ fontSize: '11px', fontWeight: 700, color: 'var(--color-muted)', marginRight: 4 }}>
                      PREVIEW MODE:
                    </span>
                    <button
                      type="button"
                      onClick={() => setPreviewFormat('document')}
                      className={`btn btn-sm ${previewFormat === 'document' ? 'btn-primary' : 'btn-secondary'}`}
                      style={{ fontSize: '12px', padding: '4px 10px', height: 30 }}
                    >
                      <Globe size={13} /> Executive PDF / HTML
                    </button>
                    <button
                      type="button"
                      onClick={() => setPreviewFormat('markdown')}
                      className={`btn btn-sm ${previewFormat === 'markdown' ? 'btn-primary' : 'btn-secondary'}`}
                      style={{ fontSize: '12px', padding: '4px 10px', height: 30 }}
                    >
                      <FileText size={13} /> Markdown
                    </button>
                    <button
                      type="button"
                      onClick={() => setPreviewFormat('csv')}
                      className={`btn btn-sm ${previewFormat === 'csv' ? 'btn-primary' : 'btn-secondary'}`}
                      style={{ fontSize: '12px', padding: '4px 10px', height: 30 }}
                    >
                      <Table size={13} /> Audit Spreadsheet
                    </button>
                  </div>

                  {/* Actions */}
                  <div style={{ display: 'inline-flex', alignItems: 'center', gap: 'var(--space-2)' }}>
                    <button
                      type="button"
                      onClick={() => handleDownload('pdf')}
                      className="btn btn-primary btn-sm"
                      style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}
                      title="Print or Save as PDF"
                    >
                      <Printer size={13} />
                      <span>Print / Save as PDF</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => handleDownload(previewFormat === 'markdown' ? 'md' : previewFormat === 'csv' ? 'csv' : 'html')}
                      className="btn btn-secondary btn-sm"
                      style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}
                    >
                      <Download size={13} />
                      <span>Download {previewFormat === 'markdown' ? '.md' : previewFormat === 'csv' ? '.csv' : '.html'}</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => handleCopy(previewFormat === 'markdown' ? markdownContent : previewFormat === 'csv' ? csvContent : htmlContent)}
                      className="btn btn-secondary btn-sm"
                      style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}
                    >
                      {copied ? <Check size={13} /> : <Copy size={13} />}
                      <span>{copied ? 'Copied!' : 'Copy'}</span>
                    </button>
                  </div>
                </div>

                {/* Preview Viewport */}
                {previewFormat === 'document' && (
                  <div style={{ position: 'relative', border: '1px solid var(--color-border)', borderRadius: 'var(--radius-md)', overflow: 'hidden' }}>
                    <iframe
                      title="Executive Security Audit Report Preview"
                      srcDoc={htmlContent}
                      style={{
                        width: '100%',
                        height: '540px',
                        border: 'none',
                        background: '#FFFFFF',
                        display: 'block',
                      }}
                    />
                  </div>
                )}

                {previewFormat === 'markdown' && (
                  <div
                    style={{
                      border: '1px solid var(--color-border)',
                      borderRadius: 'var(--radius-md)',
                      background: '#0F172A',
                      color: '#F8FAFC',
                      padding: 'var(--space-4)',
                      height: '540px',
                      overflowY: 'auto',
                      fontFamily: 'var(--font-mono)',
                      fontSize: '12px',
                      lineHeight: 1.6,
                      whiteSpace: 'pre-wrap',
                      wordBreak: 'break-word',
                    }}
                  >
                    {markdownContent}
                  </div>
                )}

                {previewFormat === 'csv' && (
                  <div
                    style={{
                      border: '1px solid var(--color-border)',
                      borderRadius: 'var(--radius-md)',
                      background: '#FFFFFF',
                      height: '540px',
                      overflow: 'auto',
                      padding: 'var(--space-2)',
                    }}
                  >
                    <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}>
                      <thead>
                        <tr style={{ background: '#F8FAFC', borderBottom: '2px solid var(--color-border)', textAlign: 'left' }}>
                          <th style={{ padding: '8px 10px' }}>Package</th>
                          <th style={{ padding: '8px 10px' }}>Verdict</th>
                          <th style={{ padding: '8px 10px' }}>Urgency</th>
                          <th style={{ padding: '8px 10px' }}>Scope</th>
                          <th style={{ padding: '8px 10px' }}>Direct</th>
                          <th style={{ padding: '8px 10px' }}>Fixed Version</th>
                          <th style={{ padding: '8px 10px' }}>Remediation Command</th>
                        </tr>
                      </thead>
                      <tbody>
                        {report.decisions.map(dec => (
                          <tr key={dec.subject} style={{ borderBottom: '1px solid var(--color-border)' }}>
                            <td style={{ padding: '6px 10px', fontWeight: 600, fontFamily: 'var(--font-sans)' }}>{dec.name}@{dec.version}</td>
                            <td style={{ padding: '6px 10px' }}>
                              <span className={`verdict-chip verdict-${dec.verdict}`} style={{ fontSize: '10px', padding: '1px 6px' }}>
                                {dec.verdict}
                              </span>
                            </td>
                            <td style={{ padding: '6px 10px' }}>{dec.urgency}</td>
                            <td style={{ padding: '6px 10px' }}>{dec.exposure?.scope || 'prod'}</td>
                            <td style={{ padding: '6px 10px' }}>{dec.is_direct ? 'Yes' : 'No'}</td>
                            <td style={{ padding: '6px 10px', color: dec.fixed_version ? '#16A34A' : '#64748B', fontWeight: 600 }}>
                              {dec.fixed_version || '—'}
                            </td>
                            <td style={{ padding: '6px 10px', fontFamily: 'var(--font-sans)', fontSize: '11px', color: '#334155' }}>
                              {dec.response_steps?.find(s => s.command)?.command || '—'}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            )}

            {/* Footer */}
            <div
              style={{
                marginTop: 'var(--space-4)',
                paddingTop: 'var(--space-3)',
                borderTop: '1px solid var(--color-border)',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                flexWrap: 'wrap',
                gap: 8,
              }}
            >
              <span style={{ fontSize: '11px', color: 'var(--color-muted)' }}>
                Deterministic evidence-backed export · As of {new Date(report.summary.as_of).toLocaleDateString()} · Warrant Enterprise
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
