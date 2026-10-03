import React, { useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { Printer, ArrowLeft, Download, Shield } from 'lucide-react';
import { getReport, exportUrl } from '../lib/api';
import { PrintReportDocument, type PrintOptions } from '../components/print/PrintReportDocument';

export default function PrintReportPage() {
  const { id } = useParams<{ id: string }>();
  const [options, setOptions] = useState<PrintOptions>({
    actionableOnly: false,
    includeLicenses: true,
    includeCoverage: true,
    includeEvidenceDetails: true,
    includePaths: true,
    includeRemediation: true,
  });

  const { data: report, isLoading, error } = useQuery({
    queryKey: ['report', id, 'print'],
    queryFn: () => getReport(id!),
    enabled: !!id,
  });

  if (isLoading) {
    return (
      <div className="container" style={{ paddingTop: 'var(--space-12)', textAlign: 'center' }}>
        <p style={{ color: 'var(--color-muted)' }}>Preparing printable document...</p>
      </div>
    );
  }

  if (error || !report) {
    return (
      <div className="container" style={{ paddingTop: 'var(--space-12)', textAlign: 'center' }}>
        <Shield size={48} style={{ color: 'var(--color-border)', margin: '0 auto var(--space-4)' }} aria-hidden />
        <h1 style={{ fontSize: 'var(--text-xl)', fontWeight: 700, marginBottom: 'var(--space-2)' }}>
          Report not found
        </h1>
        <p style={{ color: 'var(--color-muted)', marginBottom: 'var(--space-6)' }}>
          This report may have expired or does not exist.
        </p>
        <Link to="/analyze" className="btn btn-primary">
          Analyze a new lockfile
        </Link>
      </div>
    );
  }

  return (
    <div className="print-page-wrapper">
      {/* Floating Toolbar - hidden when printed */}
      <div className="print-page-bar no-print">
        <div className="container print-bar-inner">
          <div className="print-bar-left">
            <Link to={`/report/${report.id}`} className="btn btn-secondary btn-sm">
              <ArrowLeft size={14} aria-hidden />
              <span>Back to Interactive Report</span>
            </Link>
            <span className="print-bar-title">
              Printable Audit View: <strong>{String(report.meta.filename || 'Manifest')}</strong>
            </span>
          </div>

          <div className="print-bar-actions">
            <label className="print-inline-option">
              <input
                type="checkbox"
                checked={options.actionableOnly}
                onChange={e => setOptions(o => ({ ...o, actionableOnly: e.target.checked }))}
              />
              <span>Actionable only</span>
            </label>

            <a
              href={exportUrl(report.id, 'html')}
              download={`warrant-report-${report.id.slice(0, 8)}.html`}
              className="btn btn-secondary btn-sm"
              title="Download standalone HTML document"
            >
              <Download size={14} aria-hidden />
              <span>Download HTML</span>
            </a>

            <button
              onClick={() => window.print()}
              className="btn btn-primary btn-sm"
              title="Print document or Save as PDF"
            >
              <Printer size={15} aria-hidden />
              <span>Print / Save as PDF</span>
            </button>
          </div>
        </div>
      </div>

      {/* Main Document Content */}
      <div className="print-page-canvas">
        <div className="print-paper-sheet">
          <PrintReportDocument report={report} options={options} />
        </div>
      </div>
    </div>
  );
}
