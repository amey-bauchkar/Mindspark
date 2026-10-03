import React, { useState } from 'react';
import { Printer, Download, ExternalLink, X, Settings2, Eye } from 'lucide-react';
import type { Report } from '../../lib/types';
import { PrintReportDocument, type PrintOptions } from './PrintReportDocument';
import { exportUrl } from '../../lib/api';

interface PrintReportModalProps {
  report: Report;
  isOpen: boolean;
  onClose: () => void;
}

export function PrintReportModal({ report, isOpen, onClose }: PrintReportModalProps) {
  const [options, setOptions] = useState<PrintOptions>({
    actionableOnly: false,
    includeLicenses: true,
    includeCoverage: true,
    includeEvidenceDetails: true,
    includePaths: true,
    includeRemediation: true,
  });

  if (!isOpen) return null;

  const handlePrint = () => {
    window.print();
  };

  const handleOpenStandalone = () => {
    window.open(`/report/${report.id}/print`, '_blank');
  };

  return (
    <div className="print-modal-overlay" role="dialog" aria-modal="true" aria-labelledby="print-modal-title">
      <div className="print-modal-container">
        {/* Modal Top Bar (Never printed) */}
        <div className="print-modal-header no-print">
          <div className="print-modal-header-left">
            <div className="print-modal-icon-badge">
              <Printer size={20} aria-hidden="true" />
            </div>
            <div>
              <h2 id="print-modal-title" style={{ fontSize: 'var(--text-base)', fontWeight: 700, margin: 0 }}>
                Print & Export Detailed Report
              </h2>
              <p style={{ fontSize: 'var(--text-xs)', color: 'var(--color-muted)', margin: 0 }}>
                Formatted executive summary, findings, evidence citations, and license compliance table.
              </p>
            </div>
          </div>

          <div className="print-modal-header-actions">
            <button
              onClick={handlePrint}
              className="btn btn-primary btn-sm"
              title="Open browser print / Save as PDF"
            >
              <Printer size={15} aria-hidden />
              <span>Print / Save as PDF</span>
            </button>

            <a
              href={exportUrl(report.id, 'html')}
              download={`warrant-report-${report.id.slice(0, 8)}.html`}
              className="btn btn-secondary btn-sm"
              title="Download standalone HTML document"
            >
              <Download size={14} aria-hidden />
              <span>HTML File</span>
            </a>

            <button
              onClick={handleOpenStandalone}
              className="btn btn-secondary btn-sm"
              title="Open clean printable view in a new tab"
            >
              <ExternalLink size={14} aria-hidden />
              <span>Full Page View</span>
            </button>

            <button
              onClick={onClose}
              className="btn btn-ghost btn-icon btn-sm"
              aria-label="Close print modal"
            >
              <X size={18} aria-hidden />
            </button>
          </div>
        </div>

        {/* Modal Configuration Toolbar (Never printed) */}
        <div className="print-modal-toolbar no-print">
          <div className="print-options-group">
            <span className="print-options-title">
              <Settings2 size={14} aria-hidden />
              <span>Content Options:</span>
            </span>

            <label className="print-checkbox-label">
              <input
                type="checkbox"
                checked={options.actionableOnly}
                onChange={e => setOptions(o => ({ ...o, actionableOnly: e.target.checked }))}
              />
              <span>Actionable findings only ({report.summary.incident + report.summary.act_now + report.summary.upgrade + report.summary.review})</span>
            </label>

            <label className="print-checkbox-label">
              <input
                type="checkbox"
                checked={options.includeLicenses}
                onChange={e => setOptions(o => ({ ...o, includeLicenses: e.target.checked }))}
              />
              <span>Licenses table ({report.licenses?.length ?? 0})</span>
            </label>

            <label className="print-checkbox-label">
              <input
                type="checkbox"
                checked={options.includeCoverage}
                onChange={e => setOptions(o => ({ ...o, includeCoverage: e.target.checked }))}
              />
              <span>Coverage checklist ({report.coverage?.length ?? 0})</span>
            </label>

            <label className="print-checkbox-label">
              <input
                type="checkbox"
                checked={options.includeEvidenceDetails}
                onChange={e => setOptions(o => ({ ...o, includeEvidenceDetails: e.target.checked }))}
              />
              <span>Evidence quotes & links</span>
            </label>

            <label className="print-checkbox-label">
              <input
                type="checkbox"
                checked={options.includeRemediation}
                onChange={e => setOptions(o => ({ ...o, includeRemediation: e.target.checked }))}
              />
              <span>Remediation CLI commands</span>
            </label>
          </div>

          <div className="print-hint">
            <Eye size={13} aria-hidden />
            <span>Tip: In the print dialog, select <strong>"Save as PDF"</strong> for an electronic audit copy.</span>
          </div>
        </div>

        {/* Modal Printable Preview Container */}
        <div className="print-modal-body">
          <div className="print-paper-sheet">
            <PrintReportDocument report={report} options={options} />
          </div>
        </div>
      </div>
    </div>
  );
}

export default PrintReportModal;
