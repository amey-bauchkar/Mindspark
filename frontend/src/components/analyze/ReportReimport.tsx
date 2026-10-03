import React, { useRef, useState } from 'react';
import { UploadCloud, FileCheck, AlertCircle } from 'lucide-react';
import { importReport } from '../../lib/api';
import { useNavigate } from 'react-router-dom';

export function ReportReimport() {
  const navigate = useNavigate();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleFile(file: File) {
    if (!file.name.endsWith('.json')) {
      setError('Please upload a valid JSON report file (e.g. warrant-report-*.json)');
      return;
    }
    setError(null);
    setLoading(true);
    try {
      const res = await importReport(file);
      navigate(`/report/${res.report_id}`);
    } catch (err: any) {
      setError(err?.message || 'Failed to import report');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div
      style={{
        padding: 'var(--space-4) var(--space-5)',
        background: 'var(--color-surface)',
        border: '1px solid var(--color-border)',
        borderRadius: 'var(--radius-lg)',
        boxShadow: 'var(--shadow-xs)',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 'var(--space-2)' }}>
        <div>
          <p style={{ fontSize: 'var(--text-sm)', fontWeight: 600, margin: 0 }}>
            Re-import Saved Report
          </p>
          <p style={{ fontSize: 'var(--text-xs)', color: 'var(--color-muted)', margin: 0, marginTop: 2 }}>
            Upload a previously exported Warrant JSON report to view it instantly without re-scanning.
          </p>
        </div>
        <input
          ref={fileInputRef}
          type="file"
          accept=".json,application/json"
          style={{ display: 'none' }}
          onChange={e => {
            const f = e.target.files?.[0];
            if (f) handleFile(f);
          }}
        />
        <button
          type="button"
          onClick={() => fileInputRef.current?.click()}
          disabled={loading}
          className="btn btn-secondary btn-sm"
        >
          <UploadCloud size={14} aria-hidden />
          {loading ? 'Importing…' : 'Upload JSON Report'}
        </button>
      </div>

      {error && (
        <div className="callout callout-error" style={{ marginTop: 'var(--space-3)', fontSize: 'var(--text-xs)' }}>
          <AlertCircle size={14} aria-hidden />
          <span>{error}</span>
        </div>
      )}
    </div>
  );
}

export default ReportReimport;
