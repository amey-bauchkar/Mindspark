import React, { useState } from 'react';
import { Clock, History, RotateCcw } from 'lucide-react';
import { formatDateShort } from '../../lib/format';

interface AsOfSliderProps {
  currentAsOf: string;
  onApplyAsOf: (asOfIso: string | null) => void;
  isLoading?: boolean;
}

export function AsOfSlider({ currentAsOf, onApplyAsOf, isLoading = false }: AsOfSliderProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [selectedDate, setSelectedDate] = useState(() => {
    try {
      return new Date(currentAsOf).toISOString().split('T')[0];
    } catch {
      return new Date().toISOString().split('T')[0];
    }
  });

  function handleReset() {
    onApplyAsOf(null);
    setIsOpen(false);
  }

  function handleApply() {
    if (!selectedDate) return;
    const isoString = new Date(`${selectedDate}T23:59:59Z`).toISOString();
    onApplyAsOf(isoString);
  }

  return (
    <div style={{ position: 'relative', display: 'inline-block' }}>
      <button
        onClick={() => setIsOpen(x => !x)}
        className="btn btn-secondary btn-sm"
        style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}
        title="Rewind time to see what was known at a past date"
      >
        <History size={14} aria-hidden />
        <span>Time-travel (As Of)</span>
      </button>

      {isOpen && (
        <div
          style={{
            position: 'absolute',
            top: 'calc(100% + 8px)',
            right: 0,
            zIndex: 50,
            minWidth: 280,
            background: 'var(--color-surface)',
            border: '1px solid var(--color-border)',
            borderRadius: 'var(--radius-md)',
            boxShadow: 'var(--shadow)',
            padding: 'var(--space-4)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginBottom: 'var(--space-2)' }}>
            <Clock size={16} aria-hidden />
            <span style={{ fontSize: 'var(--text-sm)', fontWeight: 600 }}>As-Of Temporal Rewind</span>
          </div>
          <p style={{ fontSize: 'var(--text-xs)', color: 'var(--color-muted)', marginBottom: 'var(--space-3)' }}>
            Evaluate what Warrant knew on a specific date (e.g. before an advisory or malware was published).
          </p>

          <label style={{ display: 'block', fontSize: 'var(--text-xs)', fontWeight: 500, marginBottom: 'var(--space-1)' }}>
            Effective Date:
          </label>
          <input
            type="date"
            value={selectedDate}
            onChange={e => setSelectedDate(e.target.value)}
            className="input"
            style={{ width: '100%', marginBottom: 'var(--space-3)', fontSize: 'var(--text-xs)' }}
          />

          <div style={{ display: 'flex', justifyContent: 'space-between', gap: 'var(--space-2)' }}>
            <button onClick={handleReset} className="btn btn-ghost btn-sm" disabled={isLoading}>
              <RotateCcw size={12} aria-hidden /> Reset to Now
            </button>
            <button onClick={handleApply} className="btn btn-primary btn-sm" disabled={isLoading}>
              {isLoading ? 'Re-deriving…' : 'Apply Date'}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

export default AsOfSlider;
