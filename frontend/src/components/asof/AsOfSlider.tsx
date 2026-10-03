import React, { useState, useEffect, useRef, useMemo, useCallback } from 'react';
import { Clock, History, RotateCcw, Check, X, Loader2, Sparkles } from 'lucide-react';
import { formatDateShort } from '../../lib/format';

export type DependencyChangeType = 'ADDED' | 'MODIFIED' | 'REMOVED' | 'ADVISORY' | 'MALWARE_REPORT' | 'WITHDRAWN';

export interface DependencyChangeEvent {
  package_id: string;
  package_name: string;
  version?: string;
  type: DependencyChangeType;
  effective_at: string;
  previous_version?: string | null;
  new_version?: string | null;
  reason?: string | null;
}

export interface AsOfMilestone {
  label: string;
  date: string; // YYYY-MM-DD
  description?: string;
}

export interface AsOfSliderProps {
  currentAsOf: string;
  onApplyAsOf: (asOfIso: string | null) => void;
  isLoading?: boolean;
  milestones?: AsOfMilestone[];
  events?: DependencyChangeEvent[];
  onSelectEvent?: (event: DependencyChangeEvent | null) => void;
}

export function AsOfSlider({ 
  currentAsOf, 
  onApplyAsOf, 
  isLoading = false,
  milestones = [],
  events = [],
  onSelectEvent,
}: AsOfSliderProps) {
  const [isOpen, setIsOpen] = useState(false);
  const panelRef = useRef<HTMLDivElement>(null);

  // Today's date in YYYY-MM-DD format
  const todayStr = useMemo(() => new Date().toISOString().split('T')[0], []);

  // Initialize selected date from currentAsOf
  const [selectedDate, setSelectedDate] = useState<string>(() => {
    try {
      if (currentAsOf) {
        const d = new Date(currentAsOf);
        if (!isNaN(d.getTime())) {
          return d.toISOString().split('T')[0];
        }
      }
    } catch {}
    return new Date().toISOString().split('T')[0];
  });

  // Track active dependency change event
  const [selectedEvent, setSelectedEvent] = useState<DependencyChangeEvent | null>(() => {
    if (typeof window === 'undefined') return null;
    try {
      const stored = sessionStorage.getItem('warrant:temporal-change');
      return stored ? JSON.parse(stored) : null;
    } catch {
      return null;
    }
  });

  // Only sync selectedDate when currentAsOf externally updates from a new query response
  const lastSyncAsOf = useRef<string | null>(null);
  useEffect(() => {
    if (currentAsOf && currentAsOf !== lastSyncAsOf.current) {
      lastSyncAsOf.current = currentAsOf;
      try {
        const d = new Date(currentAsOf);
        if (!isNaN(d.getTime())) {
          setSelectedDate(d.toISOString().split('T')[0]);
        }
      } catch {}
    }
  }, [currentAsOf]);

  // Timeline markers come only from the caller (dated evidence in the displayed report) and
  // explicit milestones — never from other cached reports and never invented.
  const activeEvents = useMemo<DependencyChangeEvent[]>(() => {
    const discovered: DependencyChangeEvent[] = [...(events ?? [])];
    for (const m of milestones ?? []) {
      discovered.push({
        package_id: m.label,
        package_name: m.label,
        type: 'MODIFIED',
        effective_at: `${m.date}T00:00:00Z`,
        reason: m.description || m.label,
      });
    }
    return discovered.sort((a, b) => new Date(a.effective_at).getTime() - new Date(b.effective_at).getTime());
  }, [events, milestones]);

  // Determine if historical rewind is currently active
  const isHistoricalActive = useMemo(() => {
    if (!currentAsOf) return false;
    try {
      const currentDate = new Date(currentAsOf).toISOString().split('T')[0];
      return currentDate < todayStr;
    } catch {
      return false;
    }
  }, [currentAsOf, todayStr]);

  // Synchronize selectedEvent with current selectedDate
  useEffect(() => {
    if (activeEvents.length > 0) {
      const matched = activeEvents.find(ev => ev.effective_at.startsWith(selectedDate));
      setSelectedEvent(matched || null);
    }
  }, [selectedDate, activeEvents]);

  // Close popup on Escape or outside click
  useEffect(() => {
    if (!isOpen) return;

    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') {
        setIsOpen(false);
      }
    }

    function handleClickOutside(e: MouseEvent) {
      if (panelRef.current && !panelRef.current.contains(e.target as Node)) {
        setIsOpen(false);
      }
    }

    window.addEventListener('keydown', handleKeyDown);
    document.addEventListener('mousedown', handleClickOutside);
    return () => {
      window.removeEventListener('keydown', handleKeyDown);
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [isOpen]);

  // Timeline scrubber: 365-day (1-year) history window
  const daysOffset = useMemo(() => {
    try {
      const today = new Date(todayStr + 'T00:00:00Z').getTime();
      const target = new Date(selectedDate + 'T00:00:00Z').getTime();
      const diffDays = Math.round((today - target) / (1000 * 60 * 60 * 24));
      return Math.max(0, Math.min(diffDays, 365));
    } catch {
      return 0;
    }
  }, [selectedDate, todayStr]);

  // Calculate percentage along 365-day scrubber (0% is 365 days ago, 100% is today)
  const getEventPositionPercent = (effectiveAt: string): number | null => {
    try {
      const today = new Date(todayStr + 'T00:00:00Z').getTime();
      const cleanDate = effectiveAt.replace(' ', 'T').split('T')[0];
      const eventTime = new Date(cleanDate + 'T00:00:00Z').getTime();
      const diffDays = Math.round((today - eventTime) / (1000 * 60 * 60 * 24));
      if (diffDays < 0 || diffDays > 365) return null;
      return Math.max(3, Math.min(97, ((365 - diffDays) / 365) * 100));
    } catch {
      return null;
    }
  };

  const broadcastTemporalEvent = useCallback((event: DependencyChangeEvent | null) => {
    if (typeof window !== 'undefined') {
      try {
        if (event) {
          sessionStorage.setItem('warrant:temporal-change', JSON.stringify(event));
        } else {
          sessionStorage.removeItem('warrant:temporal-change');
        }
        window.dispatchEvent(new CustomEvent('warrant:temporal-change', { detail: event }));
      } catch {}
    }
    onSelectEvent?.(event);
  }, [onSelectEvent]);

  // Handle direct slider drag smoothly with timezone-deterministic UTC arithmetic
  const handleSliderChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const sliderPos = parseInt(e.target.value, 10); // 0 (365d ago) to 365 (today)
    const daysAgo = 365 - sliderPos;
    const d = new Date(todayStr + 'T00:00:00Z');
    d.setUTCDate(d.getUTCDate() - daysAgo);
    const dateStr = d.toISOString().split('T')[0];
    setSelectedDate(dateStr);

    const matched = activeEvents.find(ev => ev.effective_at.startsWith(dateStr)) || null;
    setSelectedEvent(matched);
    broadcastTemporalEvent(matched);
  };

  const handleSelectEvent = (event: DependencyChangeEvent) => {
    const dateStr = event.effective_at.replace(' ', 'T').split('T')[0];
    setSelectedDate(dateStr);
    setSelectedEvent(event);
    broadcastTemporalEvent(event);

    try {
      const isoString = new Date(`${dateStr}T23:59:59Z`).toISOString();
      onApplyAsOf(isoString);
      setIsOpen(false);
    } catch {}
  };

  const handleReset = () => {
    setSelectedEvent(null);
    broadcastTemporalEvent(null);
    onApplyAsOf(null);
    setIsOpen(false);
  };

  const handleApply = () => {
    if (!selectedDate) return;
    try {
      const matched = activeEvents.find(ev => ev.effective_at.startsWith(selectedDate)) || null;
      setSelectedEvent(matched);
      broadcastTemporalEvent(matched);

      const isoString = new Date(`${selectedDate}T23:59:59Z`).toISOString();
      onApplyAsOf(isoString);
      setIsOpen(false);
    } catch {}
  };

  return (
    <div style={{ position: 'relative', display: 'inline-block' }} ref={panelRef}>
      <button
        onClick={() => setIsOpen(x => !x)}
        className={`btn ${isHistoricalActive ? 'btn-primary' : 'btn-secondary'} btn-sm`}
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 'var(--space-2)',
          fontSize: 'var(--text-xs)',
        }}
        title="Rewind time to evaluate what was known on a specific past date"
        aria-expanded={isOpen}
        aria-haspopup="dialog"
      >
        <History size={14} aria-hidden />
        <span>
          {isHistoricalActive ? `As-Of: ${formatDateShort(currentAsOf)}` : 'Time-Travel (As-Of)'}
        </span>
        {isHistoricalActive && (
          <span
            style={{
              padding: '1px 5px',
              borderRadius: 'var(--radius-full)',
              background: 'rgba(255, 255, 255, 0.25)',
              fontSize: '10px',
              fontWeight: 700,
            }}
          >
            {selectedEvent ? selectedEvent.type : 'REWOUND'}
          </span>
        )}
      </button>

      {isOpen && (
        <div
          role="dialog"
          aria-label="As-Of Temporal Rewind Selector"
          style={{
            position: 'absolute',
            top: 'calc(100% + 8px)',
            right: 0,
            zIndex: 60,
            width: '360px',
            background: 'var(--color-surface)',
            border: '1px solid var(--color-border)',
            borderRadius: 'var(--radius-lg)',
            boxShadow: 'var(--shadow-lg)',
            padding: 'var(--space-4)',
          }}
        >
          {/* Header */}
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              marginBottom: 'var(--space-2)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
              <Clock size={16} style={{ color: 'var(--color-accent)' }} aria-hidden />
              <span style={{ fontSize: 'var(--text-sm)', fontWeight: 700 }}>
                As-Of Temporal Rewind
              </span>
            </div>
            <button
              onClick={() => setIsOpen(false)}
              className="btn btn-ghost btn-sm"
              style={{ padding: '2px', minWidth: 'auto', height: 'auto' }}
              aria-label="Close dialog"
            >
              <X size={14} />
            </button>
          </div>

          <p
            style={{
              fontSize: 'var(--text-xs)',
              color: 'var(--color-muted)',
              marginBottom: 'var(--space-3)',
              lineHeight: 1.4,
            }}
          >
            Rewind to inspect what was known on a specific date and trace dependency modifications in the graph.
          </p>

          {/* Timeline Range Scrubber with Event Markers */}
          <div style={{ marginBottom: 'var(--space-4)' }}>
            <div
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                fontSize: '11px',
                color: 'var(--color-muted)',
                marginBottom: '6px',
              }}
            >
              <span>1y ago ({formatDateShort(new Date(Date.now() - 365 * 86400000))})</span>
              <span style={{ fontWeight: 600, color: 'var(--color-text)' }}>
                {daysOffset === 0 ? 'Today (Latest)' : formatDateShort(selectedDate)}
              </span>
              <span>Today</span>
            </div>

            {/* Scrubber Container with Event Pins */}
            <div style={{ position: 'relative', width: '100%', height: '28px', display: 'flex', alignItems: 'center' }}>
              <input
                type="range"
                min="0"
                max="365"
                step="1"
                value={365 - daysOffset}
                onChange={handleSliderChange}
                style={{
                  width: '100%',
                  cursor: 'pointer',
                  accentColor: 'var(--color-accent)',
                  margin: 0,
                  display: 'block',
                  zIndex: 2,
                }}
                aria-label="Timeline scrubber (1 year history)"
                disabled={isLoading}
              />

              {/* Render small timeline event markers on the track */}
              {activeEvents.map((ev, idx) => {
                const percent = getEventPositionPercent(ev.effective_at);
                if (percent === null) return null;
                const isSelected = selectedEvent?.package_name === ev.package_name && selectedEvent?.type === ev.type;

                return (
                  <button
                    key={`${ev.package_name}-${idx}`}
                    onClick={(e) => {
                      e.stopPropagation();
                      handleSelectEvent(ev);
                    }}
                    style={{
                      position: 'absolute',
                      left: `${percent}%`,
                      top: '50%',
                      transform: 'translate(-50%, -50%)',
                      width: isSelected ? '16px' : '12px',
                      height: isSelected ? '16px' : '12px',
                      borderRadius: '50%',
                      background: ev.type === 'ADDED' ? '#06B6D4' : ev.type === 'MODIFIED' ? '#8B5CF6' : 'var(--verdict-incident-fg)',
                      border: '2px solid var(--color-surface)',
                      boxShadow: '0 0 0 2px rgba(0,0,0,0.15)',
                      cursor: 'pointer',
                      padding: 0,
                      zIndex: 10,
                      transition: 'transform 0.15s ease',
                    }}
                    title={`${formatDateShort(ev.effective_at)}: ${ev.package_name} (${ev.type})`}
                    aria-label={`Select event: ${ev.package_name} ${ev.type} on ${formatDateShort(ev.effective_at)}`}
                  />
                );
              })}
            </div>
          </div>

          {activeEvents.length === 0 && (
            <p style={{ fontSize: 'var(--text-xs)', color: 'var(--color-muted)', marginBottom: 'var(--space-3)' }}>
              No dated advisories or malware reports in this report. Pick any date to see what was known then.
            </p>
          )}

          {/* Timeline of dated evidence in this report */}
          {activeEvents && activeEvents.length > 0 && (
            <div style={{ marginBottom: 'var(--space-3)' }}>
              <label
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '4px',
                  fontSize: '11px',
                  fontWeight: 600,
                  color: 'var(--color-muted)',
                  marginBottom: 'var(--space-1)',
                  textTransform: 'uppercase',
                  letterSpacing: '0.04em',
                }}
              >
                <Sparkles size={12} style={{ color: 'var(--color-accent)' }} />
                <span>Dated evidence in this report (click to rewind)</span>
              </label>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-1)', maxHeight: '130px', overflowY: 'auto' }}>
                {activeEvents.map((ev, idx) => {
                  const isSelected = selectedEvent?.package_id === ev.package_id
                    && selectedEvent?.effective_at === ev.effective_at && selectedEvent?.reason === ev.reason;
                  const dateLabel = formatDateShort(ev.effective_at);
                  const isEvidence = ev.type === 'ADVISORY' || ev.type === 'MALWARE_REPORT' || ev.type === 'WITHDRAWN';
                  const typeLabel = isEvidence
                    ? `— ${ev.reason || ''}`
                    : ev.type === 'ADDED' ? 'added' : ev.type === 'MODIFIED' ? 'modified' : 'removed';

                  return (
                    <button
                      key={`${ev.package_id}-${ev.effective_at}-${idx}`}
                      onClick={() => handleSelectEvent(ev)}
                      className="btn btn-ghost btn-sm"
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        textAlign: 'left',
                        padding: '6px 10px',
                        fontSize: '11px',
                        background: isSelected ? 'var(--color-accent-bg)' : 'var(--color-bg)',
                        border: isSelected ? '1px solid var(--color-accent)' : '1px solid var(--color-border)',
                        color: isSelected ? 'var(--color-accent)' : 'var(--color-text)',
                        borderRadius: 'var(--radius-sm)',
                        width: '100%',
                      }}
                      title={ev.reason || `${ev.package_name} ${typeLabel}`}
                    >
                      <span style={{ fontWeight: 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {dateLabel} · <strong>{ev.package_name}{isEvidence && ev.version ? `@${ev.version}` : ''}</strong> {typeLabel}
                        {ev.previous_version && ev.new_version && ` (${ev.previous_version} → ${ev.new_version})`}
                      </span>
                      <span
                        style={{
                          fontSize: '10px',
                          fontWeight: 700,
                          padding: '1px 5px',
                          borderRadius: 'var(--radius-sm)',
                          background: ev.type === 'ADDED' ? 'rgba(6, 182, 212, 0.15)' : 'rgba(139, 92, 246, 0.15)',
                          color: ev.type === 'ADDED' ? '#0891B2' : '#7C3AED',
                          flexShrink: 0,
                          marginLeft: '6px',
                        }}
                      >
                        {ev.type.replace('_', ' ')}
                      </span>
                    </button>
                  );
                })}
              </div>
            </div>
          )}

          {/* Date Picker Input */}
          <div style={{ marginBottom: 'var(--space-3)' }}>
            <label
              htmlFor="as-of-date-picker"
              style={{
                display: 'block',
                fontSize: 'var(--text-xs)',
                fontWeight: 600,
                marginBottom: 'var(--space-1)',
              }}
            >
              Effective Date:
            </label>
            <input
              id="as-of-date-picker"
              type="date"
              max={todayStr}
              value={selectedDate}
              onChange={e => {
                setSelectedDate(e.target.value);
                const matched = activeEvents.find(ev => ev.effective_at.startsWith(e.target.value)) || null;
                setSelectedEvent(matched);
                broadcastTemporalEvent(matched);
              }}
              className="input"
              style={{
                width: '100%',
                fontSize: 'var(--text-xs)',
              }}
              disabled={isLoading}
            />
          </div>

          {/* Selected Event Contextual Card (Section 2 of requirements) */}
          {selectedEvent && (
            <div
              style={{
                marginTop: 'var(--space-2)',
                marginBottom: 'var(--space-3)',
                padding: 'var(--space-3)',
                borderRadius: 'var(--radius-md)',
                background: 'var(--color-bg)',
                border: '1px solid var(--color-border)',
              }}
            >
              <div
                style={{
                  fontSize: '10px',
                  fontWeight: 700,
                  color: selectedEvent.type === 'ADDED' ? '#0891B2' : selectedEvent.type === 'MODIFIED' ? '#7C3AED' : 'var(--verdict-incident-fg)',
                  textTransform: 'uppercase',
                  letterSpacing: '0.05em',
                  marginBottom: '2px',
                }}
              >
                {selectedEvent.type === 'ADDED'
                  ? 'Dependency Introduced'
                  : selectedEvent.type === 'MODIFIED'
                  ? 'Dependency Modified'
                  : 'Dependency Removed'}
              </div>
              <div style={{ fontSize: 'var(--text-xs)', fontWeight: 600 }}>
                <code>
                  {selectedEvent.package_name}
                  {selectedEvent.version ? `@${selectedEvent.version}` : ''}
                </code>
                {selectedEvent.previous_version && selectedEvent.new_version && (
                  <span style={{ marginLeft: '4px', color: 'var(--color-muted)', fontSize: '11px' }}>
                    ({selectedEvent.previous_version} → {selectedEvent.new_version})
                  </span>
                )}
              </div>
              <div style={{ fontSize: '11px', color: 'var(--color-muted)', marginTop: '2px' }}>
                Effective: {formatDateShort(selectedEvent.effective_at)}
                {selectedEvent.reason && ` · ${selectedEvent.reason}`}
              </div>
            </div>
          )}

          {/* Active Status Notice */}
          {isHistoricalActive && !selectedEvent && (
            <div
              style={{
                fontSize: '11px',
                padding: '6px 8px',
                borderRadius: 'var(--radius-sm)',
                background: 'var(--verdict-act-now-bg)',
                color: 'var(--verdict-act-now-fg)',
                border: '1px solid var(--verdict-act-now-border)',
                marginBottom: 'var(--space-3)',
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
              }}
            >
              <History size={13} aria-hidden />
              <span>Historical snapshot active: {formatDateShort(currentAsOf)}</span>
            </div>
          )}

          {/* Action Buttons */}
          <div
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              gap: 'var(--space-2)',
              borderTop: '1px solid var(--color-border)',
              paddingTop: 'var(--space-3)',
            }}
          >
            <button
              onClick={handleReset}
              className="btn btn-ghost btn-sm"
              disabled={isLoading || !isHistoricalActive}
              title="Reset report to latest live data"
              style={{ fontSize: 'var(--text-xs)' }}
            >
              <RotateCcw size={12} aria-hidden />
              <span>Reset to Now</span>
            </button>

            <button
              onClick={handleApply}
              className="btn btn-primary btn-sm"
              disabled={isLoading || !selectedDate}
              style={{ fontSize: 'var(--text-xs)', display: 'flex', alignItems: 'center', gap: '4px' }}
            >
              {isLoading ? (
                <>
                  <Loader2 size={12} className="spinner" aria-hidden />
                  <span>Re-deriving…</span>
                </>
              ) : (
                <>
                  <Check size={12} aria-hidden />
                  <span>Apply Date</span>
                </>
              )}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

export default AsOfSlider;
