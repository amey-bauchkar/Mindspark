import React, { useState, useEffect, useRef, useMemo, useCallback } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { Clock, History, RotateCcw, Check, X, Loader2, Sparkles, GitBranch, ExternalLink } from 'lucide-react';
import { formatDateShort } from '../../lib/format';
import type { Report } from '../../lib/types';

export type DependencyChangeType = 'ADDED' | 'MODIFIED' | 'REMOVED';

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
  const queryClient = useQueryClient();

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

  // Discover change events from active report query data if events prop is empty
  const activeEvents = useMemo<DependencyChangeEvent[]>(() => {
    if (events && events.length > 0) return events;

    const discovered: DependencyChangeEvent[] = [];

    // Support caller-provided milestones
    if (milestones && milestones.length > 0) {
      for (const m of milestones) {
        discovered.push({
          package_id: m.label,
          package_name: m.label,
          type: 'MODIFIED',
          effective_at: `${m.date}T00:00:00Z`,
          reason: m.description || m.label,
        });
      }
    }

    try {
      const queries = queryClient.getQueriesData<any>({ queryKey: ['report'] });
      for (const [, reportData] of queries) {
        if (!reportData || !reportData.decisions) continue;

        const decisions = reportData.decisions || [];
        const evidenceList = reportData.evidence || [];

        // Check for plain-crypto-js or malicious incident packages
        for (const dec of decisions) {
          if (dec.name === 'plain-crypto-js') {
            if (!discovered.some(d => d.package_name === 'plain-crypto-js')) {
              discovered.push({
                package_id: dec.subject || 'pkg:npm/plain-crypto-js@4.2.1',
                package_name: 'plain-crypto-js',
                version: dec.version || '4.2.1',
                type: 'ADDED',
                effective_at: '2026-03-14T00:00:00Z',
                reason: 'Malicious dependency plain-crypto-js introduced as transitive dependency',
              });
            }
          } else if (dec.name === 'axios' && dec.verdict === 'INCIDENT') {
            if (!discovered.some(d => d.package_name === 'axios')) {
              discovered.push({
                package_id: dec.subject || 'pkg:npm/axios@1.14.1',
                package_name: 'axios',
                version: dec.version || '1.14.1',
                type: 'MODIFIED',
                previous_version: '1.14.0',
                new_version: dec.version || '1.14.1',
                effective_at: '2026-03-12T00:00:00Z',
                reason: 'Axios dependency updated with reference to malicious package',
              });
            }
          } else if (dec.verdict === 'INCIDENT' && !discovered.some(d => d.package_name === dec.name)) {
            const ev = evidenceList.find((e: any) => e.subject?.includes(dec.name) && e.published_at);
            discovered.push({
              package_id: dec.subject,
              package_name: dec.name,
              version: dec.version,
              type: 'ADDED',
              effective_at: ev?.published_at ? ev.published_at.replace(' ', 'T') : '2026-03-14T00:00:00Z',
              reason: dec.what || `Malicious package detected: ${dec.name}`,
            });
          }
        }

        if (discovered.length > 0) break;
      }
    } catch {}

    // Default fallback milestone events for incident replay
    if (discovered.length === 0) {
      discovered.push({
        package_id: 'pkg:npm/plain-crypto-js@4.2.1',
        package_name: 'plain-crypto-js',
        version: '4.2.1',
        type: 'ADDED',
        effective_at: '2026-03-14T00:00:00Z',
        reason: 'Malicious package plain-crypto-js introduced into lockfile',
      });
      discovered.push({
        package_id: 'pkg:npm/axios@1.14.1',
        package_name: 'axios',
        version: '1.14.1',
        type: 'MODIFIED',
        previous_version: '1.14.0',
        new_version: '1.14.1',
        effective_at: '2026-03-12T00:00:00Z',
        reason: 'Axios version bump referencing plain-crypto-js',
      });
    }

    return discovered.sort((a, b) => new Date(a.effective_at).getTime() - new Date(b.effective_at).getTime());
  }, [events, milestones, queryClient, isOpen]);

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

  // Timeline scrubber: 365-day (1-year) history window so March 2026 fits comfortably
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

  // Find decision for selected event in current report snapshot (Section 7: As-Of -> Decision)
  const historicalDecision = useMemo(() => {
    if (!selectedEvent) return null;
    try {
      const queries = queryClient.getQueriesData<Report>({ queryKey: ['report'] });
      for (const [, reportData] of queries) {
        if (!reportData || !reportData.decisions) continue;
        const pkgName = selectedEvent.package_name.toLowerCase();
        const pkgId = selectedEvent.package_id.toLowerCase();
        const match = reportData.decisions.find(d => {
          const s = (d.subject || '').toLowerCase();
          const n = (d.name || '').toLowerCase();
          return s === pkgId || n === pkgName || s.includes(pkgName);
        });
        if (match) return match;
      }
    } catch {}
    return null;
  }, [selectedEvent, queryClient, currentAsOf]);

  // Section 6: As-Of -> Graph (Focus historical package in dependency graph)
  const handleViewEventInGraph = useCallback(() => {
    if (!selectedEvent) return;
    setIsOpen(false);

    // 1. Apply As-Of date
    const dateStr = selectedEvent.effective_at.replace(' ', 'T').split('T')[0];
    try {
      const isoString = new Date(`${dateStr}T23:59:59Z`).toISOString();
      onApplyAsOf(isoString);
    } catch {}

    // 2. Broadcast temporal change
    broadcastTemporalEvent(selectedEvent);

    // 3. Focus node in graph
    if (typeof window !== 'undefined') {
      sessionStorage.setItem('warrant:focused-package', selectedEvent.package_id);
      window.dispatchEvent(
        new CustomEvent('warrant:focus-package', {
          detail: {
            subject: selectedEvent.package_id,
            name: selectedEvent.package_name,
            version: selectedEvent.version || selectedEvent.new_version,
          },
        })
      );
    }

    // 4. Switch to Graph tab via coordinator shell
    const graphTabBtn = document.getElementById('tab-graph');
    if (graphTabBtn) {
      graphTabBtn.click();
    }
  }, [selectedEvent, onApplyAsOf, broadcastTemporalEvent]);

  // Section 7: As-Of -> Decision (Inspect historical decision)
  const handleViewEventDecision = useCallback(() => {
    if (!historicalDecision) return;
    setIsOpen(false);

    // Broadcast decision to ActionGroups / shell
    if (typeof window !== 'undefined') {
      window.dispatchEvent(
        new CustomEvent('warrant:open-decision', { detail: historicalDecision })
      );
    }

    // Switch to Decisions tab if not already active
    const decisionsTabBtn = document.getElementById('tab-decisions');
    if (decisionsTabBtn) {
      decisionsTabBtn.click();
    }
  }, [historicalDecision]);

  // Section 8: Decision -> As-Of (Listen for timeline navigation requests)
  useEffect(() => {
    if (typeof window === 'undefined') return;

    const handleNavigateAsOf = (e: Event) => {
      const customEv = e as CustomEvent<{
        date: string;
        event?: DependencyChangeEvent | null;
        package_name?: string;
        package_id?: string;
      }>;
      if (!customEv.detail) return;
      const { date, event, package_name } = customEv.detail;

      if (date) {
        const cleanDate = date.split('T')[0];
        setSelectedDate(cleanDate);
        try {
          const isoString = new Date(`${cleanDate}T23:59:59Z`).toISOString();
          onApplyAsOf(isoString);
        } catch {}
      }

      const matched = event || activeEvents.find(ev =>
        (package_name && ev.package_name.toLowerCase() === package_name.toLowerCase()) ||
        (date && ev.effective_at.startsWith(date.split('T')[0]))
      ) || null;

      if (matched) {
        setSelectedEvent(matched);
        broadcastTemporalEvent(matched);
      }

      setIsOpen(true);
    };

    window.addEventListener('warrant:navigate-asof', handleNavigateAsOf);
    return () => window.removeEventListener('warrant:navigate-asof', handleNavigateAsOf);
  }, [activeEvents, onApplyAsOf, broadcastTemporalEvent]);

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
              <span>1y ago (Mar 2026)</span>
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

          {/* Timeline Change Events List (Section 1 of requirements) */}
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
                <span>Dependency Change Events (Click to Rewind)</span>
              </label>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-1)', maxHeight: '130px', overflowY: 'auto' }}>
                {activeEvents.map((ev, idx) => {
                  const isSelected = selectedEvent?.package_name === ev.package_name && selectedEvent?.type === ev.type;
                  const dateLabel = formatDateShort(ev.effective_at);
                  const typeLabel = ev.type === 'ADDED' ? 'added' : ev.type === 'MODIFIED' ? 'modified' : 'removed';

                  return (
                    <button
                      key={`${ev.package_name}-${idx}`}
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
                        {dateLabel} · <strong>{ev.package_name}</strong> {typeLabel}
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
                        {ev.type}
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

          {/* Selected Event Contextual Card (Section 7: Historical State Context) */}
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
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  marginBottom: '4px',
                }}
              >
                <span
                  style={{
                    fontSize: '10px',
                    fontWeight: 700,
                    color: selectedEvent.type === 'ADDED' ? '#0891B2' : selectedEvent.type === 'MODIFIED' ? '#7C3AED' : 'var(--verdict-incident-fg)',
                    textTransform: 'uppercase',
                    letterSpacing: '0.05em',
                  }}
                >
                  {selectedEvent.type === 'ADDED'
                    ? 'Dependency Introduced'
                    : selectedEvent.type === 'MODIFIED'
                    ? 'Dependency Modified'
                    : 'Dependency Removed'}
                </span>
                <span style={{ fontSize: '10px', color: 'var(--color-muted)', fontWeight: 600 }}>
                  Historical state
                </span>
              </div>

              <div style={{ fontSize: 'var(--text-xs)', fontWeight: 600 }}>
                <code>
                  {selectedEvent.package_name}
                  {selectedEvent.version ? `@${selectedEvent.version}` : selectedEvent.new_version ? `@${selectedEvent.new_version}` : ''}
                </code>
                {selectedEvent.previous_version && selectedEvent.new_version && (
                  <span style={{ marginLeft: '4px', color: 'var(--color-muted)', fontSize: '11px' }}>
                    ({selectedEvent.previous_version} → {selectedEvent.new_version})
                  </span>
                )}
              </div>

              <div style={{ fontSize: '11px', color: 'var(--color-muted)', marginTop: '2px' }}>
                As of: <strong>{formatDateShort(selectedEvent.effective_at)}</strong>
                {selectedEvent.reason && ` · ${selectedEvent.reason}`}
              </div>

              {/* Historical Decision Status */}
              <div
                style={{
                  marginTop: 'var(--space-2)',
                  paddingTop: 'var(--space-2)',
                  borderTop: '1px solid var(--color-border)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  flexWrap: 'wrap',
                  gap: 'var(--space-2)',
                }}
              >
                <div style={{ fontSize: '11px' }}>
                  <span style={{ color: 'var(--color-muted)' }}>Historical Finding: </span>
                  {historicalDecision ? (
                    <span
                      style={{
                        fontWeight: 700,
                        fontSize: '10px',
                        padding: '1px 5px',
                        borderRadius: 'var(--radius-sm)',
                        background: 'var(--color-surface)',
                        border: '1px solid var(--color-border)',
                      }}
                    >
                      {historicalDecision.verdict.replace('_', ' ')}
                    </span>
                  ) : (
                    <span style={{ color: 'var(--color-muted)', fontStyle: 'italic' }}>
                      (Not assessed at this date)
                    </span>
                  )}
                </div>
              </div>

              {/* Cross-navigation actions */}
              <div style={{ display: 'flex', gap: 'var(--space-2)', marginTop: 'var(--space-2)' }}>
                <button
                  type="button"
                  onClick={handleViewEventInGraph}
                  className="btn btn-secondary btn-sm"
                  style={{
                    flex: 1,
                    display: 'inline-flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    gap: '4px',
                    fontSize: '11px',
                    height: '26px',
                  }}
                  title={`View ${selectedEvent.package_name} in graph`}
                >
                  <GitBranch size={12} aria-hidden />
                  <span>View in Dependency Graph</span>
                </button>

                {historicalDecision && (
                  <button
                    type="button"
                    onClick={handleViewEventDecision}
                    className="btn btn-ghost btn-sm"
                    style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      gap: '4px',
                      fontSize: '11px',
                      height: '26px',
                      border: '1px solid var(--color-border)',
                    }}
                    title={`View decision for ${selectedEvent.package_name}`}
                  >
                    <ExternalLink size={12} aria-hidden />
                    <span>View Decision</span>
                  </button>
                )}
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
