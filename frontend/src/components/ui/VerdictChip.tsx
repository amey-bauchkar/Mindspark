import React from 'react';
import type { Verdict } from '../../lib/types';
import { VERDICT_LABELS, VERDICT_ICONS } from '../../lib/types';

interface VerdictChipProps {
  verdict: string;
  className?: string;
}

export function VerdictChip({ verdict, className = '' }: VerdictChipProps) {
  const label = VERDICT_LABELS[verdict as Verdict] || verdict;
  const icon = VERDICT_ICONS[verdict as Verdict] || '';
  return (
    <span
      className={`verdict-chip verdict-${verdict} ${className}`}
      aria-label={`Verdict: ${label}`}
    >
      <span aria-hidden>{icon}</span> {label}
    </span>
  );
}

export default VerdictChip;
