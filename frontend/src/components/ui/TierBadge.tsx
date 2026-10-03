import React from 'react';

interface TierBadgeProps {
  tier: string;
  className?: string;
}

export function TierBadge({ tier, className = '' }: TierBadgeProps) {
  return <span className={`tier-badge tier-${tier} ${className}`}>{tier}</span>;
}

export default TierBadge;
