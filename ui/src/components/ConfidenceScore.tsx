import React from 'react';

interface Props {
  score: number | null | undefined;
  tier?: number;
  showLabel?: boolean;
  size?: 'sm' | 'md' | 'lg';
}

const TIER_LABELS: Record<number, string> = {
  1: 'Tier 1 — Autonomous',
  2: 'Tier 2 — Policy-assisted',
  3: 'Tier 3 — Expert review',
};

const TIER_COLORS: Record<number, string> = {
  1: 'text-green-700 bg-green-50 border-green-200',
  2: 'text-yellow-700 bg-yellow-50 border-yellow-200',
  3: 'text-orange-700 bg-orange-50 border-orange-200',
};

function scoreColor(score: number): { bar: string; text: string } {
  if (score >= 0.85) return { bar: 'bg-green-500', text: 'text-green-700' };
  if (score >= 0.70) return { bar: 'bg-yellow-400', text: 'text-yellow-700' };
  if (score >= 0.50) return { bar: 'bg-orange-400', text: 'text-orange-700' };
  return { bar: 'bg-red-500', text: 'text-red-700' };
}

export default function ConfidenceScore({ score, tier, showLabel = true, size = 'md' }: Props) {
  if (score == null) {
    return <span className="text-xs text-gray-400">N/A</span>;
  }

  const pct = Math.round(score * 100);
  const { bar, text } = scoreColor(score);
  const barHeight = size === 'sm' ? 'h-1' : size === 'lg' ? 'h-2.5' : 'h-1.5';
  const textSize = size === 'sm' ? 'text-xs' : size === 'lg' ? 'text-base' : 'text-sm';

  return (
    <div className="space-y-1">
      <div className="flex items-center gap-2">
        <span className={`font-semibold ${textSize} ${text}`}>{pct}%</span>
        {showLabel && (
          <span className={`text-xs text-gray-500`}>confidence</span>
        )}
      </div>
      <div className={`w-full bg-gray-200 rounded-full ${barHeight}`}>
        <div
          className={`${bar} ${barHeight} rounded-full transition-all`}
          style={{ width: `${pct}%` }}
        />
      </div>
      {tier != null && (
        <span className={`inline-block text-xs font-medium px-2 py-0.5 rounded border ${TIER_COLORS[tier] ?? 'text-gray-600 bg-gray-50 border-gray-200'}`}>
          {TIER_LABELS[tier] ?? `Tier ${tier}`}
        </span>
      )}
    </div>
  );
}
