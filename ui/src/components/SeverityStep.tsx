import React from 'react';

interface FilterConfig {
  require_active_exposure_path: boolean;
  exclude_dormant_assets: boolean;
  deduplicate_across_scanners: boolean;
  exclude_accepted_risks: boolean;
}

interface Props {
  severity: string;
  filters: FilterConfig;
  onSeverityChange: (v: string) => void;
  onFiltersChange: (f: FilterConfig) => void;
}

const SEVERITY_OPTIONS = [
  { value: 'CRITICAL_ONLY', label: 'Critical only', description: 'CVSS 9.0+' },
  { value: 'HIGH_PLUS', label: 'High and above', description: 'CVSS 7.0+ (recommended)' },
  { value: 'MEDIUM_PLUS', label: 'Medium and above', description: 'CVSS 4.0+' },
  { value: 'ALL', label: 'All severities', description: 'Including Low' },
];

export default function SeverityStep({ severity, filters, onSeverityChange, onFiltersChange }: Props) {
  const toggle = (key: keyof FilterConfig) =>
    onFiltersChange({ ...filters, [key]: !filters[key] });

  return (
    <div className="space-y-6">
      <div>
        <label className="block text-sm font-medium text-gray-700 mb-3">Minimum Severity Threshold</label>
        <div className="space-y-2">
          {SEVERITY_OPTIONS.map(opt => (
            <label key={opt.value} className={`flex items-start gap-3 p-3 rounded-lg border cursor-pointer transition-colors ${severity === opt.value ? 'border-blue-500 bg-blue-50' : 'border-gray-200 hover:border-gray-300'}`}>
              <input
                type="radio"
                name="severity"
                value={opt.value}
                checked={severity === opt.value}
                onChange={() => onSeverityChange(opt.value)}
                className="mt-0.5"
              />
              <div>
                <div className="text-sm font-medium text-gray-900">{opt.label}</div>
                <div className="text-xs text-gray-500">{opt.description}</div>
              </div>
            </label>
          ))}
        </div>
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-700 mb-3">Finding Filters</label>
        <div className="space-y-3">
          {([
            ['require_active_exposure_path', 'Require active attack exposure path', 'Only process findings with a confirmed exposure path in SCC. Reduces noise significantly.'],
            ['deduplicate_across_scanners', 'Deduplicate across scanners', 'Merge identical findings from multiple SCC scanner sources.'],
            ['exclude_accepted_risks', 'Exclude accepted risks', 'Skip findings that have been marked as accepted/muted in SCC.'],
            ['exclude_dormant_assets', 'Exclude dormant assets from auto-approve', 'Still triage dormant assets but require manual approval.'],
          ] as [keyof FilterConfig, string, string][]).map(([key, label, desc]) => (
            <label key={key} className="flex items-start gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={filters[key]}
                onChange={() => toggle(key)}
                className="mt-1"
              />
              <div>
                <div className="text-sm font-medium text-gray-900">{label}</div>
                <div className="text-xs text-gray-500">{desc}</div>
              </div>
            </label>
          ))}
        </div>
      </div>
    </div>
  );
}
