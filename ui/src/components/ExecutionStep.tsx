import React from 'react';
import { ExecutionConfig } from '../api/config';

const MODES = [
  { value: 'OS_PATCH', label: 'OS Patch', description: 'Automatically apply security patches via GCP OS Config' },
  { value: 'MISCONFIGURATION', label: 'Misconfiguration', description: 'Fix GCP resource misconfigurations (firewall rules, bucket policies)' },
  { value: 'IAM', label: 'IAM tightening', description: 'Remove over-permissioned IAM bindings' },
  { value: 'FIREWALL', label: 'Firewall rules', description: 'Restrict overly permissive ingress/egress rules' },
];

interface Props {
  value: ExecutionConfig;
  dryRun: boolean;
  onChange: (e: ExecutionConfig) => void;
  onDryRunChange: (v: boolean) => void;
}

export default function ExecutionStep({ value, dryRun, onChange, onDryRunChange }: Props) {
  const toggleMode = (mode: string) => {
    const modes = value.enabled_modes;
    onChange({ ...value, enabled_modes: modes.includes(mode) ? modes.filter(m => m !== mode) : [...modes, mode] });
  };

  return (
    <div className="space-y-6">
      <div className={`flex items-start gap-4 p-4 rounded-lg border-2 ${dryRun ? 'border-yellow-400 bg-yellow-50' : 'border-green-400 bg-green-50'}`}>
        <div className="flex-1">
          <div className="font-medium text-gray-900">{dryRun ? 'Dry-run mode active' : 'Live execution enabled'}</div>
          <div className="text-sm text-gray-600 mt-1">
            {dryRun
              ? 'The agent generates plans and sends approval requests but will not execute any changes.'
              : 'The agent will execute approved remediation plans. Changes will be applied to your infrastructure.'}
          </div>
        </div>
        <button
          onClick={() => onDryRunChange(!dryRun)}
          className={`relative inline-flex h-6 w-11 flex-shrink-0 items-center rounded-full transition-colors mt-0.5 ${!dryRun ? 'bg-green-600' : 'bg-gray-300'}`}
        >
          <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${!dryRun ? 'translate-x-6' : 'translate-x-1'}`} />
        </button>
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-700 mb-3">Remediation Modes</label>
        <div className="space-y-2">
          {MODES.map(mode => (
            <label key={mode.value} className={`flex items-start gap-3 p-3 rounded-lg border cursor-pointer transition-colors ${value.enabled_modes.includes(mode.value) ? 'border-blue-500 bg-blue-50' : 'border-gray-200 hover:border-gray-300'}`}>
              <input
                type="checkbox"
                checked={value.enabled_modes.includes(mode.value)}
                onChange={() => toggleMode(mode.value)}
                className="mt-0.5"
              />
              <div>
                <div className="text-sm font-medium text-gray-900">{mode.label}</div>
                <div className="text-xs text-gray-500">{mode.description}</div>
              </div>
            </label>
          ))}
        </div>
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-700 mb-1">Max blast radius for auto-approve</label>
        <p className="text-xs text-gray-500 mb-2">Maximum number of downstream prod dependencies for a finding to be auto-approved.</p>
        <input
          type="number"
          min={0}
          max={20}
          value={value.max_blast_radius_for_auto}
          onChange={e => onChange({ ...value, max_blast_radius_for_auto: Number(e.target.value) })}
          className="w-24 border border-gray-300 rounded px-3 py-2 text-sm"
        />
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-700 mb-1">GitOps Repository (optional)</label>
        <p className="text-xs text-gray-500 mb-2">For Terraform-based remediations, the agent will open a PR to this repo.</p>
        <input
          type="text"
          placeholder="https://github.com/your-org/infra"
          value={value.gitops_repo ?? ''}
          onChange={e => onChange({ ...value, gitops_repo: e.target.value || undefined })}
          className="w-full border border-gray-300 rounded px-3 py-2 text-sm"
        />
        {value.gitops_repo && (
          <div className="mt-2">
            <label className="block text-xs text-gray-500 mb-1">Base branch</label>
            <input
              type="text"
              value={value.gitops_branch}
              onChange={e => onChange({ ...value, gitops_branch: e.target.value })}
              className="w-40 border border-gray-300 rounded px-3 py-2 text-sm"
            />
          </div>
        )}
      </div>
    </div>
  );
}
