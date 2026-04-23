import React, { useState, useEffect } from 'react';
import ScopeStep from '../components/ScopeStep';
import SeverityStep from '../components/SeverityStep';
import ApprovalStep from '../components/ApprovalStep';
import ExecutionStep from '../components/ExecutionStep';
import NotificationStep from '../components/NotificationStep';
import {
  CustomerConfig, getConfig, saveConfig, validateConfig, simulate,
} from '../api/config';

const CUSTOMER_ID = (window as any).__CUSTOMER_ID__ ?? 'default';

const EMPTY_CONFIG: Partial<CustomerConfig> = {
  dry_run: true,
  scope: { project_ids: [], folder_ids: [], include_labels: [], exclude_labels: [] },
  severity_threshold: 'HIGH_PLUS',
  filters: {
    require_active_exposure_path: true,
    exclude_dormant_assets: false,
    deduplicate_across_scanners: true,
    exclude_accepted_risks: true,
  },
  approval_policy: {
    tiers: [],
    approvers: [],
    auto_approve_enabled: true,
    notification_channels: [],
    default_maintenance_window: {
      days_of_week: [1, 2, 3, 4],
      start_time_utc: '02:00',
      end_time_utc: '05:00',
      timezone: 'UTC',
    },
  },
  execution: {
    enabled_modes: ['OS_PATCH'],
    max_blast_radius_for_auto: 5,
    gitops_branch: 'main',
  },
  notifications: { email_digest_recipients: [] },
};

const STEPS = ['Scope', 'Severity & Filters', 'Approval Policy', 'Execution', 'Notifications'];

export default function ConfigWizard() {
  const [step, setStep] = useState(1);
  const [config, setConfig] = useState<Partial<CustomerConfig>>(EMPTY_CONFIG);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [errors, setErrors] = useState<string[]>([]);
  const [warnings, setWarnings] = useState<string[]>([]);
  const [showSimulation, setShowSimulation] = useState(false);
  const [simulation, setSimulation] = useState<any>(null);

  useEffect(() => {
    getConfig(CUSTOMER_ID)
      .then(existing => setConfig(existing))
      .catch(() => {/* new customer, use empty config */})
      .finally(() => setLoading(false));
  }, []);

  const patch = (partial: Partial<CustomerConfig>) =>
    setConfig(prev => ({ ...prev, ...partial }));

  const validateStep = async (): Promise<boolean> => {
    const result = await validateConfig(config).catch(() => null);
    if (!result) return true; // network error, allow proceeding
    setErrors(result.errors);
    setWarnings(result.warnings);
    return result.errors.length === 0;
  };

  const handleNext = async () => {
    const valid = await validateStep();
    if (!valid) return;
    if (step === 5) {
      handleActivate();
    } else {
      setStep(s => s + 1);
    }
  };

  const handleActivate = async () => {
    const sim = await simulate(config).catch(() => null);
    if (sim) {
      setSimulation(sim);
      setShowSimulation(true);
    } else {
      await doSave();
    }
  };

  const doSave = async () => {
    setSaving(true);
    try {
      await saveConfig(CUSTOMER_ID, { ...config, customer_id: CUSTOMER_ID });
      alert('Agent activated successfully.');
    } catch (e: any) {
      alert(`Save failed: ${e.message}`);
    } finally {
      setSaving(false);
      setShowSimulation(false);
    }
  };

  if (loading) return <div className="p-8 text-gray-500">Loading configuration…</div>;

  return (
    <div className="wizard-container p-6 max-w-4xl mx-auto">
      {config.dry_run && (
        <div className="bg-yellow-100 border-l-4 border-yellow-500 text-yellow-800 p-4 mb-6 rounded">
          <p className="font-bold">Dry-run mode active</p>
          <p className="text-sm">The agent generates plans but will not execute any changes until you enable execution in Step 4.</p>
        </div>
      )}

      {/* Step indicators */}
      <div className="flex mb-8">
        {STEPS.map((title, i) => {
          const num = i + 1;
          const active = step === num;
          const done = step > num;
          return (
            <div key={num} className="flex-1 flex flex-col items-center">
              <button
                onClick={() => done && setStep(num)}
                className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-medium transition-colors ${active ? 'bg-blue-600 text-white' : done ? 'bg-green-500 text-white cursor-pointer' : 'bg-gray-200 text-gray-500'}`}
              >
                {done ? '✓' : num}
              </button>
              <div className={`mt-1 text-xs text-center ${active ? 'text-blue-600 font-medium' : 'text-gray-500'}`}>{title}</div>
              {i < STEPS.length - 1 && <div className={`absolute hidden`} />}
            </div>
          );
        })}
      </div>

      {/* Validation messages */}
      {errors.length > 0 && (
        <div className="bg-red-50 border border-red-200 rounded p-3 mb-4">
          {errors.map((e, i) => <p key={i} className="text-sm text-red-700">✗ {e}</p>)}
        </div>
      )}
      {warnings.length > 0 && (
        <div className="bg-yellow-50 border border-yellow-200 rounded p-3 mb-4">
          {warnings.map((w, i) => <p key={i} className="text-sm text-yellow-700">⚠ {w}</p>)}
        </div>
      )}

      {/* Step content */}
      <div className="bg-white shadow-md rounded-lg p-6 mb-6">
        <h2 className="text-xl font-bold mb-5">{STEPS[step - 1]}</h2>

        {step === 1 && (
          <ScopeStep
            value={config.scope!}
            onChange={scope => patch({ scope })}
          />
        )}
        {step === 2 && (
          <SeverityStep
            severity={config.severity_threshold!}
            filters={config.filters as any}
            onSeverityChange={severity_threshold => patch({ severity_threshold })}
            onFiltersChange={filters => patch({ filters: filters as any })}
          />
        )}
        {step === 3 && (
          <ApprovalStep
            value={config.approval_policy!}
            onChange={approval_policy => patch({ approval_policy })}
          />
        )}
        {step === 4 && (
          <ExecutionStep
            value={config.execution!}
            dryRun={config.dry_run!}
            onChange={execution => patch({ execution })}
            onDryRunChange={dry_run => patch({ dry_run })}
          />
        )}
        {step === 5 && (
          <NotificationStep
            value={config.notifications!}
            onChange={notifications => patch({ notifications })}
          />
        )}
      </div>

      {/* Navigation */}
      <div className="flex justify-between">
        <button
          className="px-4 py-2 bg-gray-200 text-gray-700 rounded disabled:opacity-40"
          disabled={step === 1}
          onClick={() => { setErrors([]); setWarnings([]); setStep(s => s - 1); }}
        >
          Back
        </button>
        <button
          className={`px-6 py-2 rounded font-medium text-white ${step === 5 ? 'bg-green-600 hover:bg-green-700' : 'bg-blue-600 hover:bg-blue-700'}`}
          onClick={handleNext}
        >
          {step === 5 ? 'Activate Agent' : 'Save & Continue'}
        </button>
      </div>

      {/* Simulation modal */}
      {showSimulation && simulation && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-white rounded-xl shadow-2xl p-6 max-w-lg w-full mx-4">
            <h3 className="text-lg font-bold mb-4">Activation preview</h3>
            <p className="text-sm text-gray-600 mb-4">Here's what the agent would do with your current configuration:</p>
            <div className="space-y-2 mb-4">
              <div className="flex justify-between text-sm border-b pb-2">
                <span className="text-gray-600">Assets in scope</span>
                <span className="font-semibold">{simulation.preview?.assets_in_scope ?? 0}</span>
              </div>
              <div className="flex justify-between text-sm border-b pb-2">
                <span className="text-gray-600">Active findings in scope</span>
                <span className="font-semibold">{simulation.preview?.active_findings_in_scope ?? 0}</span>
              </div>
              <div className="flex justify-between text-sm border-b pb-2">
                <span className="text-gray-600">Estimated auto-approve</span>
                <span className="font-semibold">{simulation.preview?.estimated_auto_approve ?? 0}</span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-gray-600">Dry-run active</span>
                <span className={`font-semibold ${simulation.preview?.dry_run_active ? 'text-yellow-600' : 'text-green-600'}`}>
                  {simulation.preview?.dry_run_active ? 'Yes' : 'No — changes will be applied'}
                </span>
              </div>
            </div>
            {simulation.approver_routing?.length > 0 && (
              <div className="mb-4">
                <p className="text-sm font-medium text-gray-700 mb-2">Approval routing:</p>
                {simulation.approver_routing.map((a: any, i: number) => (
                  <p key={i} className="text-xs text-gray-600">{a.name} ({a.address}) — {a.severities.join(', ')}</p>
                ))}
              </div>
            )}
            <div className="flex gap-3 justify-end">
              <button onClick={() => setShowSimulation(false)} className="px-4 py-2 bg-gray-200 text-gray-700 rounded text-sm">Cancel</button>
              <button onClick={doSave} disabled={saving} className="px-4 py-2 bg-green-600 text-white rounded text-sm font-medium">
                {saving ? 'Activating…' : 'Confirm & Activate'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
