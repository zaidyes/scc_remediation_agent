import React, { useEffect, useState } from 'react';
import {
  getPolicies,
  upsertPolicy,
  deletePolicy,
  simulatePolicy,
  ExecutionPolicy,
  PolicySimulationResult,
} from '../api/config';

const CUSTOMER_ID = (window as any).__CUSTOMER_ID__ ?? 'default';

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const REMEDIATION_TYPES = ['OS_PATCH', 'FIREWALL', 'IAM', 'MISCONFIGURATION', 'ANY'];
const BLAST_LEVELS = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

const EMPTY_POLICY: Omit<ExecutionPolicy, 'policy_id'> = {
  customer_id: CUSTOMER_ID,
  remediation_type: 'ANY',
  severity_levels: ['CRITICAL', 'HIGH'],
  finding_categories: [],
  asset_label_conditions: {},
  min_confidence_threshold: 0.90,
  max_blast_radius: 'LOW',
  tier: 1,
  active: true,
};

export default function Policies() {
  const [policies, setPolicies] = useState<ExecutionPolicy[]>([]);
  const [loading, setLoading] = useState(true);
  const [editing, setEditing] = useState<ExecutionPolicy | null>(null);
  const [isNew, setIsNew] = useState(false);
  const [simulating, setSimulating] = useState<string | null>(null);
  const [simResult, setSimResult] = useState<Record<string, PolicySimulationResult>>({});
  const [saving, setSaving] = useState(false);
  const [deleting, setDeleting] = useState<string | null>(null);
  const [ackEdgeCases, setAckEdgeCases] = useState(false);

  useEffect(() => {
    getPolicies(CUSTOMER_ID)
      .then(setPolicies)
      .finally(() => setLoading(false));
  }, []);

  const openNew = () => {
    setEditing({ policy_id: crypto.randomUUID(), ...EMPTY_POLICY, customer_id: CUSTOMER_ID });
    setIsNew(true);
    setAckEdgeCases(false);
  };

  const openEdit = (p: ExecutionPolicy) => {
    setEditing({ ...p });
    setIsNew(false);
    setAckEdgeCases(false);
  };

  const handleSave = async () => {
    if (!editing) return;
    if (editing.tier === 1 && !ackEdgeCases) {
      alert('Please acknowledge the edge cases before saving a Tier 1 (autonomous) policy.');
      return;
    }
    setSaving(true);
    try {
      const updated = await upsertPolicy(CUSTOMER_ID, editing);
      setPolicies(prev => {
        const idx = prev.findIndex(p => p.policy_id === updated.policy_id);
        return idx >= 0 ? prev.map(p => p.policy_id === updated.policy_id ? updated : p) : [...prev, updated];
      });
      setEditing(null);
    } catch (e: any) {
      alert(`Save failed: ${e.message}`);
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (policyId: string) => {
    if (!confirm('Delete this policy?')) return;
    setDeleting(policyId);
    try {
      await deletePolicy(CUSTOMER_ID, policyId);
      setPolicies(prev => prev.filter(p => p.policy_id !== policyId));
    } catch (e: any) {
      alert(`Delete failed: ${e.message}`);
    } finally {
      setDeleting(null);
    }
  };

  const handleSimulate = async (policyId: string) => {
    setSimulating(policyId);
    try {
      const result = await simulatePolicy(CUSTOMER_ID, policyId);
      setSimResult(prev => ({ ...prev, [policyId]: result }));
    } catch (e: any) {
      alert(`Simulation failed: ${e.message}`);
    } finally {
      setSimulating(null);
    }
  };

  const toggleSeverity = (sev: string) => {
    if (!editing) return;
    const has = editing.severity_levels.includes(sev);
    setEditing({
      ...editing,
      severity_levels: has
        ? editing.severity_levels.filter(s => s !== sev)
        : [...editing.severity_levels, sev],
    });
  };

  return (
    <div className="p-6 max-w-5xl mx-auto space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Execution Policies</h1>
          <p className="text-sm text-gray-500 mt-0.5">
            Define which findings the agent can remediate autonomously (Tier 1) or with a single tap (Tier 2).
          </p>
        </div>
        <button
          onClick={openNew}
          className="px-4 py-2 bg-blue-600 text-white text-sm rounded font-medium hover:bg-blue-700"
        >
          + New policy
        </button>
      </div>

      {loading ? (
        <div className="text-sm text-gray-400">Loading policies…</div>
      ) : policies.length === 0 ? (
        <div className="bg-white rounded-lg shadow p-8 text-center text-gray-400 text-sm">
          No policies configured. Create one to enable autonomous or policy-assisted remediation.
        </div>
      ) : (
        <div className="space-y-3">
          {policies.map(p => {
            const sim = simResult[p.policy_id];
            return (
              <div key={p.policy_id} className="bg-white rounded-lg shadow p-5 space-y-3">
                <div className="flex items-start justify-between gap-4">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className={`text-xs font-semibold px-2 py-0.5 rounded-full ${p.tier === 1 ? 'bg-green-100 text-green-800' : 'bg-yellow-100 text-yellow-800'}`}>
                        {p.tier === 1 ? 'Tier 1 — Autonomous' : 'Tier 2 — Policy-assisted'}
                      </span>
                      <span className="text-xs px-2 py-0.5 rounded bg-gray-100 text-gray-700">{p.remediation_type}</span>
                      {p.severity_levels.map(s => (
                        <span key={s} className="text-xs px-1.5 py-0.5 rounded bg-blue-50 text-blue-700">{s}</span>
                      ))}
                      {!p.active && (
                        <span className="text-xs px-1.5 py-0.5 rounded bg-gray-200 text-gray-500">Inactive</span>
                      )}
                    </div>
                    <p className="text-xs text-gray-500 mt-1.5">
                      Confidence ≥ {Math.round(p.min_confidence_threshold * 100)}% · Blast ≤ {p.max_blast_radius}
                    </p>
                    {p.asset_label_conditions && Object.keys(p.asset_label_conditions).length > 0 && (
                      <p className="text-xs text-gray-400 mt-0.5 font-mono">
                        Labels: {Object.entries(p.asset_label_conditions).map(([k, v]) => `${k}=${v}`).join(', ')}
                      </p>
                    )}
                  </div>
                  <div className="flex gap-2 flex-shrink-0">
                    <button
                      onClick={() => handleSimulate(p.policy_id)}
                      disabled={simulating === p.policy_id}
                      className="text-xs px-2.5 py-1.5 bg-gray-100 text-gray-700 rounded hover:bg-gray-200 disabled:opacity-50"
                    >
                      {simulating === p.policy_id ? 'Simulating…' : 'Simulate (30d)'}
                    </button>
                    <button
                      onClick={() => openEdit(p)}
                      className="text-xs px-2.5 py-1.5 bg-gray-100 text-gray-700 rounded hover:bg-gray-200"
                    >
                      Edit
                    </button>
                    <button
                      onClick={() => handleDelete(p.policy_id)}
                      disabled={deleting === p.policy_id}
                      className="text-xs px-2.5 py-1.5 bg-red-50 text-red-700 rounded hover:bg-red-100 disabled:opacity-50"
                    >
                      {deleting === p.policy_id ? '…' : 'Delete'}
                    </button>
                  </div>
                </div>

                {sim && (
                  <div className="border-t border-gray-100 pt-3">
                    <p className="text-xs font-semibold text-gray-600 mb-2">30-day simulation results</p>
                    <div className="grid grid-cols-3 gap-3 text-center">
                      {[
                        { label: 'Findings evaluated', value: sim.findings_evaluated, color: 'text-gray-800' },
                        { label: 'Would auto-execute (T1)', value: sim.would_execute_tier1, color: 'text-green-700' },
                        { label: 'Would prompt (T2)', value: sim.would_execute_tier2, color: 'text-yellow-700' },
                      ].map(c => (
                        <div key={c.label} className="bg-gray-50 rounded p-2">
                          <p className={`text-lg font-bold ${c.color}`}>{c.value}</p>
                          <p className="text-xs text-gray-500">{c.label}</p>
                        </div>
                      ))}
                    </div>
                    {sim.edge_cases && sim.edge_cases.length > 0 && (
                      <div className="mt-2 p-2 bg-orange-50 rounded border border-orange-200">
                        <p className="text-xs font-semibold text-orange-700 mb-1">Edge cases ({sim.edge_cases.length})</p>
                        <ul className="space-y-0.5">
                          {sim.edge_cases.slice(0, 5).map((ec, i) => (
                            <li key={i} className="text-xs text-orange-700">• {ec}</li>
                          ))}
                          {sim.edge_cases.length > 5 && (
                            <li className="text-xs text-orange-500">…and {sim.edge_cases.length - 5} more</li>
                          )}
                        </ul>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* Edit / New modal */}
      {editing && (
        <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl shadow-xl w-full max-w-lg max-h-[90vh] overflow-y-auto p-6 space-y-4">
            <h2 className="text-lg font-semibold text-gray-900">
              {isNew ? 'New execution policy' : 'Edit policy'}
            </h2>

            {/* Tier */}
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">Execution tier</label>
              <div className="flex gap-3">
                {[1, 2].map(t => (
                  <label key={t} className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="radio"
                      name="tier"
                      value={t}
                      checked={editing.tier === t}
                      onChange={() => setEditing({ ...editing, tier: t as 1 | 2 })}
                    />
                    <span className="text-sm">{t === 1 ? 'Tier 1 — Autonomous' : 'Tier 2 — Single-tap confirm'}</span>
                  </label>
                ))}
              </div>
            </div>

            {/* Remediation type */}
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">Remediation type</label>
              <select
                value={editing.remediation_type}
                onChange={e => setEditing({ ...editing, remediation_type: e.target.value })}
                className="w-full border border-gray-300 rounded px-3 py-1.5 text-sm"
              >
                {REMEDIATION_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
              </select>
            </div>

            {/* Severity levels */}
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">Severity levels</label>
              <div className="flex gap-2 flex-wrap">
                {SEVERITIES.map(s => (
                  <label key={s} className="flex items-center gap-1 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={editing.severity_levels.includes(s)}
                      onChange={() => toggleSeverity(s)}
                    />
                    <span className="text-sm">{s}</span>
                  </label>
                ))}
              </div>
            </div>

            {/* Confidence threshold */}
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">
                Min confidence threshold: {Math.round(editing.min_confidence_threshold * 100)}%
              </label>
              <input
                type="range"
                min={0}
                max={100}
                step={5}
                value={Math.round(editing.min_confidence_threshold * 100)}
                onChange={e => setEditing({ ...editing, min_confidence_threshold: parseInt(e.target.value) / 100 })}
                className="w-full"
              />
              <div className="flex justify-between text-xs text-gray-400 mt-0.5">
                <span>0%</span><span>50%</span><span>100%</span>
              </div>
            </div>

            {/* Max blast radius */}
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">Max blast radius</label>
              <select
                value={editing.max_blast_radius}
                onChange={e => setEditing({ ...editing, max_blast_radius: e.target.value })}
                className="w-full border border-gray-300 rounded px-3 py-1.5 text-sm"
              >
                {BLAST_LEVELS.map(b => <option key={b} value={b}>{b}</option>)}
              </select>
            </div>

            {/* Active toggle */}
            <div>
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={editing.active}
                  onChange={e => setEditing({ ...editing, active: e.target.checked })}
                />
                <span className="text-sm text-gray-700">Policy active</span>
              </label>
            </div>

            {/* Edge case acknowledgment for Tier 1 */}
            {editing.tier === 1 && (
              <div className="p-3 bg-orange-50 border border-orange-200 rounded space-y-2">
                <p className="text-xs font-semibold text-orange-700">
                  Tier 1 — Autonomous execution
                </p>
                <p className="text-xs text-orange-700">
                  This policy allows the agent to execute remediations without human approval.
                  Review the following before enabling:
                </p>
                <ul className="text-xs text-orange-700 list-disc list-inside space-y-0.5">
                  <li>Rollback artifacts will be created pre-execution</li>
                  <li>Regression monitoring runs for 30 minutes post-execution</li>
                  <li>HARD_BLOCK conditions will still stop execution</li>
                  <li>Production assets with blast level above {editing.max_blast_radius} are excluded</li>
                </ul>
                <label className="flex items-center gap-2 cursor-pointer mt-1">
                  <input
                    type="checkbox"
                    checked={ackEdgeCases}
                    onChange={e => setAckEdgeCases(e.target.checked)}
                  />
                  <span className="text-xs font-medium text-orange-800">
                    I understand the above and accept responsibility for autonomous remediations
                  </span>
                </label>
              </div>
            )}

            <div className="flex justify-end gap-3 pt-2 border-t border-gray-100">
              <button
                onClick={() => setEditing(null)}
                className="px-4 py-2 text-sm text-gray-600 hover:text-gray-800"
              >
                Cancel
              </button>
              <button
                onClick={handleSave}
                disabled={saving}
                className="px-4 py-2 bg-blue-600 text-white text-sm rounded font-medium hover:bg-blue-700 disabled:opacity-50"
              >
                {saving ? 'Saving…' : 'Save policy'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
