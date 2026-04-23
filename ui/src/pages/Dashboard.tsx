import React, { useEffect, useState } from 'react';
import { getActiveFindings, getPendingApprovals, respondToApproval, Finding, Approval } from '../api/config';

const CUSTOMER_ID = (window as any).__CUSTOMER_ID__ ?? 'default';

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: 'bg-red-100 text-red-800',
  HIGH: 'bg-orange-100 text-orange-800',
  MEDIUM: 'bg-yellow-100 text-yellow-800',
  LOW: 'bg-gray-100 text-gray-600',
};

const BLAST_COLORS: Record<string, string> = {
  CRITICAL: 'text-red-600',
  HIGH: 'text-orange-500',
  MEDIUM: 'text-yellow-600',
  LOW: 'text-green-600',
};

export default function Dashboard() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [approvals, setApprovals] = useState<Approval[]>([]);
  const [loadingFindings, setLoadingFindings] = useState(true);
  const [loadingApprovals, setLoadingApprovals] = useState(true);
  const [actionLoading, setActionLoading] = useState<string | null>(null);

  useEffect(() => {
    getActiveFindings(CUSTOMER_ID)
      .then(r => setFindings(r.findings))
      .finally(() => setLoadingFindings(false));

    getPendingApprovals(CUSTOMER_ID)
      .then(r => setApprovals(r.approvals))
      .finally(() => setLoadingApprovals(false));
  }, []);

  const handleApproval = async (approvalId: string, action: 'APPROVED' | 'REJECTED' | 'DEFERRED') => {
    setActionLoading(approvalId);
    try {
      await respondToApproval(approvalId, action, 'ui-user');
      setApprovals(prev => prev.filter(a => a.approval_id !== approvalId));
    } catch (e: any) {
      alert(`Action failed: ${e.message}`);
    } finally {
      setActionLoading(null);
    }
  };

  const remediatedThisWeek = findings.filter(f => f.agent_status === 'completed').length;
  const escalations = approvals.filter(a => a.escalation_count > 0).length;

  return (
    <div className="p-6 max-w-6xl mx-auto space-y-8">
      <h1 className="text-2xl font-bold text-gray-900">SCC Remediation Agent</h1>

      {/* Metric cards */}
      <div className="grid grid-cols-4 gap-4">
        {[
          { label: 'Findings in Scope', value: loadingFindings ? '…' : findings.length, color: 'text-gray-900' },
          { label: 'Pending Approvals', value: loadingApprovals ? '…' : approvals.length, color: 'text-yellow-600' },
          { label: 'Remediated (7d)', value: loadingFindings ? '…' : remediatedThisWeek, color: 'text-green-600' },
          { label: 'Open Escalations', value: loadingApprovals ? '…' : escalations, color: 'text-red-600' },
        ].map(card => (
          <div key={card.label} className="bg-white rounded-lg shadow p-5">
            <p className="text-xs font-medium text-gray-500 uppercase tracking-wide">{card.label}</p>
            <p className={`text-3xl font-bold mt-1 ${card.color}`}>{card.value}</p>
          </div>
        ))}
      </div>

      {/* Pending approvals */}
      {approvals.length > 0 && (
        <div className="bg-white rounded-lg shadow">
          <div className="px-5 py-4 border-b border-gray-100">
            <h2 className="text-base font-semibold text-gray-900">Pending Approvals</h2>
          </div>
          <div className="divide-y divide-gray-100">
            {approvals.map(approval => (
              <div key={approval.approval_id} className="px-5 py-4 flex items-start gap-4">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <span className={`text-xs font-semibold px-2 py-0.5 rounded-full ${SEVERITY_COLORS[approval.severity] ?? 'bg-gray-100 text-gray-600'}`}>
                      {approval.severity}
                    </span>
                    {approval.blast_level && (
                      <span className={`text-xs font-medium ${BLAST_COLORS[approval.blast_level] ?? ''}`}>
                        {approval.blast_level} blast
                      </span>
                    )}
                    {approval.escalation_count > 0 && (
                      <span className="text-xs bg-red-100 text-red-700 px-1.5 py-0.5 rounded">
                        Escalated ×{approval.escalation_count}
                      </span>
                    )}
                  </div>
                  <p className="text-sm font-medium text-gray-900 truncate">{approval.asset_name.split('/').pop()}</p>
                  <p className="text-xs text-gray-500 truncate mt-0.5">{approval.plan_summary}</p>
                  <p className="text-xs text-gray-400 mt-1">Expires {new Date(approval.expires_at).toLocaleString()}</p>
                </div>
                <div className="flex gap-2 flex-shrink-0">
                  <button
                    onClick={() => handleApproval(approval.approval_id, 'APPROVED')}
                    disabled={actionLoading === approval.approval_id}
                    className="px-3 py-1.5 bg-green-600 text-white text-xs rounded font-medium hover:bg-green-700 disabled:opacity-50"
                  >
                    Approve
                  </button>
                  <button
                    onClick={() => handleApproval(approval.approval_id, 'DEFERRED')}
                    disabled={actionLoading === approval.approval_id}
                    className="px-3 py-1.5 bg-gray-200 text-gray-700 text-xs rounded font-medium hover:bg-gray-300 disabled:opacity-50"
                  >
                    Defer
                  </button>
                  <button
                    onClick={() => handleApproval(approval.approval_id, 'REJECTED')}
                    disabled={actionLoading === approval.approval_id}
                    className="px-3 py-1.5 bg-red-100 text-red-700 text-xs rounded font-medium hover:bg-red-200 disabled:opacity-50"
                  >
                    Reject
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Active findings table */}
      <div className="bg-white rounded-lg shadow">
        <div className="px-5 py-4 border-b border-gray-100">
          <h2 className="text-base font-semibold text-gray-900">Active Findings</h2>
        </div>
        {loadingFindings ? (
          <div className="px-5 py-8 text-gray-400 text-sm">Loading findings…</div>
        ) : findings.length === 0 ? (
          <div className="px-5 py-8 text-gray-400 text-sm">No active findings in scope.</div>
        ) : (
          <table className="min-w-full divide-y divide-gray-100">
            <thead className="bg-gray-50">
              <tr>
                {['Severity', 'Asset', 'Category', 'Blast', 'Exposure', 'Status'].map(h => (
                  <th key={h} className="px-5 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {findings.map(f => (
                <tr key={f.finding_id} className="hover:bg-gray-50">
                  <td className="px-5 py-3 whitespace-nowrap">
                    <span className={`text-xs font-semibold px-2 py-0.5 rounded-full ${SEVERITY_COLORS[f.severity] ?? 'bg-gray-100 text-gray-600'}`}>
                      {f.severity}
                    </span>
                  </td>
                  <td className="px-5 py-3 max-w-xs">
                    <p className="text-sm text-gray-900 truncate font-mono">{f.short_name}</p>
                    <p className="text-xs text-gray-400 truncate">{f.resource_name.split('/projects/')[1]?.split('/')[0]}</p>
                  </td>
                  <td className="px-5 py-3 text-sm text-gray-600 whitespace-nowrap">{f.category}</td>
                  <td className="px-5 py-3 whitespace-nowrap">
                    {f.blast_level && (
                      <span className={`text-xs font-medium ${BLAST_COLORS[f.blast_level] ?? 'text-gray-500'}`}>{f.blast_level}</span>
                    )}
                  </td>
                  <td className="px-5 py-3 whitespace-nowrap">
                    <div className="w-16 bg-gray-200 rounded-full h-1.5">
                      <div
                        className="bg-orange-500 h-1.5 rounded-full"
                        style={{ width: `${Math.round(f.attack_exposure_score * 100)}%` }}
                      />
                    </div>
                    <span className="text-xs text-gray-400 mt-0.5">{Math.round(f.attack_exposure_score * 100)}%</span>
                  </td>
                  <td className="px-5 py-3 whitespace-nowrap">
                    <span className="text-xs text-gray-600 capitalize">{f.agent_status.replace(/_/g, ' ')}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
