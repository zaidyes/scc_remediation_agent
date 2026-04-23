import React, { useEffect, useState } from 'react';
import { getAuditLog, AuditEntry } from '../api/config';

const CUSTOMER_ID = (window as any).__CUSTOMER_ID__ ?? 'default';

const EVENT_COLORS: Record<string, string> = {
  APPROVAL_APPROVED: 'border-green-500',
  APPROVAL_REJECTED: 'border-red-400',
  APPROVAL_DEFERRED: 'border-gray-400',
  APPROVAL_REQUESTED: 'border-blue-500',
  REMEDIATION_EXECUTED: 'border-purple-500',
  VERIFICATION_SUCCESS: 'border-green-400',
  VERIFICATION_FAILED: 'border-red-500',
  ESCALATION: 'border-orange-500',
  TRIAGE_COMPLETE: 'border-blue-300',
};

const EVENT_LABELS: Record<string, string> = {
  APPROVAL_APPROVED: 'Approved',
  APPROVAL_REJECTED: 'Rejected',
  APPROVAL_DEFERRED: 'Deferred',
  APPROVAL_REQUESTED: 'Approval Requested',
  REMEDIATION_EXECUTED: 'Remediation Executed',
  VERIFICATION_SUCCESS: 'Verification Successful',
  VERIFICATION_FAILED: 'Verification Failed',
  ESCALATION: 'Escalated',
  TRIAGE_COMPLETE: 'Triage Complete',
};

export default function AuditLog() {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [nextToken, setNextToken] = useState<string | null>(null);
  const [loadingMore, setLoadingMore] = useState(false);
  const [filter, setFilter] = useState('');

  useEffect(() => {
    getAuditLog(CUSTOMER_ID)
      .then(r => { setEntries(r.entries); setNextToken(r.next_page_token); })
      .finally(() => setLoading(false));
  }, []);

  const loadMore = async () => {
    if (!nextToken) return;
    setLoadingMore(true);
    const r = await getAuditLog(CUSTOMER_ID, 50, nextToken).catch(() => null);
    if (r) {
      setEntries(prev => [...prev, ...r.entries]);
      setNextToken(r.next_page_token);
    }
    setLoadingMore(false);
  };

  const filtered = filter
    ? entries.filter(e =>
        e.event_type.toLowerCase().includes(filter.toLowerCase()) ||
        e.asset_name?.toLowerCase().includes(filter.toLowerCase()) ||
        e.finding_id?.toLowerCase().includes(filter.toLowerCase()) ||
        e.detail.toLowerCase().includes(filter.toLowerCase())
      )
    : entries;

  return (
    <div className="p-6 max-w-4xl mx-auto space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900">Audit Log</h1>
        <input
          type="text"
          placeholder="Filter by asset, event, finding…"
          value={filter}
          onChange={e => setFilter(e.target.value)}
          className="border border-gray-300 rounded px-3 py-2 text-sm w-64"
        />
      </div>

      {loading ? (
        <div className="text-gray-400 text-sm py-8">Loading audit log…</div>
      ) : filtered.length === 0 ? (
        <div className="text-gray-400 text-sm py-8">No entries found.</div>
      ) : (
        <div className="bg-white shadow rounded-lg divide-y divide-gray-100">
          {filtered.map(entry => (
            <div key={entry.entry_id} className={`border-l-4 px-5 py-4 ${EVENT_COLORS[entry.event_type] ?? 'border-gray-300'}`}>
              <div className="flex items-start justify-between gap-4">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-sm font-semibold text-gray-900">
                      {EVENT_LABELS[entry.event_type] ?? entry.event_type}
                    </span>
                    <span className="text-xs text-gray-400">{entry.actor}</span>
                  </div>
                  <p className="text-sm text-gray-700">{entry.detail}</p>
                  {(entry.finding_id || entry.asset_name) && (
                    <div className="flex items-center gap-3 mt-1.5">
                      {entry.finding_id && (
                        <span className="text-xs font-mono bg-gray-100 text-gray-600 px-1.5 py-0.5 rounded">{entry.finding_id}</span>
                      )}
                      {entry.asset_name && (
                        <span className="text-xs text-gray-400 truncate">{entry.asset_name.split('/').pop()}</span>
                      )}
                    </div>
                  )}
                </div>
                <time className="text-xs text-gray-400 whitespace-nowrap flex-shrink-0">
                  {new Date(entry.timestamp).toLocaleString()}
                </time>
              </div>
            </div>
          ))}
        </div>
      )}

      {nextToken && (
        <div className="text-center">
          <button
            onClick={loadMore}
            disabled={loadingMore}
            className="px-4 py-2 bg-gray-100 text-gray-700 rounded text-sm hover:bg-gray-200 disabled:opacity-50"
          >
            {loadingMore ? 'Loading…' : 'Load more'}
          </button>
        </div>
      )}
    </div>
  );
}
