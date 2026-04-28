import React, { useState } from 'react';

export interface PreflightResult {
  check: string;
  result: 'PASS' | 'WARN' | 'BLOCK';
  detail: string;
}

interface Props {
  results: PreflightResult[];
  defaultExpanded?: boolean;
}

const RESULT_CONFIG = {
  PASS:  { icon: '✅', label: 'Pass',  row: 'bg-white',      badge: 'text-green-700 bg-green-50' },
  WARN:  { icon: '⚠️', label: 'Warn',  row: 'bg-yellow-50',  badge: 'text-yellow-700 bg-yellow-50' },
  BLOCK: { icon: '🚫', label: 'Block', row: 'bg-red-50',     badge: 'text-red-700 bg-red-50' },
};

export default function PreflightChecklist({ results, defaultExpanded = false }: Props) {
  const [expanded, setExpanded] = useState(defaultExpanded);

  if (!results || results.length === 0) {
    return <span className="text-xs text-gray-400">No pre-flight checks recorded.</span>;
  }

  const blocks = results.filter(r => r.result === 'BLOCK').length;
  const warns  = results.filter(r => r.result === 'WARN').length;
  const passes = results.filter(r => r.result === 'PASS').length;

  return (
    <div className="border border-gray-200 rounded-md overflow-hidden">
      <button
        className="w-full flex items-center justify-between px-3 py-2 bg-gray-50 text-sm font-medium text-gray-700 hover:bg-gray-100"
        onClick={() => setExpanded(e => !e)}
      >
        <span>Pre-flight checks</span>
        <div className="flex items-center gap-2">
          {blocks > 0 && <span className="text-xs px-1.5 py-0.5 rounded bg-red-100 text-red-700">{blocks} block</span>}
          {warns  > 0 && <span className="text-xs px-1.5 py-0.5 rounded bg-yellow-100 text-yellow-700">{warns} warn</span>}
          {passes > 0 && <span className="text-xs px-1.5 py-0.5 rounded bg-green-100 text-green-700">{passes} pass</span>}
          <span className="text-gray-400 ml-1">{expanded ? '▲' : '▼'}</span>
        </div>
      </button>

      {expanded && (
        <table className="min-w-full divide-y divide-gray-100 text-xs">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-3 py-2 text-left font-medium text-gray-500 uppercase tracking-wider w-6"></th>
              <th className="px-3 py-2 text-left font-medium text-gray-500 uppercase tracking-wider">Check</th>
              <th className="px-3 py-2 text-left font-medium text-gray-500 uppercase tracking-wider">Result</th>
              <th className="px-3 py-2 text-left font-medium text-gray-500 uppercase tracking-wider">Detail</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100">
            {results.map((r, i) => {
              const cfg = RESULT_CONFIG[r.result] ?? RESULT_CONFIG.WARN;
              return (
                <tr key={i} className={cfg.row}>
                  <td className="px-3 py-2">{cfg.icon}</td>
                  <td className="px-3 py-2 font-mono text-gray-800">{r.check}</td>
                  <td className="px-3 py-2">
                    <span className={`px-1.5 py-0.5 rounded font-semibold ${cfg.badge}`}>{cfg.label}</span>
                  </td>
                  <td className="px-3 py-2 text-gray-600">{r.detail}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </div>
  );
}
