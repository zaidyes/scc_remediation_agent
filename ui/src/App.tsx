import React, { useState } from 'react';
import Dashboard from './pages/Dashboard';
import ConfigWizard from './pages/ConfigWizard';
import AuditLog from './pages/AuditLog';
import Policies from './pages/Policies';

type Page = 'dashboard' | 'policies' | 'config' | 'audit';

const NAV: { id: Page; label: string }[] = [
  { id: 'dashboard', label: 'Dashboard' },
  { id: 'policies',  label: 'Policies' },
  { id: 'config',    label: 'Config' },
  { id: 'audit',     label: 'Audit Log' },
];

export default function App() {
  const [page, setPage] = useState<Page>(() => {
    const hash = window.location.hash.replace('#', '') as Page;
    return NAV.some(n => n.id === hash) ? hash : 'dashboard';
  });

  const navigate = (p: Page) => {
    setPage(p);
    window.location.hash = p;
  };

  return (
    <div className="min-h-screen bg-gray-50">
      <nav className="bg-white border-b border-gray-200 sticky top-0 z-40">
        <div className="max-w-6xl mx-auto px-6 flex items-center gap-1 h-12">
          <span className="text-sm font-bold text-gray-900 mr-6 tracking-tight">SCC Remediation</span>
          {NAV.map(n => (
            <button
              key={n.id}
              onClick={() => navigate(n.id)}
              className={`px-3 py-1.5 text-sm rounded font-medium transition-colors ${
                page === n.id
                  ? 'bg-blue-50 text-blue-700'
                  : 'text-gray-600 hover:text-gray-900 hover:bg-gray-100'
              }`}
            >
              {n.label}
            </button>
          ))}
        </div>
      </nav>

      <main>
        {page === 'dashboard' && <Dashboard />}
        {page === 'policies'  && <Policies />}
        {page === 'config'    && <ConfigWizard />}
        {page === 'audit'     && <AuditLog />}
      </main>
    </div>
  );
}
