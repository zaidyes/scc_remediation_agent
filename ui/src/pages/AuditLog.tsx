import React from 'react';

const AuditLog = () => {
  return (
    <div className="p-6 max-w-6xl mx-auto">
      <h1 className="text-3xl font-bold mb-8">Audit Log</h1>
      
      <div className="bg-white shadow rounded-lg p-6">
        <div className="border-l-4 border-blue-500 pl-4 py-2 mb-6">
          <p className="text-sm text-gray-500">2026-04-23 10:45:00 UTC</p>
          <p className="font-semibold text-gray-900 mt-1">Approval Requested</p>
          <p className="text-gray-600 mt-1">Sent approval card for finding <span className="font-mono bg-gray-100 px-1 rounded">f-12345</span> on <span className="font-mono bg-gray-100 px-1 rounded">compute-instance-prod-1</span> to Google Chat.</p>
        </div>

        <div className="border-l-4 border-green-500 pl-4 py-2 mb-6">
          <p className="text-sm text-gray-500">2026-04-23 10:50:12 UTC</p>
          <p className="font-semibold text-gray-900 mt-1">Remediation Approved</p>
          <p className="text-gray-600 mt-1">Approved by admin@example.com via Google Chat. Patch job execution scheduled.</p>
        </div>

        <div className="border-l-4 border-purple-500 pl-4 py-2">
          <p className="text-sm text-gray-500">2026-04-23 11:05:00 UTC</p>
          <p className="font-semibold text-gray-900 mt-1">Verification Successful</p>
          <p className="text-gray-600 mt-1">SCC confirmed finding <span className="font-mono bg-gray-100 px-1 rounded">f-12345</span> is resolved. Finding muted.</p>
        </div>
      </div>
    </div>
  );
};

export default AuditLog;
