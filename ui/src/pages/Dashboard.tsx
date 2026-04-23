import React from 'react';

const Dashboard = () => {
  return (
    <div className="p-6 max-w-6xl mx-auto">
      <h1 className="text-3xl font-bold mb-8">SCC Remediation Agent Dashboard</h1>

      <div className="grid grid-cols-4 gap-6 mb-8">
        <div className="bg-white p-6 rounded-lg shadow">
          <h3 className="text-gray-500 text-sm font-medium">Findings in Scope</h3>
          <p className="text-3xl font-bold text-gray-900 mt-2">124</p>
        </div>
        <div className="bg-white p-6 rounded-lg shadow">
          <h3 className="text-gray-500 text-sm font-medium">Pending Approvals</h3>
          <p className="text-3xl font-bold text-yellow-600 mt-2">12</p>
        </div>
        <div className="bg-white p-6 rounded-lg shadow">
          <h3 className="text-gray-500 text-sm font-medium">Remediated (7d)</h3>
          <p className="text-3xl font-bold text-green-600 mt-2">45</p>
        </div>
        <div className="bg-white p-6 rounded-lg shadow">
          <h3 className="text-gray-500 text-sm font-medium">Escalations</h3>
          <p className="text-3xl font-bold text-red-600 mt-2">3</p>
        </div>
      </div>

      <div className="bg-white rounded-lg shadow overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-200">
          <h2 className="text-xl font-semibold">Recent Active Findings</h2>
        </div>
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Severity</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Asset</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Category</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
            </tr>
          </thead>
          <tbody className="bg-white divide-y divide-gray-200">
            <tr>
              <td className="px-6 py-4 whitespace-nowrap"><span className="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-red-100 text-red-800">CRITICAL</span></td>
              <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">compute-instance-prod-1</td>
              <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">VULNERABILITY</td>
              <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">Awaiting Approval</td>
            </tr>
            <tr>
              <td className="px-6 py-4 whitespace-nowrap"><span className="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-orange-100 text-orange-800">HIGH</span></td>
              <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">gke-cluster-dev</td>
              <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">MISCONFIGURATION</td>
              <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">Triaging</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default Dashboard;
