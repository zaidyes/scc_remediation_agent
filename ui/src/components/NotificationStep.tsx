import React from 'react';
import { NotificationConfig } from '../api/config';

interface Props {
  value: NotificationConfig;
  onChange: (n: NotificationConfig) => void;
}

export default function NotificationStep({ value, onChange }: Props) {
  const [emailInput, setEmailInput] = React.useState('');

  const addEmail = () => {
    const trimmed = emailInput.trim();
    if (trimmed && !value.email_digest_recipients.includes(trimmed)) {
      onChange({ ...value, email_digest_recipients: [...value.email_digest_recipients, trimmed] });
    }
    setEmailInput('');
  };

  const removeEmail = (email: string) =>
    onChange({ ...value, email_digest_recipients: value.email_digest_recipients.filter(e => e !== email) });

  return (
    <div className="space-y-6">
      <div className="p-4 bg-blue-50 border border-blue-200 rounded-lg text-sm text-blue-800">
        Configure how the agent notifies your team when a finding requires approval or when a remediation completes.
        Credentials are stored in Secret Manager — paste the values here and they will be saved securely on activation.
      </div>

      <div className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">Google Chat Space</label>
          <p className="text-xs text-gray-500 mb-2">The space ID where approval cards will be sent (e.g. <span className="font-mono">spaces/XXXXXXXX</span>).</p>
          <input
            type="text"
            placeholder="spaces/XXXXXXXX"
            value={value.google_chat_space ?? ''}
            onChange={e => onChange({ ...value, google_chat_space: e.target.value || undefined })}
            className="w-full border border-gray-300 rounded px-3 py-2 text-sm"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">PagerDuty Service Key</label>
          <p className="text-xs text-gray-500 mb-2">Events API v2 integration key from your PagerDuty service.</p>
          <input
            type="password"
            placeholder="••••••••••••••••"
            value={value.pagerduty_service_key ?? ''}
            onChange={e => onChange({ ...value, pagerduty_service_key: e.target.value || undefined })}
            className="w-full border border-gray-300 rounded px-3 py-2 text-sm"
          />
        </div>

        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Jira Base URL</label>
            <input
              type="text"
              placeholder="https://your-org.atlassian.net"
              value={value.jira_base_url ?? ''}
              onChange={e => onChange({ ...value, jira_base_url: e.target.value || undefined })}
              className="w-full border border-gray-300 rounded px-3 py-2 text-sm"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Jira Project Key</label>
            <input
              type="text"
              placeholder="SEC"
              value={value.jira_project_key ?? ''}
              onChange={e => onChange({ ...value, jira_project_key: e.target.value || undefined })}
              className="w-full border border-gray-300 rounded px-3 py-2 text-sm"
            />
          </div>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">Email Digest Recipients</label>
          <p className="text-xs text-gray-500 mb-2">Daily summary of agent activity sent to these addresses.</p>
          <div className="flex gap-2 mb-2">
            <input
              type="email"
              placeholder="security-team@acme.com"
              value={emailInput}
              onChange={e => setEmailInput(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && addEmail()}
              className="flex-1 border border-gray-300 rounded px-3 py-2 text-sm"
            />
            <button onClick={addEmail} className="px-3 py-2 bg-blue-600 text-white rounded text-sm">Add</button>
          </div>
          <div className="flex flex-wrap gap-2">
            {value.email_digest_recipients.map(email => (
              <span key={email} className="inline-flex items-center gap-1 bg-gray-100 text-gray-700 text-xs px-2 py-1 rounded-full">
                {email}
                <button onClick={() => removeEmail(email)} className="text-gray-400 hover:text-gray-700 font-bold">×</button>
              </span>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
