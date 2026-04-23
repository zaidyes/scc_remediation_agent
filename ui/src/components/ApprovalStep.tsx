import React, { useState } from 'react';
import { ApprovalPolicy, Approver, MaintenanceWindow } from '../api/config';

const DAYS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const CHANNELS = ['google_chat', 'pagerduty', 'jira'];

interface Props {
  value: ApprovalPolicy;
  onChange: (p: ApprovalPolicy) => void;
}

export default function ApprovalStep({ value, onChange }: Props) {
  const [newApprover, setNewApprover] = useState<Partial<Approver>>({
    severity_levels: [], channel: 'google_chat',
  });

  const updateWindow = (patch: Partial<MaintenanceWindow>) =>
    onChange({ ...value, default_maintenance_window: { ...value.default_maintenance_window, ...patch } });

  const toggleDay = (day: number) => {
    const days = value.default_maintenance_window.days_of_week;
    updateWindow({ days_of_week: days.includes(day) ? days.filter(d => d !== day) : [...days, day].sort() });
  };

  const toggleChannel = (ch: string) => {
    const channels = value.notification_channels;
    onChange({
      ...value,
      notification_channels: channels.includes(ch) ? channels.filter(c => c !== ch) : [...channels, ch],
    });
  };

  const toggleApproverSeverity = (sev: string) => {
    const sevs = newApprover.severity_levels ?? [];
    setNewApprover({ ...newApprover, severity_levels: sevs.includes(sev) ? sevs.filter(s => s !== sev) : [...sevs, sev] });
  };

  const addApprover = () => {
    if (!newApprover.name || !newApprover.address || !newApprover.severity_levels?.length) return;
    const approver: Approver = {
      name: newApprover.name!,
      type: newApprover.type ?? 'email',
      address: newApprover.address!,
      severity_levels: newApprover.severity_levels!,
      channel: newApprover.channel ?? 'google_chat',
      fallback_address: newApprover.fallback_address,
    };
    onChange({ ...value, approvers: [...value.approvers, approver] });
    setNewApprover({ severity_levels: [], channel: 'google_chat' });
  };

  const removeApprover = (i: number) =>
    onChange({ ...value, approvers: value.approvers.filter((_, idx) => idx !== i) });

  const w = value.default_maintenance_window;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between p-3 bg-gray-50 rounded-lg border border-gray-200">
        <div>
          <div className="text-sm font-medium text-gray-900">Auto-approve eligible findings</div>
          <div className="text-xs text-gray-500">Dormant assets with zero prod downstream dependencies</div>
        </div>
        <button
          onClick={() => onChange({ ...value, auto_approve_enabled: !value.auto_approve_enabled })}
          className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${value.auto_approve_enabled ? 'bg-blue-600' : 'bg-gray-300'}`}
        >
          <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${value.auto_approve_enabled ? 'translate-x-6' : 'translate-x-1'}`} />
        </button>
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-700 mb-3">Default Maintenance Window</label>
        <div className="flex gap-2 mb-3">
          {DAYS.map((day, i) => (
            <button
              key={i}
              onClick={() => toggleDay(i)}
              className={`w-10 h-10 rounded-full text-xs font-medium transition-colors ${w.days_of_week.includes(i) ? 'bg-blue-600 text-white' : 'bg-gray-100 text-gray-600 hover:bg-gray-200'}`}
            >
              {day}
            </button>
          ))}
        </div>
        <div className="flex gap-4 items-center">
          <div>
            <label className="block text-xs text-gray-500 mb-1">Start (UTC)</label>
            <input type="time" value={w.start_time_utc} onChange={e => updateWindow({ start_time_utc: e.target.value })} className="border border-gray-300 rounded px-2 py-1 text-sm" />
          </div>
          <div>
            <label className="block text-xs text-gray-500 mb-1">End (UTC)</label>
            <input type="time" value={w.end_time_utc} onChange={e => updateWindow({ end_time_utc: e.target.value })} className="border border-gray-300 rounded px-2 py-1 text-sm" />
          </div>
          <div>
            <label className="block text-xs text-gray-500 mb-1">Timezone</label>
            <select value={w.timezone} onChange={e => updateWindow({ timezone: e.target.value })} className="border border-gray-300 rounded px-2 py-1 text-sm">
              <option value="UTC">UTC</option>
              <option value="America/New_York">Eastern</option>
              <option value="America/Los_Angeles">Pacific</option>
              <option value="Europe/London">London</option>
              <option value="Europe/Berlin">Berlin</option>
              <option value="Asia/Tokyo">Tokyo</option>
            </select>
          </div>
        </div>
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-700 mb-3">Approvers</label>
        {value.approvers.length > 0 && (
          <div className="mb-3 space-y-2">
            {value.approvers.map((a, i) => (
              <div key={i} className="flex items-center justify-between p-2 bg-gray-50 rounded border border-gray-200 text-sm">
                <div>
                  <span className="font-medium">{a.name}</span>
                  <span className="text-gray-500 ml-2">{a.address}</span>
                  <span className="ml-2">{a.severity_levels.map(s => <span key={s} className="text-xs bg-orange-100 text-orange-700 px-1 rounded ml-1">{s}</span>)}</span>
                </div>
                <button onClick={() => removeApprover(i)} className="text-red-400 hover:text-red-600 font-bold">×</button>
              </div>
            ))}
          </div>
        )}
        <div className="border border-gray-200 rounded p-3 space-y-2 bg-gray-50">
          <div className="grid grid-cols-2 gap-2">
            <input className="border border-gray-300 rounded px-2 py-1 text-sm" placeholder="Name" value={newApprover.name ?? ''} onChange={e => setNewApprover({ ...newApprover, name: e.target.value })} />
            <input className="border border-gray-300 rounded px-2 py-1 text-sm" placeholder="Email or group address" value={newApprover.address ?? ''} onChange={e => setNewApprover({ ...newApprover, address: e.target.value })} />
          </div>
          <div className="flex gap-2 items-center">
            <span className="text-xs text-gray-500">Approves:</span>
            {SEVERITIES.map(s => (
              <button key={s} onClick={() => toggleApproverSeverity(s)} className={`text-xs px-2 py-1 rounded ${newApprover.severity_levels?.includes(s) ? 'bg-orange-500 text-white' : 'bg-gray-200 text-gray-600'}`}>{s}</button>
            ))}
          </div>
          <div className="flex gap-2 items-center">
            <span className="text-xs text-gray-500">Via:</span>
            <select value={newApprover.channel} onChange={e => setNewApprover({ ...newApprover, channel: e.target.value })} className="border border-gray-300 rounded px-2 py-1 text-xs">
              {CHANNELS.map(c => <option key={c} value={c}>{c}</option>)}
            </select>
            <button onClick={addApprover} className="ml-auto px-3 py-1 bg-blue-600 text-white rounded text-sm">Add approver</button>
          </div>
        </div>
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-700 mb-2">Notification Channels</label>
        <div className="flex gap-3">
          {CHANNELS.map(ch => (
            <label key={ch} className="flex items-center gap-2 cursor-pointer">
              <input type="checkbox" checked={value.notification_channels.includes(ch)} onChange={() => toggleChannel(ch)} />
              <span className="text-sm text-gray-700">{ch.replace('_', ' ')}</span>
            </label>
          ))}
        </div>
      </div>
    </div>
  );
}
