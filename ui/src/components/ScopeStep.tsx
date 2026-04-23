import React, { useState, useEffect, useCallback } from 'react';
import { ScopeConfig, LabelFilter, previewScope } from '../api/config';

interface Props {
  value: ScopeConfig;
  onChange: (scope: ScopeConfig) => void;
}

export default function ScopeStep({ value, onChange }: Props) {
  const [projectInput, setProjectInput] = useState('');
  const [labelKey, setLabelKey] = useState('');
  const [labelVal, setLabelVal] = useState('');
  const [excludeKey, setExcludeKey] = useState('');
  const [excludeVal, setExcludeVal] = useState('');
  const [preview, setPreview] = useState<{ asset_count: number; filter_description: string } | null>(null);
  const [previewLoading, setPreviewLoading] = useState(false);

  const fetchPreview = useCallback(async () => {
    setPreviewLoading(true);
    try {
      const result = await previewScope(value);
      setPreview(result);
    } catch {
      setPreview(null);
    } finally {
      setPreviewLoading(false);
    }
  }, [value]);

  useEffect(() => {
    const timer = setTimeout(fetchPreview, 500);
    return () => clearTimeout(timer);
  }, [fetchPreview]);

  const addProject = () => {
    const trimmed = projectInput.trim();
    if (trimmed && !value.project_ids.includes(trimmed)) {
      onChange({ ...value, project_ids: [...value.project_ids, trimmed] });
    }
    setProjectInput('');
  };

  const removeProject = (id: string) =>
    onChange({ ...value, project_ids: value.project_ids.filter(p => p !== id) });

  const addIncludeLabel = () => {
    if (labelKey && labelVal) {
      onChange({ ...value, include_labels: [...value.include_labels, { key: labelKey, value: labelVal }] });
      setLabelKey(''); setLabelVal('');
    }
  };

  const removeIncludeLabel = (i: number) =>
    onChange({ ...value, include_labels: value.include_labels.filter((_, idx) => idx !== i) });

  const addExcludeLabel = () => {
    if (excludeKey && excludeVal) {
      onChange({ ...value, exclude_labels: [...value.exclude_labels, { key: excludeKey, value: excludeVal }] });
      setExcludeKey(''); setExcludeVal('');
    }
  };

  const removeExcludeLabel = (i: number) =>
    onChange({ ...value, exclude_labels: value.exclude_labels.filter((_, idx) => idx !== i) });

  return (
    <div className="space-y-6">
      <div>
        <label className="block text-sm font-medium text-gray-700 mb-1">Target Projects</label>
        <p className="text-xs text-gray-500 mb-2">Leave empty to scope the entire organisation.</p>
        <div className="flex gap-2 mb-2">
          <input
            className="flex-1 border border-gray-300 rounded px-3 py-2 text-sm"
            placeholder="my-project-id"
            value={projectInput}
            onChange={e => setProjectInput(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && addProject()}
          />
          <button onClick={addProject} className="px-3 py-2 bg-blue-600 text-white rounded text-sm">Add</button>
        </div>
        <div className="flex flex-wrap gap-2">
          {value.project_ids.map(id => (
            <span key={id} className="inline-flex items-center gap-1 bg-blue-100 text-blue-800 text-xs px-2 py-1 rounded-full">
              {id}
              <button onClick={() => removeProject(id)} className="text-blue-500 hover:text-blue-800 font-bold">×</button>
            </span>
          ))}
        </div>
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-700 mb-1">Include Labels</label>
        <p className="text-xs text-gray-500 mb-2">All labels must match (AND logic).</p>
        <div className="flex gap-2 mb-2">
          <input className="w-32 border border-gray-300 rounded px-3 py-2 text-sm" placeholder="key" value={labelKey} onChange={e => setLabelKey(e.target.value)} />
          <span className="self-center text-gray-400">=</span>
          <input className="w-32 border border-gray-300 rounded px-3 py-2 text-sm" placeholder="value" value={labelVal} onChange={e => setLabelVal(e.target.value)} />
          <button onClick={addIncludeLabel} className="px-3 py-2 bg-green-600 text-white rounded text-sm">Add</button>
        </div>
        <div className="flex flex-wrap gap-2">
          {value.include_labels.map((f, i) => (
            <span key={i} className="inline-flex items-center gap-1 bg-green-100 text-green-800 text-xs px-2 py-1 rounded-full">
              {f.key}={f.value}
              <button onClick={() => removeIncludeLabel(i)} className="text-green-500 hover:text-green-800 font-bold">×</button>
            </span>
          ))}
        </div>
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-700 mb-1">Exclude Labels</label>
        <p className="text-xs text-gray-500 mb-2">Any match excludes the asset (e.g. skip-remediation=true).</p>
        <div className="flex gap-2 mb-2">
          <input className="w-32 border border-gray-300 rounded px-3 py-2 text-sm" placeholder="key" value={excludeKey} onChange={e => setExcludeKey(e.target.value)} />
          <span className="self-center text-gray-400">=</span>
          <input className="w-32 border border-gray-300 rounded px-3 py-2 text-sm" placeholder="value" value={excludeVal} onChange={e => setExcludeVal(e.target.value)} />
          <button onClick={addExcludeLabel} className="px-3 py-2 bg-red-500 text-white rounded text-sm">Add</button>
        </div>
        <div className="flex flex-wrap gap-2">
          {value.exclude_labels.map((f, i) => (
            <span key={i} className="inline-flex items-center gap-1 bg-red-100 text-red-800 text-xs px-2 py-1 rounded-full">
              NOT {f.key}={f.value}
              <button onClick={() => removeExcludeLabel(i)} className="text-red-400 hover:text-red-700 font-bold">×</button>
            </span>
          ))}
        </div>
      </div>

      <div className="bg-gray-50 border border-gray-200 rounded p-4 text-sm">
        {previewLoading ? (
          <span className="text-gray-500">Counting assets…</span>
        ) : preview ? (
          <>
            <span className="font-semibold text-gray-800">{preview.asset_count.toLocaleString()} assets</span>
            <span className="text-gray-500"> match — </span>
            <span className="font-mono text-xs text-gray-600">{preview.filter_description}</span>
          </>
        ) : (
          <span className="text-gray-400">Scope preview unavailable</span>
        )}
      </div>
    </div>
  );
}
