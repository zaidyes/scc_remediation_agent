import React, { useState } from 'react';
import { rollbackApproval } from '../api/config';

interface Props {
  approvalId: string;
  executedAt: string | null | undefined;
}

type State = 'idle' | 'confirming' | 'loading' | 'success' | 'error';

const EXPIRY_HOURS = 24;

function isWithinWindow(executedAt: string | null | undefined): boolean {
  if (!executedAt) return false;
  const elapsed = Date.now() - new Date(executedAt).getTime();
  return elapsed < EXPIRY_HOURS * 60 * 60 * 1000;
}

export default function RollbackButton({ approvalId, executedAt }: Props) {
  const [state, setState] = useState<State>('idle');
  const [errorMsg, setErrorMsg] = useState('');

  if (!isWithinWindow(executedAt)) return null;

  const hoursRemaining = executedAt
    ? Math.max(0, EXPIRY_HOURS - (Date.now() - new Date(executedAt).getTime()) / 3_600_000).toFixed(1)
    : '0';

  const handleClick = () => {
    if (state === 'idle') {
      setState('confirming');
      return;
    }
    if (state === 'confirming') {
      execute();
    }
  };

  const execute = async () => {
    setState('loading');
    try {
      await rollbackApproval(approvalId);
      setState('success');
    } catch (e: any) {
      setErrorMsg(e.message ?? 'Rollback failed');
      setState('error');
    }
  };

  if (state === 'success') {
    return (
      <span className="text-xs text-green-700 font-medium px-2 py-1 bg-green-50 rounded border border-green-200">
        Rolled back
      </span>
    );
  }

  if (state === 'error') {
    return (
      <span className="text-xs text-red-700 font-medium px-2 py-1 bg-red-50 rounded border border-red-200" title={errorMsg}>
        Rollback failed — {errorMsg}
      </span>
    );
  }

  return (
    <div className="flex items-center gap-2">
      {state === 'confirming' && (
        <span className="text-xs text-orange-700">Are you sure?</span>
      )}
      <button
        onClick={handleClick}
        disabled={state === 'loading'}
        className={`text-xs px-2.5 py-1 rounded font-medium border transition-colors disabled:opacity-50 ${
          state === 'confirming'
            ? 'bg-red-600 text-white border-red-600 hover:bg-red-700'
            : 'bg-white text-orange-700 border-orange-300 hover:bg-orange-50'
        }`}
      >
        {state === 'loading' ? 'Rolling back…' : state === 'confirming' ? 'Confirm rollback' : 'Rollback'}
      </button>
      {state === 'confirming' && (
        <button
          onClick={() => setState('idle')}
          className="text-xs text-gray-500 hover:text-gray-700"
        >
          Cancel
        </button>
      )}
      {state === 'idle' && (
        <span className="text-xs text-gray-400">{hoursRemaining}h remaining</span>
      )}
    </div>
  );
}
