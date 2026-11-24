'use client';

import { useState } from 'react';
import { Loader2 } from 'lucide-react';
import { api, getApiErrorMessage, type BodyReplaySuggestion, type BodyReplaySuggestions as Suggestions } from '@/lib/api';
import { Button } from '@/components/ui/button';

/**
 * POST paths the agent saw while mapping but could not body-test because they
 * are not approved. Adding one appends it to the approved list for the next turn.
 */
export function BodyReplaySuggestions({ sessionId, approved, onAdd, disabled }: {
  sessionId: string | null;
  approved: string[];
  onAdd: (path: string) => void;
  disabled?: boolean;
}) {
  const [data, setData] = useState<Suggestions | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const load = async () => {
    if (!sessionId) return;
    setLoading(true); setError('');
    try {
      setData(await api.getBodyReplaySuggestions(sessionId));
    } catch (err) {
      setError(getApiErrorMessage(err));
    } finally {
      setLoading(false);
    }
  };

  const row = (item: BodyReplaySuggestion, destructive: boolean) => {
    const added = approved.includes(item.path);
    return (
      <li key={item.path} className="flex items-start justify-between gap-2">
        <span className="min-w-0 break-all">
          <span className="font-mono">{item.path}</span>
          <span className="ml-1 opacity-70">({item.inputs} input{item.inputs === 1 ? '' : 's'}{item.classes.length ? `, ${item.classes.join(', ')}` : ''})</span>
          {destructive && <span className="ml-1 text-amber-600 dark:text-amber-400">may change account or money state</span>}
        </span>
        <Button type="button" size="sm" variant="outline" className="h-6 shrink-0 px-2 text-xs"
          disabled={disabled || added || approved.length >= 8} onClick={() => onAdd(item.path)}>
          {added ? 'Added' : 'Add'}
        </Button>
      </li>
    );
  };

  if (!sessionId) return <p>Run a mapping turn first; observed POST paths appear here.</p>;

  return (
    <div className="space-y-1">
      <Button type="button" size="sm" variant="outline" className="h-7 text-xs" onClick={load} disabled={loading || disabled}>
        {loading && <Loader2 className="mr-1 h-3 w-3 animate-spin" />}Suggest POST paths from this session
      </Button>
      {error && <p className="text-destructive">{error}</p>}
      {data && !data.suggested.length && !data.needs_review.length && <p>No unapproved POST paths observed yet.</p>}
      {data && data.suggested.length > 0 && <ul className="space-y-1">{data.suggested.map((item) => row(item, false))}</ul>}
      {data && data.needs_review.length > 0 && (
        <>
          <p className="pt-1">Review before adding (never auto-approved):</p>
          <ul className="space-y-1">{data.needs_review.map((item) => row(item, true))}</ul>
        </>
      )}
    </div>
  );
}
