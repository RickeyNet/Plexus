import { useEffect, useState } from 'react';

import {
  AdminCapabilities,
  useUpdateFeatureVisibility,
} from '@/api/settings';

export function FeaturesTab({
  capabilities,
}: {
  capabilities: AdminCapabilities;
}) {
  const update = useUpdateFeatureVisibility();
  const [hidden, setHidden] = useState<Set<string>>(
    () => new Set(capabilities.feature_visibility.hidden),
  );
  const [status, setStatus] = useState<{ kind: 'success' | 'error'; message: string } | null>(null);

  // If the capabilities query refetches with a different hidden list (e.g.
  // another admin saved changes), fold the server state back into the local
  // draft so we don't display stale toggles.
  useEffect(() => {
    setHidden(new Set(capabilities.feature_visibility.hidden));
  }, [capabilities.feature_visibility.hidden]);

  const catalog = capabilities.feature_visibility.catalog;

  return (
    <div className="card" style={{ padding: '1rem' }}>
      <h3 style={{ margin: '0 0 0.5rem 0' }}>Feature Visibility</h3>
      <p className="card-description" style={{ marginBottom: '0.75rem' }}>
        Hide nav entries from non-admin users without removing the feature itself.
      </p>

      {catalog.length === 0 ? (
        <p className="text-muted">No toggleable features available.</p>
      ) : (
        <div style={{ display: 'grid', gap: '0.4rem' }}>
          {catalog.map((entry) => {
            const isVisible = !hidden.has(entry.key);
            return (
              <label
                key={entry.key}
                style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}
              >
                <input
                  type="checkbox"
                  checked={isVisible}
                  onChange={(e) => {
                    const next = new Set(hidden);
                    if (e.target.checked) next.delete(entry.key);
                    else next.add(entry.key);
                    setHidden(next);
                  }}
                />
                <span>{entry.label}</span>
              </label>
            );
          })}
        </div>
      )}

      <div style={{ marginTop: '0.75rem' }}>
        <button
          type="button"
          className="btn btn-primary"
          disabled={update.isPending}
          onClick={() => {
            setStatus(null);
            update.mutate(Array.from(hidden), {
              onSuccess: () =>
                setStatus({ kind: 'success', message: 'Feature visibility saved' }),
              onError: (err) =>
                setStatus({
                  kind: 'error',
                  message: `Failed to save feature visibility: ${(err as Error).message}`,
                }),
            });
          }}
        >
          {update.isPending ? 'Saving…' : 'Save Visibility'}
        </button>
      </div>

      {status && (
        <div
          className={status.kind === 'error' ? 'error' : ''}
          style={{
            marginTop: '0.5rem',
            color: status.kind === 'error' ? undefined : 'var(--success)',
          }}
        >
          {status.message}
        </div>
      )}
    </div>
  );
}
