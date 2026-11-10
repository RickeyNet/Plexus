import { useState } from 'react';

import {
  AdminCapabilities,
  useUpdateFeatureVisibility,
} from '@/api/settings';
import { BusyButton } from '@/components/BusyButton';
import { EmptyState } from '@/components/EmptyState';

import { FormStatus, StatusLine } from './StatusLine';

export function FeaturesTab({
  capabilities,
}: {
  capabilities: AdminCapabilities;
}) {
  const update = useUpdateFeatureVisibility();
  const [hidden, setHidden] = useState<Set<string>>(
    () => new Set(capabilities.feature_visibility.hidden),
  );
  const [status, setStatus] = useState<FormStatus | null>(null);

  // If the capabilities query refetches with a different hidden list (e.g.
  // another admin saved changes), fold the server state back into the local
  // draft so we don't display stale toggles.
  const [prevHidden, setPrevHidden] = useState(capabilities.feature_visibility.hidden);
  if (capabilities.feature_visibility.hidden !== prevHidden) {
    setPrevHidden(capabilities.feature_visibility.hidden);
    setHidden(new Set(capabilities.feature_visibility.hidden));
  }

  const catalog = capabilities.feature_visibility.catalog;

  return (
    <div>
      <h3 style={{ margin: '0 0 0.5rem 0' }}>Feature Visibility</h3>
      <p className="card-description" style={{ marginBottom: '0.75rem' }}>
        Hide nav entries from non-admin users without removing the feature itself.
      </p>

      {catalog.length === 0 ? (
        <EmptyState compact message="No toggleable features available." />
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
        <BusyButton
          className="btn btn-primary"
          busy={update.isPending}
          busyLabel="Saving…"
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
          Save Visibility
        </BusyButton>
      </div>

      <StatusLine status={status} />
    </div>
  );
}
