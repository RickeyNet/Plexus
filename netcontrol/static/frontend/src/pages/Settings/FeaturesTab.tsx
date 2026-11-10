import { useMemo, useState } from 'react';

import {
  AdminCapabilities,
  useUpdateFeatureVisibility,
} from '@/api/settings';
import { EmptyState } from '@/components/EmptyState';

import { CheckboxField } from './FormFields';
import { SaveBar } from './SaveBar';
import { FormStatus } from './StatusLine';
import { useSavedDraft } from './useSavedDraft';

export function FeaturesTab({
  capabilities,
}: {
  capabilities: AdminCapabilities;
}) {
  const update = useUpdateFeatureVisibility();
  // Sorted so toggling a feature off and on again compares equal to the
  // saved list. A refetch (another admin saved) re-seeds the draft while it
  // holds no unsaved toggles.
  const savedHidden = capabilities.feature_visibility.hidden;
  const serverHidden = useMemo(() => [...savedHidden].sort(), [savedHidden]);
  const { draft, setDraft, dirty, discard, markSaved } = useSavedDraft(serverHidden);
  const [status, setStatus] = useState<FormStatus | null>(null);

  const hidden = new Set(draft ?? serverHidden);
  const catalog = capabilities.feature_visibility.catalog;

  return (
    <div>
      {catalog.length === 0 ? (
        <EmptyState compact message="No toggleable features available." />
      ) : (
        <div style={{ display: 'grid', gap: '0.4rem', justifyItems: 'start' }}>
          {catalog.map((entry) => (
            <CheckboxField
              key={entry.key}
              label={entry.label}
              checked={!hidden.has(entry.key)}
              onChange={(visible) => {
                const next = new Set(hidden);
                if (visible) next.delete(entry.key);
                else next.add(entry.key);
                setDraft(Array.from(next).sort());
              }}
            />
          ))}
        </div>
      )}

      <SaveBar
        name="Feature Visibility"
        dirty={dirty}
        busy={update.isPending}
        label="Save Visibility"
        status={status}
        onDiscard={discard}
        onSave={() => {
          setStatus(null);
          const next = Array.from(hidden).sort();
          update.mutate(next, {
            onSuccess: () => {
              markSaved(next);
              setStatus({ kind: 'success', message: 'Feature visibility saved' });
            },
            onError: (err) =>
              setStatus({
                kind: 'error',
                message: `Failed to save feature visibility: ${(err as Error).message}`,
              }),
          });
        }}
      />
    </div>
  );
}
