import { useState } from 'react';

import { useAuthConfig, useUpdateAuthConfig } from '@/api/settings';
import { LoadingState } from '@/components/LoadingState';
import { QueryError } from '@/components/QueryError';

import { FormRow, NumberField } from './FormFields';
import { SaveBar } from './SaveBar';
import { FormStatus } from './StatusLine';
import { useSavedDraft } from './useSavedDraft';

/** The server rejects anything lower (routes/admin.py, ge=30). */
const MIN_RETENTION_DAYS = 30;

/**
 * Job history retention. The value is stored in the auth config, so a save
 * sends the server's current auth config with only `job_retention_days`
 * changed: unsaved edits in the Authentication form are neither sent nor
 * discarded (that form re-seeds only while it is clean).
 */
export function JobRetentionSection() {
  const query = useAuthConfig();
  const update = useUpdateAuthConfig();
  const { draft, setDraft, dirty, discard, markSaved } = useSavedDraft(
    query.data?.job_retention_days,
  );
  const [status, setStatus] = useState<FormStatus | null>(null);

  if (draft === null || !query.data) {
    if (query.isError) return <QueryError what="job retention" query={query} />;
    return <LoadingState />;
  }

  const tooLow = draft < MIN_RETENTION_DAYS;

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        setStatus(null);
        if (!query.data) return;
        if (tooLow) {
          setStatus({
            kind: 'error',
            message: `Job retention must be at least ${MIN_RETENTION_DAYS} days`,
          });
          return;
        }
        update.mutate(
          { ...query.data, job_retention_days: draft },
          {
            onSuccess: (saved) => {
              markSaved(saved.job_retention_days);
              setStatus({ kind: 'success', message: 'Job retention saved' });
            },
            onError: (err) =>
              setStatus({
                kind: 'error',
                message: `Failed to save job retention: ${(err as Error).message}`,
              }),
          },
        );
      }}
    >
      <FormRow>
        <NumberField
          label="Job Retention (days)"
          value={draft}
          min={MIN_RETENTION_DAYS}
          flex="0 1 320px"
          onChange={setDraft}
          help={`Finished jobs (succeeded, failed or cancelled) older than this are deleted. Minimum ${MIN_RETENTION_DAYS} days.`}
        />
      </FormRow>
      <SaveBar
        name="Job Retention"
        dirty={dirty}
        busy={update.isPending}
        status={status}
        onDiscard={discard}
      />
    </form>
  );
}
