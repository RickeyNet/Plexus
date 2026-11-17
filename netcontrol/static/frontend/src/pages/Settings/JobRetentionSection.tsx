import { useState } from 'react';

import { type AuthConfig, useAuthConfig, useUpdateAuthConfig } from '@/api/settings';
import { LoadingState } from '@/components/LoadingState';
import { QueryError } from '@/components/QueryError';

import { FormRow, NumberField } from './FormFields';
import { SaveBar } from './SaveBar';
import { FormStatus } from './StatusLine';
import { useSavedDraft } from './useSavedDraft';

/** A retention setting stored in the auth config. */
type RetentionKey = 'job_retention_days' | 'change_log_retention_days';

interface RetentionProps {
  field: RetentionKey;
  /** Section name, e.g. "Job Retention"; also names the save bar and messages. */
  name: string;
  min: number;
  max?: number;
  help: string;
}

/**
 * One retention value of the auth config. A save sends the server's current
 * auth config with only `field` changed: unsaved edits in the Authentication
 * form (or the other retention form) are neither sent nor discarded (each
 * form re-seeds only while it is clean).
 */
function AuthRetentionSection({ field, name, min, max, help }: RetentionProps) {
  const query = useAuthConfig();
  const update = useUpdateAuthConfig();
  const { draft, setDraft, dirty, discard, markSaved } = useSavedDraft(query.data?.[field]);
  const [status, setStatus] = useState<FormStatus | null>(null);

  if (draft === null || !query.data) {
    if (query.isError) return <QueryError what={name.toLowerCase()} query={query} />;
    return <LoadingState />;
  }

  const outOfRange = draft < min || (max !== undefined && draft > max);

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        setStatus(null);
        if (!query.data) return;
        if (outOfRange) {
          setStatus({
            kind: 'error',
            message:
              max === undefined
                ? `${name} must be at least ${min} days`
                : `${name} must be between ${min} and ${max} days`,
          });
          return;
        }
        const payload: AuthConfig = { ...query.data, [field]: draft };
        update.mutate(payload, {
          onSuccess: (saved) => {
            markSaved(saved[field] ?? draft);
            setStatus({ kind: 'success', message: `${name} saved` });
          },
          onError: (err) =>
            setStatus({
              kind: 'error',
              message: `Failed to save ${name.toLowerCase()}: ${(err as Error).message}`,
            }),
        });
      }}
    >
      <FormRow>
        <NumberField
          label={`${name} (days)`}
          value={draft}
          min={min}
          max={max}
          flex="0 1 320px"
          onChange={setDraft}
          help={help}
        />
      </FormRow>
      <SaveBar name={name} dirty={dirty} busy={update.isPending} status={status} onDiscard={discard} />
    </form>
  );
}

/** The server rejects anything lower (routes/admin.py, ge=30). */
const MIN_JOB_RETENTION_DAYS = 30;

/** Job history retention. */
export function JobRetentionSection() {
  return (
    <AuthRetentionSection
      field="job_retention_days"
      name="Job Retention"
      min={MIN_JOB_RETENTION_DAYS}
      help={`Finished jobs (succeeded, failed or cancelled) older than this are deleted. Minimum ${MIN_JOB_RETENTION_DAYS} days.`}
    />
  );
}

/** Per-object change log retention (routes/admin.py: 1 to 3650 days). */
export function ChangeLogRetentionSection() {
  return (
    <AuthRetentionSection
      field="change_log_retention_days"
      name="Change Log Retention"
      min={1}
      max={3650}
      help="Recorded object changes (Change Management > Change Log, the Changelog of each object) older than this are deleted. 1 to 3650 days."
    />
  );
}
