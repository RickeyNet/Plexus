import { useState } from 'react';

import {
  useFlowCollectorConfig,
  useUpdateFlowCollectorConfig,
} from '@/api/settings';
import { Badge } from '@/components/Badge';
import { LoadingState } from '@/components/LoadingState';
import { QueryError } from '@/components/QueryError';

import { CheckboxRow, CheckboxField, FormRow, NumberField } from './FormFields';
import { SaveBar } from './SaveBar';
import { FormStatus } from './StatusLine';
import { useSavedDraft } from './useSavedDraft';

type NumKey =
  | 'netflow_port'
  | 'sflow_port'
  | 'retention_hours'
  | 'summary_retention_days'
  | 'aggregation_interval_seconds';

export function NetFlowTab() {
  const query = useFlowCollectorConfig();
  const update = useUpdateFlowCollectorConfig();
  const { draft, setDraft, dirty, discard, markSaved } = useSavedDraft(query.data);
  const [status, setStatus] = useState<FormStatus | null>(null);

  if (!draft) {
    if (query.isError)
      return (
        <QueryError what="NetFlow config" query={query} />
      );
    return <LoadingState />;
  }

  const num = (label: string, key: NumKey, min: number, help: string) => (
    <NumberField
      label={label}
      value={draft[key]}
      min={min}
      flex="0 1 200px"
      help={help}
      onChange={(v) => setDraft({ ...draft, [key]: v })}
    />
  );

  const running = query.data?.netflow_running ?? false;
  const sflowRunning = query.data?.sflow_running ?? false;

  return (
    <div>
      <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap', marginBottom: '0.75rem' }}>
        <Badge tone={running ? 'success' : 'neutral'}>NetFlow {running ? 'running' : 'stopped'}</Badge>
        <Badge tone={sflowRunning ? 'success' : 'neutral'}>sFlow {sflowRunning ? 'running' : 'stopped'}</Badge>
      </div>

      <form
        onSubmit={(e) => {
          e.preventDefault();
          setStatus(null);
          update.mutate(draft, {
            onSuccess: (saved) => {
              markSaved(saved);
              setStatus({
                kind: 'success',
                message:
                  'NetFlow configuration saved' +
                  (saved.enabled
                    ? saved.netflow_running
                      ? ' - collector running.'
                      : ' - collector failed to start (check logs).'
                    : ' - collector stopped.'),
              });
            },
            onError: (err) =>
              setStatus({
                kind: 'error',
                message: `Failed to save NetFlow config: ${(err as Error).message}`,
              }),
          });
        }}
      >
        <CheckboxRow>
          <CheckboxField
            label="Enabled"
            checked={draft.enabled}
            onChange={(v) => setDraft({ ...draft, enabled: v })}
          />
        </CheckboxRow>

        <FormRow>
          {num('NetFlow / IPFIX port', 'netflow_port', 1, 'UDP, default 2055')}
          {num('sFlow port', 'sflow_port', 0, 'UDP, default 6343 (set 0 to disable)')}
        </FormRow>

        <FormRow>
          {num('Raw retention (hours)', 'retention_hours', 1, 'Raw flow records older than this are purged.')}
          {num('Summary retention (days)', 'summary_retention_days', 1, 'Hourly aggregates kept this long.')}
          {num(
            'Aggregation interval (s)',
            'aggregation_interval_seconds',
            60,
            'How often raw records roll up into summaries.',
          )}
        </FormRow>

        <p className="form-help">
          Saving rebinds the UDP listeners right away, so port and toggle changes need no restart.
        </p>

        <SaveBar
          name="NetFlow"
          dirty={dirty}
          busy={update.isPending}
          label="Save NetFlow Settings"
          status={status}
          onDiscard={discard}
        />
      </form>
    </div>
  );
}
