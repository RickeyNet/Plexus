import { useState } from 'react';

import {
  MonitoringConfig,
  useMonitoringConfig,
  useRunMonitoringPoll,
  useUpdateMonitoringConfig,
} from '@/api/settings';
import { BusyButton } from '@/components/BusyButton';
import { LoadingState } from '@/components/LoadingState';
import { QueryError } from '@/components/QueryError';

import { CheckboxField, CheckboxRow, FormRow, NumberField } from './FormFields';
import { SaveBar } from './SaveBar';
import { FormStatus } from './StatusLine';
import { useSavedDraft } from './useSavedDraft';

type NumKey = {
  [K in keyof MonitoringConfig]: MonitoringConfig[K] extends number ? K : never;
}[keyof MonitoringConfig];
type BoolKey = {
  [K in keyof MonitoringConfig]: MonitoringConfig[K] extends boolean ? K : never;
}[keyof MonitoringConfig];

export function MonitoringTab() {
  const query = useMonitoringConfig();
  const update = useUpdateMonitoringConfig();
  const runNow = useRunMonitoringPoll();
  const { draft, setDraft, dirty, discard, markSaved } = useSavedDraft(query.data);
  const [status, setStatus] = useState<FormStatus | null>(null);

  if (!draft) {
    if (query.isError)
      return (
        <QueryError what="monitoring config" query={query} />
      );
    return <LoadingState />;
  }

  const num = (label: string, key: NumKey, min: number, help?: string) => (
    <NumberField
      label={label}
      value={draft[key]}
      min={min}
      flex="0 1 180px"
      help={help}
      onChange={(v) => setDraft({ ...draft, [key]: v })}
    />
  );

  const check = (label: string, key: BoolKey) => (
    <CheckboxField
      label={label}
      checked={draft[key]}
      onChange={(v) => setDraft({ ...draft, [key]: v })}
    />
  );

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        setStatus(null);
        update.mutate(draft, {
          onSuccess: (saved) => {
            markSaved(saved);
            setStatus({ kind: 'success', message: 'Monitoring configuration saved' });
          },
          onError: (err) =>
            setStatus({
              kind: 'error',
              message: `Failed to save monitoring config: ${(err as Error).message}`,
            }),
        });
      }}
    >
      <CheckboxRow>
        {check('Enabled', 'enabled')}
        {check('Collect routes', 'collect_routes')}
        {check('Collect VPN', 'collect_vpn')}
        {check('Escalation enabled', 'escalation_enabled')}
      </CheckboxRow>
      <FormRow>
        {num('Interval (s)', 'interval_seconds', 30, 'Time between polls of each monitored host.')}
        {num('Retention (days)', 'retention_days', 1, 'Raw poll results older than this are purged.')}
        {num('CPU threshold (%)', 'cpu_threshold', 0, 'Alert when CPU use goes above this.')}
        {num('Memory threshold (%)', 'memory_threshold', 0, 'Alert when memory use goes above this.')}
      </FormRow>
      <FormRow>
        {num(
          'Cooldown (min)',
          'default_cooldown_minutes',
          0,
          'Minimum gap before the same alert is raised again.',
        )}
        {num(
          'Escalate after (min)',
          'escalation_after_minutes',
          0,
          'An unacknowledged alert escalates after this long.',
        )}
        {num(
          'Escalation check (s)',
          'escalation_check_interval',
          30,
          'How often alerts are checked for escalation (30 to 3600).',
        )}
      </FormRow>

      <SaveBar
        name="Monitoring"
        dirty={dirty}
        busy={update.isPending}
        label="Save Monitoring Settings"
        status={status}
        onDiscard={discard}
      >
        <BusyButton
          className="btn btn-secondary"
          busy={runNow.isPending}
          busyLabel="Polling…"
          title="Run one monitoring poll now with the saved settings"
          onClick={() => {
            setStatus(null);
            runNow.mutate(undefined, {
              onSuccess: (res) => {
                const errors = res.errors ?? 0;
                setStatus({
                  kind: errors > 0 ? 'error' : 'success',
                  message: `Monitoring poll complete: ${res.hosts_polled ?? 0} hosts, ${res.alerts_created ?? 0} alerts, ${errors} errors`,
                });
              },
              onError: (err) =>
                setStatus({
                  kind: 'error',
                  message: `Monitoring poll failed: ${(err as Error).message}`,
                }),
            });
          }}
        >
          Poll Now
        </BusyButton>
      </SaveBar>
    </form>
  );
}
