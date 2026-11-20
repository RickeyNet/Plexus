import { useState } from 'react';

import { type EventReceiverConfig, useEventReceiverConfig, useUpdateEventReceiverConfig } from '@/api/settings';
import { Badge } from '@/components/Badge';
import { FieldError } from '@/components/FieldError';
import { LoadingState } from '@/components/LoadingState';
import { QueryError } from '@/components/QueryError';
import { SummaryStrip } from '@/components/SummaryStrip';
import { formatCount } from '@/lib/formatCount';

import {
  filterlogSummary,
  RECEIVER_LABEL,
  type ReceiverKind,
  receiverCounters,
  receiverSettings,
  saveSummary,
  validateReceiverPorts,
} from './eventReceivers';
import { CheckboxField, CheckboxRow, FormRow, NumberField } from './FormFields';
import { SaveBar } from './SaveBar';
import { FormStatus } from './StatusLine';
import { useSavedDraft } from './useSavedDraft';

const DEFAULT_PORT: Record<ReceiverKind, number> = { syslog: 1514, trap: 10162 };

export function EventReceiversTab() {
  const query = useEventReceiverConfig();
  const update = useUpdateEventReceiverConfig();
  const { draft, setDraft, dirty, discard, markSaved } = useSavedDraft<EventReceiverConfig>(query.data);
  const [status, setStatus] = useState<FormStatus | null>(null);

  if (!draft) {
    if (query.isError) return <QueryError what="receiver settings" query={query} />;
    return <LoadingState />;
  }

  const errors = validateReceiverPorts(draft);
  const live = query.data ?? draft;

  const receiver = (kind: ReceiverKind) => {
    const running = live[`${kind}_running`] ?? false;
    const portKey = `${kind}_port` as const;
    const enabledKey = `${kind}_enabled` as const;
    const error = errors[portKey];
    return (
      <section style={{ marginBottom: '1rem' }}>
        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', marginBottom: '0.5rem' }}>
          <h4 style={{ margin: 0 }}>{RECEIVER_LABEL[kind]}</h4>
          <Badge tone={running ? 'success' : 'neutral'}>
            {running ? `Running on UDP ${live[`${kind}_listening_port`] ?? live[portKey]}` : 'Stopped'}
          </Badge>
        </div>
        <FormRow>
          <CheckboxField
            inRow
            label="Enabled"
            checked={draft[enabledKey]}
            onChange={(v) => setDraft({ ...draft, [enabledKey]: v })}
          />
          <NumberField
            label="UDP port"
            value={draft[portKey]}
            min={1}
            max={65535}
            flex="0 1 200px"
            help={error ? <FieldError>{error}</FieldError> : `Default ${DEFAULT_PORT[kind]}`}
            onChange={(v) => setDraft({ ...draft, [portKey]: v })}
          />
        </FormRow>
        <SummaryStrip items={receiverCounters(live, kind)} />
      </section>
    );
  };

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        if (Object.keys(errors).length > 0) {
          setStatus({ kind: 'error', message: 'Fix the highlighted ports, then save again.' });
          return;
        }
        setStatus(null);
        update.mutate(receiverSettings(draft), {
          onSuccess: (saved) => {
            markSaved(saved);
            setStatus({ kind: 'success', message: saveSummary(saved) });
          },
          onError: (err) =>
            setStatus({
              kind: 'error',
              message: `Could not save the receiver settings: ${(err as Error).message}`,
            }),
        });
      }}
    >
      {receiver('syslog')}
      {receiver('trap')}

      <h4 style={{ margin: '0 0 0.5rem 0' }}>What received syslog messages do</h4>
      <CheckboxRow>
        <CheckboxField
          label="Raise alerts from syslog rules"
          checked={draft.syslog_alerts}
          help="Messages that match a syslog alert rule raise a monitoring alert."
          onChange={(v) => setDraft({ ...draft, syslog_alerts: v })}
        />
        <CheckboxField
          label="Back up the config on a change message"
          checked={draft.config_change_trigger}
          help="A configuration-change message starts a config backup and drift check of that host."
          onChange={(v) => setDraft({ ...draft, config_change_trigger: v })}
        />
        <CheckboxField
          label="Re-poll on link down or reload"
          checked={draft.repoll_trigger}
          help="A link-down or reload message polls that host right away instead of at the next interval."
          onChange={(v) => setDraft({ ...draft, repoll_trigger: v })}
        />
        <CheckboxField
          label="Re-collect OPNsense on a state change"
          checked={draft.recollect_trigger}
          help="A gateway alarm, CARP transition, VPN up or down, or configuration save logged by an OPNsense firewall collects its topology source right away (at most once a minute and 6 times an hour)."
          onChange={(v) => setDraft({ ...draft, recollect_trigger: v })}
        />
        <CheckboxField
          label="Keep OPNsense firewall log evidence per rule"
          checked={draft.filterlog_evidence}
          help="Firewall log (filterlog) lines are counted per rule as pass / block evidence for the Rules tab and path traces, kept 7 days. The lines themselves are never stored; off drops them."
          onChange={(v) => setDraft({ ...draft, filterlog_evidence: v })}
        />
      </CheckboxRow>
      <p className="form-help">{filterlogSummary(live)}</p>

      <p className="form-help">
        Saving starts, stops or rebinds each receiver right away, and enabled receivers start with Plexus.
        In Docker, a new port also needs the matching published UDP port in docker-compose.yml (by default
        host 162 goes to 10162 for traps and 1514 to 1514 for syslog; publish 514:1514/udp for devices that
        can only send syslog to port 514). Events dropped because the write buffer was full since Plexus
        started: {formatCount(live.events_dropped)}.
      </p>

      <SaveBar
        name="Event receivers"
        dirty={dirty}
        busy={update.isPending}
        label="Save Receiver Settings"
        status={status}
        onDiscard={discard}
      />
    </form>
  );
}
