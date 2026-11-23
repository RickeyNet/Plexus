import { useState } from 'react';
import { Link } from 'react-router';

import {
  type EventReceiverConfig,
  useEventReceiverConfig,
  useSyslogTls,
  useUpdateEventReceiverConfig,
} from '@/api/settings';
import { Badge } from '@/components/Badge';
import { Callout } from '@/components/Callout';
import { FieldError } from '@/components/FieldError';
import { LoadingState } from '@/components/LoadingState';
import { QueryError } from '@/components/QueryError';
import { SummaryStrip } from '@/components/SummaryStrip';
import { formatCount } from '@/lib/formatCount';

import {
  filterlogSummary,
  isStreamKind,
  RECEIVER_DEFAULT_PORT,
  RECEIVER_LABEL,
  RECEIVER_PROTOCOL,
  type ReceiverKind,
  receiverCounters,
  receiverGuards,
  receiverSettings,
  saveSummary,
  validateReceiverPorts,
} from './eventReceivers';
import { CheckboxField, CheckboxRow, FormRow, NumberField } from './FormFields';
import { SaveBar } from './SaveBar';
import { FormStatus } from './StatusLine';
import { SyslogTlsSection } from './SyslogTlsSection';
import { useSavedDraft } from './useSavedDraft';

export function EventReceiversTab() {
  const query = useEventReceiverConfig();
  const update = useUpdateEventReceiverConfig();
  const tls = useSyslogTls();
  const { draft, setDraft, dirty, discard, markSaved } = useSavedDraft<EventReceiverConfig>(query.data);
  const [status, setStatus] = useState<FormStatus | null>(null);

  if (!draft) {
    if (query.isError) return <QueryError what="receiver settings" query={query} />;
    return <LoadingState />;
  }

  const live = query.data ?? draft;
  const errors = { ...validateReceiverPorts(draft), ...receiverGuards(draft, live, tls.data) };

  const receiver = (kind: ReceiverKind) => {
    const running = live[`${kind}_running`] ?? false;
    const portKey = `${kind}_port` as const;
    const enabledKey = `${kind}_enabled` as const;
    const protocol = RECEIVER_PROTOCOL[kind];
    const error = errors[portKey];
    const enabledError = kind === 'syslog_tls' ? errors.syslog_tls_enabled : undefined;
    const listenerError = isStreamKind(kind) ? live[`${kind}_error`] : '';
    return (
      <section style={{ marginBottom: '1rem' }}>
        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', marginBottom: '0.5rem' }}>
          <h4 style={{ margin: 0 }}>{RECEIVER_LABEL[kind]}</h4>
          <Badge tone={running ? 'success' : 'neutral'}>
            {running ? `Running on ${protocol} ${live[`${kind}_listening_port`] ?? live[portKey]}` : 'Stopped'}
          </Badge>
        </div>
        {listenerError && <Callout tone="warning">{listenerError}</Callout>}
        <FormRow>
          <CheckboxField
            inRow
            label="Enabled"
            checked={draft[enabledKey]}
            help={enabledError ? <FieldError>{enabledError}</FieldError> : undefined}
            onChange={(v) => setDraft({ ...draft, [enabledKey]: v })}
          />
          <NumberField
            label={`${protocol} port`}
            value={draft[portKey]}
            min={1}
            max={65535}
            flex="0 1 200px"
            help={error ? <FieldError>{error}</FieldError> : `Default ${RECEIVER_DEFAULT_PORT[kind]}`}
            onChange={(v) => setDraft({ ...draft, [portKey]: v })}
          />
        </FormRow>
        {kind === 'syslog_tls' && (
          <CheckboxRow>
            <CheckboxField
              label="Require client certificates"
              checked={draft.syslog_tls_require_client_cert}
              help={
                errors.syslog_tls_require_client_cert ? (
                  <FieldError>{errors.syslog_tls_require_client_cert}</FieldError>
                ) : (
                  'Mutual TLS: only devices holding a certificate the client CA signed can connect. Store the client CA under Client certificates below.'
                )
              }
              onChange={(v) =>
                setDraft({
                  ...draft,
                  syslog_tls_require_client_cert: v,
                  // The host check needs client certificates; it goes off with them.
                  syslog_tls_match_client_cert: v && draft.syslog_tls_match_client_cert,
                })}
            />
            <CheckboxField
              label="Certificate must name the host"
              checked={draft.syslog_tls_match_client_cert}
              disabled={!draft.syslog_tls_require_client_cert && !draft.syslog_tls_match_client_cert}
              help={
                errors.syslog_tls_match_client_cert ? (
                  <FieldError>{errors.syslog_tls_match_client_cert}</FieldError>
                ) : (
                  'The client certificate must carry the source address as a SAN IP address, or the hostname of the inventory host at that address as a SAN DNS name or common name. Otherwise the connection is closed before any message is read.'
                )
              }
              onChange={(v) => setDraft({ ...draft, syslog_tls_match_client_cert: v })}
            />
          </CheckboxRow>
        )}
        <SummaryStrip items={receiverCounters(live, kind)} />
      </section>
    );
  };

  return (
    <>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (Object.keys(errors).length > 0) {
            setStatus({ kind: 'error', message: 'Fix the highlighted fields, then save again.' });
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
        {receiver('syslog_tcp')}
        {receiver('syslog_tls')}
        {receiver('trap')}

        <h4 style={{ margin: '0 0 0.5rem 0' }}>What received syslog messages and traps do</h4>
        <CheckboxRow>
          <CheckboxField
            label="Act on UDP messages"
            checked={draft.syslog_udp_actions}
            help={
              <>
                {errors.syslog_udp_actions && <FieldError>{errors.syslog_udp_actions}</FieldError>}
                The source address of a UDP message can be forged. Off, syslog over UDP is still received and stored but
                raises no alert and starts no backup, re-poll or re-collection; TCP and TLS messages act as before. Move
                devices to TCP or TLS first: Received messages under{' '}
                <Link to="/monitoring/configure/syslog-rules">Monitoring &gt; Configure &gt; Syslog Rules</Link> shows the
                hosts that still send over UDP.
              </>
            }
            onChange={(v) => setDraft({ ...draft, syslog_udp_actions: v })}
          />
          <CheckboxField
            label="Raise alerts from syslog rules"
            checked={draft.syslog_alerts}
            help="Messages that match a syslog alert rule raise a monitoring alert."
            onChange={(v) => setDraft({ ...draft, syslog_alerts: v })}
          />
          <CheckboxField
            label="Raise alerts from SNMP trap rules"
            checked={draft.trap_alerts}
            help="Traps from inventory hosts, with the host's SNMP community (SNMPv3: signed by the host's SNMPv3 user), that match a built-in trap rule raise or resolve a monitoring alert."
            onChange={(v) => setDraft({ ...draft, trap_alerts: v })}
          />
          <CheckboxField
            label="Back up the config on a change message"
            checked={draft.config_change_trigger}
            help="A configuration-change syslog message or trap starts a config backup and drift check of that host."
            onChange={(v) => setDraft({ ...draft, config_change_trigger: v })}
          />
          <CheckboxField
            label="Re-poll on link down, module down or reload"
            checked={draft.repoll_trigger}
            help="A link-down, module down or back online, or reload message, or a trap that names a state change, polls that host right away instead of at the next interval."
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
          In Docker, a new port also needs the matching published port in docker-compose.yml (by default
          host 162 goes to 10162/udp for traps, 1514 to 1514/udp and 1514/tcp for syslog, and 6514 to 6514/tcp
          for syslog over TLS; publish 514:1514/udp for devices that can only send syslog to port 514). Events
          dropped because the write buffer was full since Plexus started: {formatCount(live.events_dropped)}.
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
      <SyslogTlsSection
        query={tls}
        tlsEnabled={live.syslog_tls_enabled}
        requireClientCert={live.syslog_tls_require_client_cert}
      />
    </>
  );
}
