import { useId, useState } from 'react';

import {
  SyslogConfig,
  useSyslogConfig,
  useTestSyslog,
  useUpdateSyslogConfig,
} from '@/api/settings';
import { BusyButton } from '@/components/BusyButton';
import { LoadingState } from '@/components/LoadingState';
import { QueryError } from '@/components/QueryError';

import { CheckboxField, CheckboxRow, FormRow } from './FormFields';
import { SaveBar } from './SaveBar';
import { FormStatus } from './StatusLine';
import { useSavedDraft } from './useSavedDraft';

const PROTOCOLS = ['udp', 'tcp'];
const FACILITIES = [
  'kern', 'user', 'mail', 'daemon', 'auth', 'syslog',
  'lpr', 'news', 'uucp', 'cron', 'authpriv', 'ftp',
  'local0', 'local1', 'local2', 'local3', 'local4', 'local5', 'local6', 'local7',
];
const LEVELS = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'];

export function LoggingTab() {
  const query = useSyslogConfig();
  const update = useUpdateSyslogConfig();
  const test = useTestSyslog();
  const fid = useId();
  const { draft, setDraft, dirty, discard, markSaved } = useSavedDraft<SyslogConfig>(query.data);
  const [status, setStatus] = useState<FormStatus | null>(null);

  if (!draft) {
    if (query.isError)
      return (
        <QueryError what="syslog config" query={query} />
      );
    return <LoadingState />;
  }

  const statusLabel = draft.active ? 'Active' : draft.enabled ? 'Configured' : 'Disabled';
  const statusBadge = draft.active ? 'badge-success' : 'badge-info';

  return (
    <div>
      <div style={{ marginBottom: '0.75rem' }}>
        <span className={`badge ${statusBadge}`}>{statusLabel}</span>
      </div>

      <form
        onSubmit={(e) => {
          e.preventDefault();
          setStatus(null);
          if (draft.enabled && !draft.host.trim()) {
            setStatus({
              kind: 'error',
              message: 'Syslog host is required when enabled',
            });
            return;
          }
          const { active, ...payload } = draft;
          void active;
          update.mutate(
            { ...payload, app_name: payload.app_name.trim() || 'plexus' },
            {
              onSuccess: (saved) => {
                markSaved(saved);
                setStatus({ kind: 'success', message: 'Syslog settings saved' });
              },
              onError: (err) =>
                setStatus({
                  kind: 'error',
                  message: `Failed to save syslog settings: ${(err as Error).message}`,
                }),
            },
          );
        }}
      >
        <CheckboxRow>
          <CheckboxField
            label="Enable Syslog Forwarding"
            checked={draft.enabled}
            onChange={(v) => setDraft({ ...draft, enabled: v })}
          />
        </CheckboxRow>

        <FormRow>
          <div className="form-group" style={{ flex: '1 1 220px' }}>
            <label className="form-label" htmlFor={`${fid}-host`}>Host</label>
            <input
              id={`${fid}-host`}
              className="form-input"
              value={draft.host}
              onChange={(e) => setDraft({ ...draft, host: e.target.value })}
            />
          </div>
          <div className="form-group" style={{ flex: '0 1 120px' }}>
            <label className="form-label" htmlFor={`${fid}-port`}>Port</label>
            <input
              id={`${fid}-port`}
              type="number"
              min={1}
              max={65535}
              className="form-input"
              value={draft.port}
              onChange={(e) => setDraft({ ...draft, port: Number(e.target.value) })}
            />
          </div>
          <div className="form-group" style={{ flex: '0 1 140px' }}>
            <label className="form-label" htmlFor={`${fid}-protocol`}>Protocol</label>
            <select
              id={`${fid}-protocol`}
              className="form-select"
              value={draft.protocol}
              onChange={(e) => setDraft({ ...draft, protocol: e.target.value })}
            >
              {PROTOCOLS.map((p) => (
                <option key={p} value={p}>
                  {p.toUpperCase()}
                </option>
              ))}
            </select>
          </div>
          <div className="form-group" style={{ flex: '0 1 160px' }}>
            <label className="form-label" htmlFor={`${fid}-facility`}>Facility</label>
            <select
              id={`${fid}-facility`}
              className="form-select"
              value={draft.facility}
              onChange={(e) => setDraft({ ...draft, facility: e.target.value })}
            >
              {FACILITIES.map((f) => (
                <option key={f} value={f}>
                  {f}
                </option>
              ))}
            </select>
            <div className="form-help">Syslog facility stamped on each message.</div>
          </div>
          <div className="form-group" style={{ flex: '0 1 140px' }}>
            <label className="form-label" htmlFor={`${fid}-level`}>Level</label>
            <select
              id={`${fid}-level`}
              className="form-select"
              value={draft.level}
              onChange={(e) => setDraft({ ...draft, level: e.target.value })}
            >
              {LEVELS.map((l) => (
                <option key={l} value={l}>
                  {l}
                </option>
              ))}
            </select>
            <div className="form-help">Lowest log level that is forwarded.</div>
          </div>
          <div className="form-group" style={{ flex: '1 1 200px' }}>
            <label className="form-label" htmlFor={`${fid}-app-name`}>App Name</label>
            <input
              id={`${fid}-app-name`}
              className="form-input"
              value={draft.app_name}
              onChange={(e) => setDraft({ ...draft, app_name: e.target.value })}
            />
            <div className="form-help">Tag that names Plexus in each message; blank means plexus.</div>
          </div>
        </FormRow>

        <SaveBar
          name="Syslog Forwarding"
          dirty={dirty}
          busy={update.isPending}
          label="Save Syslog Settings"
          status={status}
          onDiscard={discard}
        >
          <BusyButton
            className="btn btn-secondary"
            busy={test.isPending}
            busyLabel="Testing…"
            disabled={!draft.active}
            title={
              !draft.active
                ? 'Save with logging enabled first'
                : 'Send a test message'
            }
            onClick={() => {
              setStatus(null);
              test.mutate(undefined, {
                onSuccess: () =>
                  setStatus({
                    kind: 'success',
                    message: 'Syslog test message sent',
                  }),
                onError: (err) =>
                  setStatus({
                    kind: 'error',
                    message: `Failed to send syslog test: ${(err as Error).message}`,
                  }),
              });
            }}
          >
            Send Test Message
          </BusyButton>
        </SaveBar>
      </form>
    </div>
  );
}
